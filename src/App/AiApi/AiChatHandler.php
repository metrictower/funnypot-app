<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Closure;
use Funnypot\Ai\ModelCatalog;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\RequestContext;
use Throwable;

/**
 * Orchestrates one fake chat-completion turn for a picked dialect (the AiApiRouter chose it by path).
 * The whole point is fidelity WITHOUT the two tells a naive proxy would leak: it resolves the full
 * answer string BEFORE emitting a single byte (so a fault never becomes a half-stream), and any
 * failure degrades to a deterministic troll fallback framed in the dialect's own shape — never a 500,
 * which would itself unmask the honeypot.
 *
 * Not final: the router unit test spies on serve().
 */
class AiChatHandler
{
    /** Length cap for a resolved answer. The persona keeps replies short; a runaway generation is a tell. */
    private const MAX_ANSWER_BYTES = 4000;

    private bool $emitted = false;

    /**
     * @param callable(int,array<string,string>,string):void|null $emitBuffered writes a buffered
     *        [status, headers, body]; null = the real header()/echo path. Injected as a sink in tests.
     * @param callable():StreamEmitter|null $emitterFactory builds the streaming emitter; null = a real
     *        one at $delayMs pacing. Tests inject a factory returning a sink-backed, capturing emitter.
     */
    public function __construct(
        private LlmClient $llm,
        private AiChatPromptBuilder $prompt,
        private LlmOutputSanitizer $sanitizer,
        private NonsenseFallback $fallback,
        private ProbeGate $gate,
        private LlmFakeCache $cache,
        private HitStore $store,
        private ModelCatalog $catalog,
        private ?AbuseIpdb $abuse = null,
        // Default OFF: we impersonate an OPEN LLM box (LiteLLM/vLLM/LM Studio/ollama-openai-compat),
        // which serves keyless and echoes any model name. 401/404-ing a keyless or unlisted-model
        // request turns a scanner away and defeats engagement, so strictness is opt-in only.
        private bool $strictAuth = false,
        private bool $strictModel = false,
        // Chat-only sampling. High temperature + min_p 0 + a per-request random seed is what turns the
        // low-temp sidecar's (otherwise correct) output into believable nonsense. Page generation is a
        // different LLM path and is unaffected by these.
        private float $temp = 1.5,
        private float $minP = 0.0,
        private float $topP = 1.0,
        private int $maxConcurrent = 4,
        private int $delayMs = 20,
        private $emitBuffered = null,
        private $emitterFactory = null,
    ) {
    }

    /**
     * Resolve-then-frame (spec §6.4). Parse → auth → model → gate/generate → emit → log → report, with
     * the whole body wrapped so any fault degrades to a dialect-shaped fallback rather than a 500.
     */
    public function serve(ChatDialect $dialect, RequestContext $ctx, string $ip): void
    {
        $this->emitted = false;
        $req = null;

        try {
            try {
                $req = $dialect->parse($ctx);
            } catch (Throwable $e) {
                $this->emitTuple($dialect->error('bad', $this->blankRequest()));
                $this->logHit($ctx, $ip);
                $this->report($ctx, $ip);

                return;
            }

            // Auth/model are served by default (open-box behaviour). Only the opt-in strict flags turn
            // a keyless or unlisted-model request into an error; either way the hit is logged (with
            // hasAuth + model) and reported, since the recon intel is the point.
            if ($this->strictAuth && $dialect->needsAuth() && !$req->hasAuth) {
                $this->emitTuple($dialect->error('auth', $req));
                $this->logHit($ctx, $ip, $req);
                $this->report($ctx, $ip);

                return;
            }

            if ($this->strictModel && !$this->catalog->has($req->model)) {
                $this->emitTuple($dialect->error('model', $req));
                $this->logHit($ctx, $ip, $req);
                $this->report($ctx, $ip);

                return;
            }

            // Full answer resolved up front so streaming can never emit a partial then fault.
            $text = $this->resolveText($req, $ctx, $ip);

            if ($req->stream) {
                $this->emitted = true;
                $dialect->streamOk($text, $req, $this->makeEmitter());
            } else {
                $this->emitTuple($dialect->bufferedOk($text, $req));
            }

            $this->logHit($ctx, $ip, $req);
            $this->report($ctx, $ip);
        } catch (Throwable $e) {
            // Never a 500. If nothing was emitted, frame a plain fallback in this dialect's buffered
            // shape; if a stream already began there is nothing safe to append, so leave it.
            if (!$this->emitted) {
                try {
                    $safe = $req ?? $this->blankRequest();
                    $this->emitTuple($dialect->bufferedOk($this->fallback->text($safe), $safe));
                } catch (Throwable $inner) {
                    // last resort: swallow — a torn response still beats a 500 tell
                }
            }
        }
    }

    /**
     * Resolve the answer: the sidecar's sanitized output when the gate allows and a slot is free, else
     * the deterministic troll fallback. Any decline/fault returns a fallback — this only ever answers.
     */
    private function resolveText(ChatRequest $req, RequestContext $ctx, string $ip): string
    {
        // Gate A (per-IP velocity + bulk pin) and Gate B (path plausibility) — default-deny, same gate
        // the 404-upgrade path uses. A bulk scanner gets the fallback with no sidecar call.
        if (($this->gate->decide($ctx->method, $ctx->path, $ip)['generate'] ?? false) !== true) {
            return $this->fallback->text($req);
        }

        // Global concurrency ceiling. A unique key per request means acquire only ever returns WON or
        // FULL, so FULL is a hard cap on how many chats hold the sidecar at once.
        $slot = 'aiapi:' . bin2hex(random_bytes(8));
        if ($this->cache->acquire($slot, $this->maxConcurrent) !== LlmFakeCache::ACQUIRE_WON) {
            return $this->fallback->text($req);
        }

        try {
            // Random seed per request so the same question does not always get the identical reply.
            $raw = $this->llm->generate($this->prompt->build($req), '', [
                'temperature' => $this->temp,
                'min_p' => $this->minP,
                'top_p' => $this->topP,
                'top_k' => 0,
                'seed' => random_int(1, PHP_INT_MAX),
            ]);
            if (is_string($raw) && trim($raw) !== '') {
                $clean = $this->sanitizeAnswer($raw);
                if ($clean !== null) {
                    return $clean;
                }
            }
        } catch (Throwable $e) {
            // fall through to the fallback
        } finally {
            $this->cache->release($slot);
        }

        return $this->fallback->text($req);
    }

    /**
     * Light sanitize for a chat answer (not a web body): cap length keeping whole codepoints, drop
     * control bytes, and reuse the LLM sanitizer's self-disclosure / active-content gate so the model
     * can never reveal what it is. pageBodyOk carries no minimum-size floor, so a short confidently-
     * wrong reply passes. Returns null on any violation → the caller serves the fallback.
     */
    private function sanitizeAnswer(string $raw): ?string
    {
        $text = mb_strcut(trim($raw), 0, self::MAX_ANSWER_BYTES);
        $text = rtrim((string) preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', $text));
        if ($text === '' || !$this->sanitizer->pageBodyOk($text)) {
            return null;
        }

        return $text;
    }

    /** @param array{0:int,1:array<string,string>,2:string} $tuple */
    private function emitTuple(array $tuple): void
    {
        [$status, $headers, $body] = $tuple;
        $this->emitted = true;

        if ($this->emitBuffered !== null) {
            ($this->emitBuffered)($status, $headers, $body);

            return;
        }

        // Real AI APIs send no X-Powered-By; strip the app's global persona header on this path (the
        // front controller also skips setting it for AI surfaces — this is belt-and-suspenders).
        header_remove('X-Powered-By');
        http_response_code($status);
        foreach ($headers as $name => $value) {
            header("{$name}: {$value}");
        }
        echo $body;
    }

    private function makeEmitter(): StreamEmitter
    {
        if ($this->emitterFactory !== null) {
            return ($this->emitterFactory)();
        }

        return new StreamEmitter(null, $this->delayMs);
    }

    private function logHit(RequestContext $ctx, string $ip, ?ChatRequest $req = null): void
    {
        // Same store method HoneypotController::handle() uses, so AI probes show in the feed + count
        // toward the per-IP velocity gate. The requested model + whether a key was sent are the recon
        // intel, recorded on the entry (they ride the JSON-lines export even without dedicated columns).
        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => $ctx->method,
            'path' => substr($ctx->path, 0, 200),
            'ua' => substr($ctx->headers['User-Agent'] ?? '', 0, 160),
            'matched' => true,
            'severity' => AttackClassifier::severityFor(AttackClassifier::AI_API_RECON),
            'templates' => ['payload-' . AttackClassifier::AI_API_RECON],
            'served' => true,
            'model' => $req !== null ? substr($req->model, 0, 120) : '',
            'hasAuth' => $req !== null && $req->hasAuth,
            'body' => $ctx->rawBody !== null ? substr($ctx->rawBody, 0, 300) : null,
        ]);
    }

    private function report(RequestContext $ctx, string $ip): void
    {
        // Web-app-attack category; the self-guard (FUNNYPOT_SELF_IPS) lives inside enqueue().
        $this->abuse?->enqueue($ip, AttackClassifier::AI_API_RECON . ' ' . substr($ctx->path, 0, 200), '21');
    }

    /** A do-nothing request for the error/fallback paths, where the dialect ignores its fields. */
    private function blankRequest(): ChatRequest
    {
        return new ChatRequest('', '', '', false, false, false);
    }
}

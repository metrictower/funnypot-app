<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\Core\Ai\ModelCatalog;
use Funnypot\App\AiApi\Value\AssistantTurn;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\ReportComment;
use Funnypot\Core\RequestContext;
use Throwable;

/**
 * Orchestrates one fake chat-completion turn for a picked dialect (the AiApiRouter chose it by path).
 * The whole point is fidelity WITHOUT the two tells a naive proxy would leak: it resolves the full
 * answer (text, an inert tool call, or a length stop) BEFORE emitting a single byte (so a fault never
 * becomes a half-stream), and any failure degrades to a deterministic troll fallback framed in the
 * dialect's own shape — never a 500, which would itself unmask the honeypot.
 *
 * Tool calls, identity answers, code snippets and length stops are all inert: they never touch the
 * sidecar, so they neither charge the LLM gen-budget nor run the LLM output sanitizer (there is no model
 * output to sanitise). Only the ordinary text path consults the gated LLM. The server NEVER executes a
 * supplied tool, opens a path, follows a URL or reflects a returned result.
 *
 * Not final: the router unit test spies on serve().
 */
class AiChatHandler
{
    /** Length cap for a resolved answer. The persona keeps replies short; a runaway generation is a tell. */
    private const MAX_ANSWER_BYTES = 4000;

    private bool $emitted = false;
    private int $respBytes = 0;
    private ?ToolTurnPlanner $planner = null;
    private ?ModelIdentityResponder $identity = null;
    private UsageEstimator $usageEstimator;

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
        private WordSwap $wordSwap,
        private WrongLanguageCode $wrongCode,
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
        // Chat-only sampling. The corrupted question already supplies the nonsense, so temperature is
        // kept moderate for a COHERENT answer to it (too high just garbles the reply); min_p 0 + a
        // per-request random seed keep replies varied. Page generation is a different LLM path,
        // unaffected by these.
        private float $temp = 0.8,
        private float $minP = 0.0,
        private float $topP = 1.0,
        private int $maxConcurrent = 4,
        // Believable-first budget: a fresh IP's first $realFirst chat answers within $realWindowS are
        // answered straight (real, correct); after that it degrades to the word-swap troll persona.
        private int $realFirst = 5,
        private int $realWindowS = 600,
        private int $delayMs = 20,
        private $emitBuffered = null,
        private $emitterFactory = null,
        // Bounded tool-calling loop (spec §5): default 2 fabricated calls per conversation, clamped to
        // the hard ceiling of 4. The state store single-consumes a returned result; null degrades to a
        // plausible stateless first turn.
        private int $toolCallLimit = 2,
        private ?AiToolStateStore $toolState = null,
        // Opt-in raw-prompt capture (OFF by default); null unless the operator armed it.
        private ?AiPromptCapture $promptCapture = null,
    ) {
        $this->usageEstimator = new UsageEstimator();
    }

    /**
     * Resolve-then-frame (spec §6.4). Parse → auth → model → resolve turn → emit → log → report, with
     * the whole body wrapped so any fault degrades to a dialect-shaped fallback rather than a 500.
     */
    public function serve(ChatDialect $dialect, RequestContext $ctx, string $ip): void
    {
        $this->emitted = false;
        $this->respBytes = 0;
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

            // Full turn resolved up front so streaming can never emit a partial then fault.
            $turn = $this->resolveTurn($dialect, $req, $ctx, $ip);
            $this->emit($dialect, $turn, $req);

            $this->logHit($ctx, $ip, $req, $turn);
            $this->promptCapture?->capture($req, $ip);
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

    /** Frame the resolved turn into the dialect's wire shape (streamed or buffered). */
    private function emit(ChatDialect $dialect, AssistantTurn $turn, ChatRequest $req): void
    {
        if ($req->stream) {
            $this->emitted = true;
            $out = $this->makeEmitter();
            if ($turn->isToolCall() && $turn->call !== null) {
                $dialect->streamTool($turn->call, $req, $out);
                $this->respBytes = strlen($turn->call->name) + strlen($turn->call->argumentsJson);
            } elseif ($turn->isLength()) {
                $dialect->streamLength($req, $out);
            } else {
                $dialect->streamOk($turn->text, $req, $out);
                $this->respBytes = strlen($turn->text);
            }

            return;
        }

        if ($turn->isToolCall() && $turn->call !== null) {
            $tuple = $dialect->bufferedTool($turn->call, $req);
        } elseif ($turn->isLength()) {
            $tuple = $dialect->bufferedLength($req);
        } else {
            $tuple = $dialect->bufferedOk($turn->text, $req);
        }
        $this->emitTuple($tuple);
        $this->respBytes = strlen($tuple[2]);
    }

    /**
     * Decide the semantic turn: a zero output budget is a length stop; a tools-bearing request may
     * fabricate one inert call (else falls through); otherwise the ordinary text path resolves the reply.
     */
    private function resolveTurn(ChatDialect $dialect, ChatRequest $req, RequestContext $ctx, string $ip): AssistantTurn
    {
        if ($req->maxOutputTokens === 0) {
            return AssistantTurn::length();
        }
        if ($req->tools !== []) {
            $turn = $this->toolPlanner()->plan(
                $req,
                $dialect->toolCallId(),
                $this->actor($ip),
                $this->toolState,
                $this->effectiveLimit()
            );
            if ($turn !== null) {
                return $turn;
            }
        }

        return AssistantTurn::text($this->resolveText($req, $ctx, $ip));
    }

    /**
     * Resolve the answer: the sidecar's sanitized output when the gate allows and a slot is free, else
     * the deterministic troll fallback. Any decline/fault returns a fallback — this only ever answers.
     */
    private function resolveText(ChatRequest $req, RequestContext $ctx, string $ip): string
    {
        // Identity/capability probes ("what model are you") get a believable hardcoded persona answer,
        // coherent with the requested model's real vendor — no sidecar call, no gate. Answering these
        // plainly is what reads as a live box and keeps a scanner engaged, while the canned text stays
        // useless as free compute. Checked first, so an identity probe is never diverted to the troll path.
        if (IdentityResponder::matches($req->userText)) {
            return $this->modelIdentity()->answer($req->userText, $req->model);
        }

        // Code requests get a static wrong-language snippet — no model call, no gate. (serve() still
        // logs + reports it; the recon intel is the point.)
        if (NonsenseFallback::isCodeRequest($req->userText)) {
            return $this->wrongCode->snippet($req->userText);
        }

        // Gate A (per-IP velocity + bulk pin) and Gate B (path plausibility) — default-deny, same gate
        // the 404-upgrade path uses. A bulk scanner gets the generic fallback with no sidecar call.
        if (($this->gate->decide($ctx->method, $ctx->path, $ip)['generate'] ?? false) !== true) {
            return $this->fallback->text($req);
        }

        // Global concurrency ceiling. A unique key per request means acquire only ever returns WON or
        // FULL, so FULL is a hard cap on how many chats hold the sidecar at once.
        $slot = 'aiapi:' . bin2hex(random_bytes(8));
        if ($this->cache->acquire($slot, $this->maxConcurrent) !== LlmFakeCache::ACQUIRE_WON) {
            return $this->fallback->text($req);
        }

        // Believable-first: a fresh IP's opening chats (this IP's prior ai-api hits in the window are
        // below the budget) are answered STRAIGHT — a real box on the first probes. Past the budget the
        // question is corrupted into the troll persona. The count is prior hits (this one is logged
        // after resolve), so request #1 sees 0. A pinned bulk scanner never reaches here (gate above).
        $normal = $this->store->recentEventCount($ip, 'ai-api', $this->realWindowS) < $this->realFirst;

        try {
            if ($normal) {
                // Answer the real question — believable early engagement, capped by the budget.
                $promptText = $req->userText;
            } else {
                // Corrupt the question (swap content words for absurd nouns) and have the model answer
                // THAT straight — the nonsense lives in the question, not in an instruction to be wrong.
                $promptText = $this->wordSwap->corrupt($req->userText);
                // Nothing swappable (e.g. "what is 2+2", "hi") → the helpful model would answer
                // CORRECTLY, which the troll persona must never do. Serve static nonsense instead.
                if ($promptText === $req->userText) {
                    return $this->fallback->text($req);
                }
            }
            // Random seed per request so the same question does not always get the identical reply.
            $raw = $this->llm->generate($this->prompt->build($promptText), '', [
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
        // Reject self-disclosure / active HTML (pageBodyOk) AND any exploit-shaped substring — the
        // model could emit a real shell/PHP snippet in an otherwise prose answer. Both gates skip the
        // 32-byte size floor so a short confidently-wrong reply still passes.
        if ($text === '' || $this->sanitizer->hasExploitSubstring($text) || !$this->sanitizer->pageBodyOk($text)) {
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

    private function toolPlanner(): ToolTurnPlanner
    {
        if ($this->planner === null) {
            $selector = new SafeToolSelector();
            $this->planner = new ToolTurnPlanner($selector, new SafeArgumentSynthesizer($selector), $this->usageEstimator);
        }

        return $this->planner;
    }

    private function modelIdentity(): ModelIdentityResponder
    {
        return $this->identity ??= new ModelIdentityResponder($this->catalog);
    }

    private function effectiveLimit(): int
    {
        return max(0, min(ToolTurnPlanner::HARD_CEILING, $this->toolCallLimit));
    }

    private function actor(string $ip): string
    {
        return hash('sha256', 'a|' . $ip);
    }

    private function logHit(RequestContext $ctx, string $ip, ?ChatRequest $req = null, ?AssistantTurn $turn = null): void
    {
        // Same store method HoneypotController::handle() uses, so AI probes show in the feed + count
        // toward the per-IP velocity gate. The requested model + whether a key was sent are the recon
        // intel; the body carries ONLY privacy-safe structured telemetry — never a prompt excerpt, tool
        // schema, argument, result, auth value or cookie (spec §8).
        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => $ctx->method,
            'path' => substr($ctx->path, 0, 200),
            'ua' => substr($ctx->headers['User-Agent'] ?? '', 0, 160),
            // Tags the row as fake-inference-API traffic so the dashboard can filter to it (the "AI API"
            // quick view), distinct from the LLM-generated fake pages that carry event 'llm-fake'.
            'event' => 'ai-api',
            'matched' => true,
            'severity' => AttackClassifier::severityFor(AttackClassifier::AI_API_RECON),
            'templates' => ['payload-' . AttackClassifier::AI_API_RECON],
            'served' => true,
            'model' => $req !== null ? substr($req->model, 0, 120) : '',
            'hasAuth' => $req !== null && $req->hasAuth,
            'body' => $this->telemetry($ctx, $req, $turn),
        ]);
    }

    private function telemetry(RequestContext $ctx, ?ChatRequest $req, ?AssistantTurn $turn): ?string
    {
        if ($req === null) {
            return null;
        }
        $reqBytes = $ctx->rawBody !== null ? strlen($ctx->rawBody) : 0;
        $outcome = AiTelemetry::OUT_TEXT;
        $outputTokens = 0;
        if ($turn !== null) {
            $outputTokens = $this->usageEstimator->outputTokens($turn);
            $outcome = $turn->isToolCall() ? AiTelemetry::OUT_TOOL_CALL : ($turn->isLength() ? AiTelemetry::OUT_LENGTH : AiTelemetry::OUT_TEXT);
        }

        return AiTelemetry::forHit($req, $reqBytes, $this->respBytes, max(1, $req->inputTokens), $outputTokens, $outcome);
    }

    private function report(RequestContext $ctx, string $ip): void
    {
        // Web-app-attack category; the self-guard (FUNNYPOT_SELF_IPS) lives inside enqueue().
        // FP-0247 (Fix H / fable #3b): the path is attacker-controlled and AbuseIPDB comments are
        // PUBLIC — a Gemini-dialect request carries `?key=AIza...`, so republishing it verbatim leaks a
        // Google API key. Route it through ReportComment::build() to redact secrets, strip a
        // third-party host, and drop control bytes/blobs.
        $comment = ReportComment::build(AttackClassifier::AI_API_RECON, $ctx->path);
        $this->abuse?->enqueue($ip, $comment, '21');
    }

    /** A do-nothing request for the error/fallback paths, where the dialect ignores its fields. */
    private function blankRequest(): ChatRequest
    {
        return new ChatRequest('', '', '', false, false, false);
    }
}

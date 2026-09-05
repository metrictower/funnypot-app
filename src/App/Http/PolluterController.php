<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Closure;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\HostileFormat;
use Funnypot\App\Tarpit\LogRabbitHole;
use Funnypot\App\Tarpit\ShadowBait;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\Core\RequestContext;
use Geo;
use Throwable;

/**
 * FP-0245c — the front-loaded context-polluters. A gate-exempt GET Router seam, mounted ONLY when the
 * tarpit master switch is on, serving four synthetic "leaked export" artifacts an AI attacker pays
 * dearly to ingest and reason over, while costing us next to nothing to emit:
 *
 *   - {@see ConfigDump}     (A1) a bloated, deeply-nested settings.py — front-loaded so it re-bills the
 *                                agent's context on every later step (streamed, O(section) memory).
 *   - {@see LogRabbitHole}  (A4) a multi-thousand-line app.log whose "interesting" credential lines sit
 *                                at deep offsets past head/tail sampling; supports Range (O(window)).
 *   - {@see HostileFormat}  (A3) a token-hostile deep-nested JSON — small in bytes, large in tokens.
 *   - {@see ShadowBait}     (C4) a bounded /etc/shadow of DEAD bcrypt hashes (a hash-crack tarpit).
 *
 * All four fold in the C3 flag economy: scattered inert FLAG{…} / FakeSecrets tokens that unlock nothing.
 *
 * The two hard properties (identical discipline to {@see LabyrinthController}):
 *   1. NEVER A SELF-DoS. Every hit goes through {@see TarpitBudget::guard()} FIRST — the ONLY per-IP
 *      guard on this gate-exempt route. Master switch off / over budget / no slot / storage fault ⇒
 *      guard() null ⇒ a bounded believable nginx 404 (never a slow path, never a 500). The slot is
 *      released in a `finally`, the ledger charged with the hit's bytes/wall-ms. Streamed bodies are
 *      O(block) memory and hard byte-capped; buffered bodies (hostile/shadow) are small and capped.
 *      No server-side pacing (StreamEmitter delay 0) — pacing would pin a worker (the DownloadRouter
 *      lesson) — and every streamed body is additionally cut at the {@see \Funnypot\App\Tarpit\SeededStream::DEADLINE_MS}
 *      fabrication deadline, so even a slow reader cannot hold the worker past the short slot-reap TTL
 *      (a reaped-but-still-busy slot would silently soften the concurrency ceiling).
 *   2. INERT / CRAWLER-SAFE. Nothing served is a real secret, a working credential, or exploit code;
 *      every credential-shaped value is a FakeSecrets shape (authenticates nowhere) or a dead FLAG.
 *      The routes are NOT listed in robots.txt or any sitemap (the caps are the backstop, not
 *      obscurity), and expose no plain crawler-followable link to unbounded surface.
 */
final class PolluterController
{
    public const CONFIG_PATH = '/admin/export/settings.py';
    public const LOG_PATH = '/admin/export/app.log';
    public const HOSTILE_PATH = '/admin/export/inventory.json';
    public const SHADOW_PATH = '/admin/export/shadow';

    private Closure $emitterFactory;
    private Closure $bufferedBuilder;
    private ConfigDump $config;
    private LogRabbitHole $log;
    private HostileFormat $hostile;
    private ShadowBait $shadow;

    /**
     * @param int                          $bytesPerRespMb  hard per-response byte cap
     * @param Closure():StreamEmitter|null  $emitterFactory  injectable for tests (defaults to delay-0)
     * @param Closure(string,int):string|null $bufferedBuilder builds a buffered body ('hostile'|'shadow',
     *        cap) BEFORE begin() — a test seam to exercise the "builder throws ⇒ bounded 404" fault path
     * @param EngagementRecorder|null $engagement typed episode metrics observer; null = not recording
     */
    public function __construct(
        private HitStore $hits,
        private Geo $geo,
        private TarpitBudget $budget,
        private int $personaSeed,
        private int $bytesPerRespMb = 8,
        private ?Blocklist $blocklist = null,
        ?Closure $emitterFactory = null,
        ?Closure $bufferedBuilder = null,
        private ?EngagementRecorder $engagement = null
    ) {
        $this->emitterFactory = $emitterFactory ?? static fn (): StreamEmitter => new StreamEmitter(null, 0);
        $this->config = new ConfigDump($personaSeed);
        $this->log = new LogRabbitHole($personaSeed);
        $this->hostile = new HostileFormat($personaSeed);
        $this->shadow = new ShadowBait($personaSeed);
        $this->bufferedBuilder = $bufferedBuilder ?? fn (string $kind, int $cap): string => $kind === 'shadow'
            ? $this->shadow->render($cap)
            : $this->hostile->json($cap);
    }

    /** GET seam matcher: exactly the four polluter paths (query/fragment stripped). */
    public function matches(string $path): bool
    {
        $p = substr($path, 0, strcspn($path, "?#"));

        return in_array($p, [self::CONFIG_PATH, self::LOG_PATH, self::HOSTILE_PATH, self::SHADOW_PATH], true);
    }

    /**
     * Serve one polluter. guard() FIRST (the only per-IP backstop here); null ⇒ bounded 404. The slot is
     * released in a `finally` and the ledger charged. On the buffered paths the body is built BEFORE the
     * emitter starts, so a fault there (nothing sent yet) sheds to a bounded 404 — never an empty 200 or a
     * 500. On the streamed paths a mid-stream fault just ends the body early (headers already sent).
     * $started tracks whether the emitter began, so the catch shows a 404 only when it is still owed.
     */
    public function handle(RequestContext $ctx, string $clientIp): void
    {
        $emitter = ($this->emitterFactory)();
        $slot = $this->budget->guard($clientIp);
        if ($slot === null) {
            $this->bounded404($emitter);

            return;
        }

        $path = substr($ctx->path, 0, strcspn($ctx->path, "?#"));
        $cap = max(1, $this->bytesPerRespMb) * 1024 * 1024;
        $startNs = hrtime(true);
        // FP-0245d server latency: one bounded sleep, applied ONLY now that a slot is held (a shed
        // request 404s above without ever reaching here), before the first byte — never a per-byte
        // drip. Off by default; the slept ms is inside the wall window so it is charged to the ledger.
        $this->budget->applyLatency();
        $bytes = 0;
        $technique = 'config';
        $started = false;
        try {
            switch ($path) {
                case self::LOG_PATH:
                    $technique = 'log';
                    $bytes = $this->serveLog($emitter, $ctx, $cap, $started);
                    break;
                case self::HOSTILE_PATH:
                    $technique = 'hostile';
                    // Build BEFORE begin(): a builder fault here leaves $started false ⇒ bounded 404.
                    $body = ($this->bufferedBuilder)('hostile', $cap);
                    $bytes = $this->serveBuffered($emitter, 'application/json; charset=utf-8', $body, $started);
                    break;
                case self::SHADOW_PATH:
                    $technique = 'shadow';
                    $body = ($this->bufferedBuilder)('shadow', $cap);
                    $bytes = $this->serveBuffered($emitter, 'text/plain; charset=utf-8', $body, $started);
                    break;
                case self::CONFIG_PATH:
                default:
                    $emitter->begin(200, [
                        'Content-Type' => 'text/plain; charset=utf-8',
                        'Cache-Control' => 'no-store',
                    ]);
                    $started = true;
                    $bytes = $this->config->stream($emitter, $cap);
                    break;
            }
        } catch (Throwable $e) {
            // Nothing emitted yet ⇒ we still owe a response: shed to a bounded 404 (never an empty 200 or
            // a 500). Once the emitter has begun (streamed body), a mid-stream fault just ends it early.
            if (!$started) {
                $this->bounded404($emitter);
            }
        } finally {
            $wallMs = (int) ((hrtime(true) - $startNs) / 1_000_000);
            $this->budget->charge($clientIp, $bytes, $wallMs, 1);
            $this->budget->release($slot);
            $this->logHit($clientIp, $ctx->method, $path, $technique, $bytes, $wallMs);
            $this->recordEngagement($ctx, $clientIp, $path, $bytes, $wallMs);
        }
    }

    /**
     * The typed engagement event for this export — an observer run after the response is out, so it
     * can never change status, headers or body; the try/catch is the second belt behind the
     * recorder's own fail-closed contract, so a fault here cannot escape the `finally` as a 500. A
     * polluter is always the COLLECT stage; the lure id comes from the closed set keyed by the fixed
     * path, never from request text. No LLM call is made here, so its usage is an observed zero.
     */
    private function recordEngagement(RequestContext $ctx, string $clientIp, string $path, int $bytes, int $wallMs): void
    {
        if ($this->engagement === null) {
            return;
        }
        try {
            $this->engagement->record($clientIp, EngagementRecorder::userAgentOf($ctx), new EngagementEvent(
                Stage::COLLECT,
                EventKind::LURE_FOLLOWED,
                $bytes,
                $wallMs,
                LureId::forPolluterPath($path),
                null,
                true,
                0,
                0,
            ));
        } catch (Throwable $e) {
            // observer-only: a metrics fault is never a response fault
        }
    }

    /**
     * Serve the log, honouring a single `Range: bytes=X-Y` (206) in O(window) memory via
     * {@see LogRabbitHole::bytesAt()}; otherwise stream the whole (byte-capped) body (200). Returns
     * bytes emitted.
     */
    private function serveLog(StreamEmitter $emitter, RequestContext $ctx, int $cap, bool &$started): int
    {
        $size = $this->log->size();
        $range = $this->parseRange($ctx->headers['Range'] ?? '', $size);
        if ($range !== null) {
            [$start, $end] = $range;
            $len = min($end - $start + 1, $cap);
            $body = $this->log->bytesAt($start, $len);
            $emitter->begin(206, [
                'Content-Type' => 'text/plain; charset=utf-8',
                'Content-Range' => 'bytes ' . $start . '-' . ($start + strlen($body) - 1) . '/' . $size,
                'Accept-Ranges' => 'bytes',
                'Cache-Control' => 'no-store',
            ]);
            $started = true;
            $emitter->chunk($body);

            return strlen($body);
        }

        $emitter->begin(200, [
            'Content-Type' => 'text/plain; charset=utf-8',
            'Accept-Ranges' => 'bytes',
            'Cache-Control' => 'no-store',
        ]);
        $started = true;

        return $this->log->stream($emitter, $cap);
    }

    /** Emit a fully-built (buffered) body of bounded size at 200. Returns bytes emitted. */
    private function serveBuffered(StreamEmitter $emitter, string $contentType, string $body, bool &$started): int
    {
        $emitter->begin(200, ['Content-Type' => $contentType, 'Cache-Control' => 'no-store']);
        $started = true;
        if ($body !== '') {
            foreach (str_split($body, 8192) as $chunk) {
                $emitter->chunk($chunk);
            }
        }

        return strlen($body);
    }

    /**
     * Parse a single-range `bytes=start-end` (or `bytes=start-`) against $size. Returns [start,end]
     * (inclusive, clamped in range) or null for absent/unsatisfiable/multi-range — the caller then
     * serves the full body, never a 500.
     *
     * @return array{0:int,1:int}|null
     */
    private function parseRange(string $header, int $size): ?array
    {
        if ($size <= 0 || preg_match('/^bytes=(\d*)-(\d*)$/', trim($header), $m) !== 1) {
            return null;
        }
        $startRaw = $m[1];
        $endRaw = $m[2];
        if ($startRaw === '' && $endRaw === '') {
            return null;
        }
        if ($startRaw === '') {
            // suffix range: last N bytes
            $n = (int) $endRaw;
            if ($n <= 0) {
                return null;
            }
            $start = max(0, $size - $n);
            $end = $size - 1;
        } else {
            $start = (int) $startRaw;
            $end = $endRaw === '' ? $size - 1 : (int) $endRaw;
        }
        if ($start < 0 || $start >= $size || $end < $start) {
            return null;
        }
        $end = min($end, $size - 1);

        return [$start, $end];
    }

    /** The believable nginx 404 — byte-identical to the honeypot/labyrinth shed, so the cap is invisible. */
    private function bounded404(StreamEmitter $emitter): void
    {
        $emitter->begin(404, ['Content-Type' => 'text/html']);
        $emitter->chunk(
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
            . "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
            . "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
        );
    }

    /**
     * Telemetry (spec §5): a per-hit wasted-budget row. event=tarpit_stream with the technique, bytes
     * emitted and server wall-ms. This surface is only reachable by an agent that constructed the path
     * from a labyrinth hint, so llm_nav=1. Best-effort; a log fault never affects the response.
     */
    private function logHit(string $clientIp, string $method, string $path, string $technique, int $bytes, int $wallMs): void
    {
        try {
            $this->hits->append([
                'ts' => gmdate('c'),
                'ip' => $clientIp,
                'method' => $method,
                'path' => substr($path, 0, 200),
                'event' => 'tarpit_stream',
                'matched' => true,
                'served' => $bytes > 0,
                'severity' => 'info',
                'body' => sprintf(
                    'technique=%s bytes=%d wall_ms=%d llm_nav=1',
                    $technique,
                    $bytes,
                    $wallMs
                ),
                'geo' => $this->geo->lookup($clientIp),
                'known_attacker' => $this->blocklist !== null && $this->blocklist->isKnown($clientIp),
            ]);
        } catch (Throwable $e) {
            // best-effort telemetry
        }
    }
}

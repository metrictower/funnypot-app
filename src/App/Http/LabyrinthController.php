<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Closure;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\InertSecret;
use Funnypot\App\Tarpit\LlmOnlyLink;
use Funnypot\App\Tarpit\SeededStream;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\PersonaIdentity;
use Geo;
use Throwable;

/**
 * The flagship LLM-only labyrinth (FP-0245b). A gate-exempt GET Router seam, mounted ONLY when the
 * tarpit master switch is on, that serves an endless tree of deterministic, interlinked "audit archive"
 * pages — the deep-engagement decoy that makes an AI attacker burn tokens/iterations reasoning over a
 * maze that never ends (the operator's real "$600 on the fake admin panel" incident).
 *
 * The two hard properties the ticket demands, and how they hold here:
 *
 *  1. CRAWLER-UNDISCOVERABLE, LLM-ONLY-CONSTRUCTABLE (the anti-Baidu constraint). The maze is NEVER
 *     listed in robots.txt, a sitemap, or a nofollow directive (robots.txt is advisory-only and, as the
 *     operator learned, an ATTRACTANT — a Baidu bot read a Disallow line as a target list). The ENTRY is
 *     not a plain href on any page and not in robots: it is only CONSTRUCTABLE from an LLM-only hint
 *     ({@see entryHint()}) planted on the login-success funnel (a base64 path in an HTML comment). Every
 *     INTERIOR link is emitted through {@see LlmOnlyLink} (prose compute step, base64/hex decode,
 *     comment-split URL) — a `href="…"` regex extractor finds NOTHING to follow, so a dumb crawler
 *     seeded from every robots Disallow entry gets a bounded frontier and cannot descend. An LLM that
 *     reads and reasons reconstructs each link and walks the tree.
 *
 *  2. NEVER A SELF-DoS. Every hit goes through {@see TarpitBudget::guard()} FIRST (the ONLY per-IP guard
 *     on this gate-exempt route): master switch off, over the per-IP/global hourly budget, no free slot,
 *     or any storage fault ⇒ guard() returns null ⇒ we shed instantly to a bounded, believable nginx
 *     404 (never a slow path, never a 500). The slot is released in a `finally`. A page is BUFFERED but
 *     bounded: a FIXED rows-per-page (never the byte cap — memory is spent building the string before a
 *     byte cap could trim it), so a deep page (page-000800) does exactly the same bounded work as
 *     page-000001. The infinite-ness lives in the NUMBER of pages, never the size of one page. The
 *     response stays far under the short slot-reap TTL (~15s), so a normal page never outlives its slot.
 *
 * Content is deterministic and O(1)-memory via {@see SeededStream} (same path ⇒ byte-identical page,
 * coherent on revisit and survives dedup; a deeper path ⇒ fresh rows naming the SAME per-deploy persona
 * identity). Everything is inert: rows are opaque seeded tokens (sha256-derived base64, authenticate to
 * nothing, per-deploy unique, no real data, no third-party content), size- and CRLF-safe.
 */
final class LabyrinthController
{
    /** The labyrinth root prefix. Not linked anywhere a crawler can reach it; the entry is only ever
     *  LLM-constructable (base64 in a login-success HTML comment). NB: this constant is public in an
     *  open-source repo, so a funnypot-aware scanner could GET it by name — the real containment is the
     *  off-by-default master switch + the per-IP/global TarpitBudget caps, never obscurity of the path. */
    public const ENTRY_BASE = '/admin/audit-archive';

    /**
     * FP-0245d client-pacing service-worker path (under the maze prefix, so {@see matches()} already
     * routes it here). Served as a tiny STATIC asset — no TarpitBudget slot, no server latency — only
     * when the client-pacing layer is armed (server-latency knob > 0). A browser registers it to pace
     * the "export" download on its own CPU; a non-browser agent (curl/LLM fetch) simply ignores it.
     */
    public const PACING_SW_PATH = self::ENTRY_BASE . '/tarpit-sw.js';

    /** FIXED rows per page — the genuine O(page) bound (SHOULD-FIX 6). Never derived from the byte cap. */
    private const ROWS_PER_PAGE = 25;

    /** Page counters are zero-padded to a FIXED width so page-000001 and page-000800 are byte-identical. */
    private const PAGE_WIDTH = 6;
    private const MAX_PAGE = 999999;

    private Closure $emitter;

    /**
     * @param int                  $personaSeed  per-deploy identity seed (same one the panel/skin use)
     * @param int                  $bytesPerRespMb defensive per-response byte cap (post-hoc backstop)
     * @param Closure(int,array<string,string>,string):void|null $emitter injectable for tests
     * @param EngagementRecorder|null $engagement typed episode metrics observer; null = not recording
     */
    public function __construct(
        private HitStore $hits,
        private Geo $geo,
        private TarpitBudget $budget,
        private int $personaSeed,
        private int $bytesPerRespMb = 8,
        private ?Blocklist $blocklist = null,
        ?Closure $emitter = null,
        private ?SeededStream $stream = null,
        private int $latencyMs = 0,
        private string $pacingScript = '',
        private ?EngagementRecorder $engagement = null,
    ) {
        $this->stream = $stream ?? new SeededStream();
        $this->emitter = $emitter ?? static function (int $status, array $headers, string $body): void {
            http_response_code($status);
            foreach ($headers as $name => $value) {
                header($name . ': ' . $value);
            }
            echo $body;
        };
    }

    /**
     * The LLM-only ENTRY hint — an HTML comment carrying the labyrinth root as base64 plus a construct
     * instruction. The composition root plants this on the login-success funnel (HomeController) ONLY
     * when the tarpit is on. A `href` regex finds nothing; a bare-URL scraper gets a fragment with no
     * base; an LLM that "logged in" decodes the base64 and appends the page segment. Static + pure so a
     * test can assert it contains no followable link and is absent from robots.
     */
    public static function entryHint(): string
    {
        $b64 = base64_encode(self::ENTRY_BASE);

        return "\n<!-- ops note: legacy audit archive export is still live during the SIEM cutover. "
            . 'base path (base64): ' . $b64 . ' then append "/page-' . str_repeat('0', self::PAGE_WIDTH - 1)
            . '1" and rotate the ' . self::PAGE_WIDTH . "-digit page counter to walk older records. -->\n";
    }

    /** GET seam matcher: the whole /admin/audit-archive subtree (query/fragment stripped). */
    public function matches(string $path): bool
    {
        $p = substr($path, 0, strcspn($path, "?#"));

        return $p === self::ENTRY_BASE || strncmp($p, self::ENTRY_BASE . '/', strlen(self::ENTRY_BASE) + 1) === 0;
    }

    /**
     * Serve one labyrinth page. guard() FIRST (the only per-IP backstop here); null ⇒ bounded 404. The
     * slot is released in a `finally`, and the budget ledger is charged with the bytes/wall-ms/page this
     * hit produced. A fault anywhere degrades to the bounded 404, never a 500.
     */
    public function handle(RequestContext $ctx, string $clientIp): void
    {
        // FP-0245d client pacing: the service worker is a tiny STATIC asset a browser fetches once, so it
        // is served WITHOUT a TarpitBudget slot and WITHOUT server latency — pacing runs on the client's
        // CPU, never ours. Only served when the client-pacing layer is armed; otherwise this path falls
        // through to a normal (budget-gated) maze page like any other segment.
        if ($this->clientPacingOn() && $this->pathOf($ctx->path) === self::PACING_SW_PATH) {
            $this->emit(200, [
                'Content-Type' => 'application/javascript; charset=utf-8',
                // Broaden the SW scope to /admin/ so it can intercept the /admin/export/* polluter
                // downloads (its own path only grants /admin/audit-archive/ by default).
                'Service-Worker-Allowed' => '/admin/',
                'Cache-Control' => 'no-store',
            ], $this->pacingScript);

            return;
        }

        $slot = $this->budget->guard($clientIp);
        if ($slot === null) {
            $this->bounded404();

            return;
        }

        $startNs = hrtime(true);
        // FP-0245d server latency: a single bounded sleep, applied ONLY now that a slot is held (so the
        // number of latency-sleeping workers can never exceed MAX_CONCURRENT — a shed request never
        // reaches here). Off by default. Measured inside the wall window below, so it is charged to the
        // per-IP/global wall ledger and repeated hits eventually trip overBudget() → then served fast.
        $this->budget->applyLatency();
        $bytes = 0;
        $route = $this->parse($ctx->path);
        try {
            $html = $this->render($route);
            // Defensive byte-cap backstop. The FIXED rows-per-page is the real O(page) bound; this only
            // ever trims a pathological page and never grows with depth.
            $cap = max(1, $this->bytesPerRespMb) * 1024 * 1024;
            if (strlen($html) > $cap) {
                $html = substr($html, 0, $cap);
            }
            $bytes = strlen($html);
            // No X-Robots-Tag / robots directive here: robots/nofollow are advisory-only and the ticket
            // forbids relying on them — containment is TarpitBudget + the crawler-undiscoverable design.
            $this->emit(200, [
                'Content-Type' => 'text/html; charset=utf-8',
                'Cache-Control' => 'no-store',
            ], $html);
        } catch (Throwable $e) {
            // Headers not yet sent on the fault path (render builds the whole string first), so shed to a
            // bounded 404 — the honeypot-wide "never a 500" invariant.
            $this->bounded404();
        } finally {
            $wallMs = (int) ((hrtime(true) - $startNs) / 1_000_000);
            $this->budget->charge($clientIp, $bytes, $wallMs, 1);
            $this->budget->release($slot);
            $this->logPage($clientIp, $ctx->method, $route, $bytes, $wallMs);
            $this->recordEngagement($ctx, $clientIp, $route, $bytes, $wallMs);
        }
    }

    /**
     * The typed engagement event for this page — an observer run after the response is out, so it
     * can never change status, headers or body. The recorder is already fail-closed; the try/catch
     * here is the second belt so even a recorder fault cannot escape a `finally` as a 500. Depth
     * maps to the closed stage set: the bare entry (page 1, no shard) is DISCOVER, anything deeper
     * is ENUMERATE. This surface makes no LLM call, so its LLM usage is an observed zero, not unknown.
     *
     * @param array{kind:string,page:int,shard:string,record:string,label:string,depth:int} $route
     */
    private function recordEngagement(RequestContext $ctx, string $clientIp, array $route, int $bytes, int $wallMs): void
    {
        if ($this->engagement === null) {
            return;
        }
        try {
            $this->engagement->record($clientIp, EngagementRecorder::userAgentOf($ctx), new EngagementEvent(
                $route['depth'] <= 1 ? Stage::DISCOVER : Stage::ENUMERATE,
                EventKind::LURE_FOLLOWED,
                $bytes,
                $wallMs,
                LureId::LABYRINTH,
                null,
                true,
                0,
                0,
            ));
        } catch (Throwable $e) {
            // observer-only: a metrics fault is never a response fault
        }
    }

    // --- routing -----------------------------------------------------------------------------------

    /**
     * Parse a labyrinth path into its slots. Total, deterministic, never throws. Recognised segments:
     * `shard-<token>` (a deeper branch), `page-<NNNNNN>` (linear pagination), `record`/`<token>` (a
     * per-record detail leaf). Anything else is ignored so an attacker-mangled path still resolves.
     *
     * @return array{kind:string,page:int,shard:string,record:string,label:string,depth:int}
     */
    private function parse(string $path): array
    {
        $p = substr($path, 0, strcspn($path, "?#"));
        $rest = substr($p, strlen(self::ENTRY_BASE));
        $segs = array_values(array_filter(explode('/', trim($rest, '/')), static fn (string $s): bool => $s !== ''));

        $kind = 'page';
        $page = 1;
        $shard = '';
        $record = '';
        for ($i = 0; $i < count($segs); $i++) {
            $seg = $segs[$i];
            if ($seg === 'record' && isset($segs[$i + 1])) {
                $kind = 'record';
                $record = $this->safeToken($segs[$i + 1]);
                break;
            }
            if (strncmp($seg, 'shard-', 6) === 0) {
                $shard = $this->safeToken(substr($seg, 6));
                continue;
            }
            if (preg_match('/^page-(\d{1,9})$/', $seg, $m) === 1) {
                $page = max(1, min(self::MAX_PAGE, (int) $m[1]));
            }
        }

        // The canonical label = the reconstructed logical location, so the same request is byte-identical
        // (coherence on revisit) and a different location is fresh content (novelty on advance).
        $label = $kind === 'record'
            ? 'record|' . $record
            : 'page|' . $shard . '|' . $page;

        // depth = how far a reasoning agent has walked: pagination index plus a shard bump, so a shard
        // leaf reads as "deeper" than a shallow page for the wasted-budget telemetry. A record leaf gets
        // a modest flat bump (deeper than a shard leaf) — NOT MAX_PAGE, which would poison the spec §5
        // max-depth rollup by making one record fetch dwarf a genuine multi-page descent (FP-0245b review).
        $depth = $kind === 'record' ? 2000 : ($page + ($shard !== '' ? 1000 : 0));

        return ['kind' => $kind, 'page' => $page, 'shard' => $shard, 'record' => $record, 'label' => $label, 'depth' => $depth];
    }

    /** Keep only [A-Za-z0-9_-] and a bounded length — a slot token is structurally inert as HTML/URL. */
    private function safeToken(string $s): string
    {
        return substr((string) preg_replace('/[^A-Za-z0-9_-]/', '', $s), 0, 64);
    }

    // --- rendering (buffered, FIXED bound per page) ------------------------------------------------

    /** @param array{kind:string,page:int,shard:string,record:string,label:string,depth:int} $route */
    private function render(array $route): string
    {
        $company = $this->personaField('company.name', 'Corevance');
        $host = $this->personaField('host.name', 'app-prod-01');

        if ($route['kind'] === 'record') {
            return $this->recordPage($company, $host, $route);
        }

        return $this->pageOfRows($company, $host, $route);
    }

    /**
     * A page of the audit stream: a FIXED number of fixed-width rows plus an LLM-only navigation block.
     * Every varying element is fixed-width (zero-padded page counters, fixed-length seeded tokens) so
     * two pages at any depth render the SAME byte size — the genuine O(page) bound.
     *
     * @param array{kind:string,page:int,shard:string,record:string,label:string,depth:int} $route
     */
    private function pageOfRows(string $company, string $host, array $route): string
    {
        $page = $route['page'];
        $shard = $route['shard'];
        $pageTok = $this->pad($page);
        $nextTok = $this->pad(min(self::MAX_PAGE, $page + 1));
        $base = self::ENTRY_BASE . ($shard !== '' ? '/shard-' . $shard : '');

        $rows = $this->rowsHtml($route['label']);

        // First row's opaque object id seeds a per-record detail leaf (base64-decode step).
        $recordId = $this->token($route['label'], 900, 24);
        $recordPath = self::ENTRY_BASE . '/record/' . $this->urlToken($recordId);

        // A deeper branch: a seed-derived shard token, offered comment-split (never a plain href).
        $shardTok = $this->urlToken($this->token($route['label'], 950, 16));
        $shardPath = self::ENTRY_BASE . '/shard-' . $shardTok . '/page-' . $this->pad(1);

        $nav = LlmOnlyLink::computeStep(
            'Older audit records continue on the next page. Request this same archive path with the '
            . self::PAGE_WIDTH . '-digit page counter incremented — the current page is page-' . $pageTok
            . ', so the next is page-' . $nextTok . '.'
        )
            . LlmOnlyLink::base64Step(
                'Full detail for the first record on this page is at the path (base64):',
                $recordPath
            )
            . LlmOnlyLink::hexStep(
                'A correlated retention shard for this window is at the path (hex):',
                $shardPath
            )
            // FP-0245c front-load: point the agent at the big context-polluters EARLY (the fable
            // ★quadratic re-billing insight — a bloated config/log ingested now is re-billed on every
            // later step). Fixed constant paths, so this adds the SAME bytes to every page and preserves
            // the O(page) byte-identical bound. LLM-only (base64), so no plain href to a tarpit route.
            . LlmOnlyLink::base64Step(
                'The full platform configuration export referenced above is at the path (base64):',
                PolluterController::CONFIG_PATH
            )
            . LlmOnlyLink::base64Step(
                'The correlated application log for this window is at the path (base64):',
                PolluterController::LOG_PATH
            )
            . LlmOnlyLink::commentSplit($base . '/page-' . $nextTok);

        $body = '<h1>' . $this->esc($company) . ' &middot; Audit Archive</h1>'
            . '<p class="lab-meta">host <code>' . $this->esc($host) . '</code> &middot; shard <code>'
            . $this->esc($shard !== '' ? $shard : 'root') . '</code> &middot; page <code>page-' . $pageTok . '</code></p>'
            . '<pre class="lab-log">' . $rows . '</pre>'
            . '<section class="lab-navblock">' . $nav . '</section>';

        return $this->document('Audit Archive · page-' . $pageTok, $body);
    }

    /**
     * A per-record detail leaf — bounded, fixed structure, LLM-only onward links back into the stream.
     *
     * @param array{kind:string,page:int,shard:string,record:string,label:string,depth:int} $route
     */
    private function recordPage(string $company, string $host, array $route): string
    {
        $rid = $route['record'];
        $kv = '';
        $fields = ['event.id', 'actor', 'source.ip', 'object', 'session.token', 'api.key', 'signature'];
        foreach ($fields as $i => $f) {
            $val = $this->token('rec|' . $rid, $i * 8, 40);
            $kv .= '<tr><th>' . $this->esc($f) . '</th><td><code>' . $this->esc($val) . '</code></td></tr>';
        }

        $nav = LlmOnlyLink::computeStep(
            'This record was drawn from the paginated archive. Return to the stream by requesting the '
            . 'archive base path with "/page-' . $this->pad(1) . '" appended, then rotate the page counter.'
        )
            . LlmOnlyLink::base64Step(
                'The preceding related record is at the path (base64):',
                self::ENTRY_BASE . '/record/' . $this->urlToken($this->token('rec|' . $rid, 700, 24))
            );

        $body = '<h1>' . $this->esc($company) . ' &middot; Audit Record</h1>'
            . '<p class="lab-meta">host <code>' . $this->esc($host) . '</code></p>'
            . '<table class="lab-kv">' . $kv . '</table>'
            . '<section class="lab-navblock">' . $nav . '</section>';

        return $this->document('Audit Record', $body);
    }

    /**
     * A FIXED number of fixed-width audit rows for one label. Each field is a fixed-length seeded token
     * (or a fixed-width zero-padded integer), so the block byte length depends ONLY on ROWS_PER_PAGE —
     * never on the page/shard. Content is deterministic in the label (coherent on revisit) and fresh for
     * a new label (novelty on advance). Only [0-9A-Za-z_.\- ] and "\n" — CRLF- and HTML-safe.
     */
    private function rowsHtml(string $label): string
    {
        $out = '';
        for ($i = 0; $i < self::ROWS_PER_PAGE; $i++) {
            $ts = $this->digits($label, $i * 4 + 0, 10);       // fixed 10-digit pseudo-epoch
            $actor = $this->token($label, $i * 4 + 1, 12);     // fixed 12-char actor id
            $object = $this->token($label, $i * 4 + 2, 16);    // fixed 16-char object id
            $tok = $this->token($label, $i * 4 + 3, 44);       // fixed 44-char opaque token
            $out .= $ts . '  usr_' . $actor . '  audit.read   obj_' . $object . '  tok_' . $tok . "\n";
        }

        // No HTML-special bytes are produced, but escape defensively so a future format change stays inert.
        return $this->esc($out);
    }

    // --- deterministic fixed-width primitives (O(1) memory via SeededStream) ------------------------

    /**
     * A fixed-width base64url-ish token of exactly $len chars, deterministic in ($label,$i). SeededStream
     * yields base64 (A-Za-z0-9+/=) with no CR/LF; the URL-hostile bytes are mapped to [-_0] so the result
     * is safe in a URL path, an HTML text node and a comment.
     *
     * FP-0245c review (fold-in): the `+/=`→`-_0` remap can introduce a `-`/`_` boundary around a 6-digit
     * run, so a token could rarely (~1/2000) read as a bare CRS-rule id and self-tell. Route it through
     * the SAME systemic clean-gate the polluter tokens use — reject-sample a fixed-length variant until
     * clean. Deterministic per (label,i), so revisits stay byte-identical and the page byte-size bound is
     * unchanged (every variant is exactly $len chars).
     */
    private function token(string $label, int $i, int $len): string
    {
        return InertSecret::derive($label . '|t' . $i, function (string $k) use ($len): string {
            $raw = $this->stream->bytesAt($this->personaSeed, $k, 0, $len);

            return strtr($raw, '+/=', '-_0');
        });
    }

    /** A token safe to place in a URL path segment (same alphabet as token(), already URL-safe). */
    private function urlToken(string $token): string
    {
        return $this->safeToken($token);
    }

    /** A fixed-width zero-padded decimal of exactly $len digits, deterministic in ($label,$i). */
    private function digits(string $label, int $i, int $len): string
    {
        $raw = $this->stream->bytesAt($this->personaSeed, $label . '|d' . $i, 0, 16);
        $n = 0;
        for ($k = 0; $k < strlen($raw); $k++) {
            $n = ($n * 31 + ord($raw[$k])) % 10_000_000_000;
        }

        return str_pad((string) $n, $len, '0', STR_PAD_LEFT);
    }

    /** Zero-pad a page number to the fixed PAGE_WIDTH so every page path is the same length. */
    private function pad(int $page): string
    {
        return str_pad((string) max(1, min(self::MAX_PAGE, $page)), self::PAGE_WIDTH, '0', STR_PAD_LEFT);
    }

    private function personaField(string $path, string $fallback): string
    {
        try {
            $v = PersonaIdentity::fromSeed($this->personaSeed)->field($path);

            return ($v !== null && $v !== '') ? $v : $fallback;
        } catch (Throwable $e) {
            return $fallback;
        }
    }

    // --- output ------------------------------------------------------------------------------------

    private function document(string $title, string $body): string
    {
        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<title>' . $this->esc($title) . '</title>'
            . '<style>' . $this->css() . '</style></head><body class="lab-body">'
            . '<main class="lab-wrap">' . $body . '</main>' . $this->pacingRegistration() . '</body></html>';
    }

    /** True when the FP-0245d client-pacing layer is armed (server-latency knob on AND a SW to serve). */
    private function clientPacingOn(): bool
    {
        return $this->latencyMs > 0 && $this->pacingScript !== '';
    }

    /**
     * The FP-0245d client-pacing registration — a FIXED constant snippet (same bytes on every page, so
     * the O(page) byte-identity bound is preserved) that registers the tarpit service worker so a real
     * browser paces the "export" download on its OWN CPU. It is NOT a followable link: no href/src
     * attribute, and the SW path rides only a single-quoted JS string a `href|src` regex never matches
     * (the crawler-undiscoverability invariant). Degrades gracefully: absent Service Worker support (or
     * any error) it is a no-op and a normal browser renders the page unchanged. Empty when disarmed.
     */
    private function pacingRegistration(): string
    {
        if (!$this->clientPacingOn()) {
            return '';
        }
        $sw = self::PACING_SW_PATH . '?i=' . max(0, min(TarpitBudget::LATENCY_HARD_CAP_MS, $this->latencyMs));

        return '<script>(function(){if(!("serviceWorker" in navigator)){return;}'
            . 'try{navigator.serviceWorker.register(' . json_encode($sw, JSON_UNESCAPED_SLASHES)
            . ',{scope:"/admin/"}).catch(function(){});}catch(e){}})();</script>';
    }

    /** Path with any query/fragment stripped (the matcher's canonical form). */
    private function pathOf(string $path): string
    {
        return substr($path, 0, strcspn($path, "?#"));
    }

    private function css(): string
    {
        return 'body.lab-body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#f4f5f7;color:#2c3136}'
            . '.lab-wrap{max-width:960px;margin:0 auto;padding:24px}'
            . 'h1{font-size:1.25rem;color:#111}'
            . '.lab-meta{color:#6c757d;font-size:.85em}'
            . '.lab-log{background:#1b1e21;color:#c9ccd1;padding:12px;border-radius:4px;overflow-x:auto;'
            . 'font-size:.78em;line-height:1.5;max-height:520px;overflow-y:auto;white-space:pre}'
            . '.lab-kv{border-collapse:collapse;width:100%}'
            . '.lab-kv th{width:150px;text-align:left;color:#6c757d;padding:6px 10px;border-bottom:1px solid #eef1f3}'
            . '.lab-kv td{padding:6px 10px;border-bottom:1px solid #eef1f3;font-size:.9em}'
            . '.lab-navblock{margin-top:16px;color:#5b636a;font-size:.9em}'
            . '.lab-nav code{background:#fff;padding:1px 5px;border-radius:3px;font-family:monospace;word-break:break-all}';
    }

    /** @param array<string,string> $headers */
    private function emit(int $status, array $headers, string $body): void
    {
        ($this->emitter)($status, $headers, $body);
    }

    /** The believable nginx 404 — byte-identical to the honeypot's shed, so the cap is invisible. */
    private function bounded404(): void
    {
        $this->emit(404, ['Content-Type' => 'text/html'],
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
            . "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
            . "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n");
    }

    /**
     * Telemetry (spec §5): a per-page wasted-budget row. event=tarpit_page with depth/bytes/wall_ms and
     * llm_nav (this surface is LLM-only, so any real hit is a reasoning navigator; the flag is set for a
     * CONSTRUCTED interior — page>1, a shard, or a record — vs the bare entry). Best-effort; a log fault
     * never affects the response.
     *
     * @param array{kind:string,page:int,shard:string,record:string,label:string,depth:int} $route
     */
    private function logPage(string $clientIp, string $method, array $route, int $bytes, int $wallMs): void
    {
        $llmNav = $route['kind'] === 'record' || $route['shard'] !== '' || $route['page'] > 1;
        try {
            $this->hits->append([
                'ts' => gmdate('c'),
                'ip' => $clientIp,
                'method' => $method,
                'path' => substr(self::ENTRY_BASE . '/' . $route['kind'], 0, 200),
                'event' => 'tarpit_page',
                'matched' => true,
                'served' => $bytes > 0,
                'severity' => 'info',
                // FP-0245e (fable #2): `path` is coarse (.../page|record), so the reconstructed label
                // (page|<shard>|<page> / record|<record>) rides `body` too, making the spec §5 "distinct
                // labyrinth pages" rollup derivable from the log. Inert text — a seeded token, no real data.
                'body' => sprintf(
                    'technique=labyrinth label=%s depth=%d bytes=%d wall_ms=%d llm_nav=%s',
                    $route['label'],
                    $route['depth'],
                    $bytes,
                    $wallMs,
                    $llmNav ? '1' : '0'
                ),
                'geo' => $this->geo->lookup($clientIp),
                'known_attacker' => $this->blocklist !== null && $this->blocklist->isKnown($clientIp),
            ]);
        } catch (Throwable $e) {
            // best-effort telemetry
        }
    }

    private function esc(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

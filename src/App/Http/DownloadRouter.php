<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Closure;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Storage\HitStore;
use Funnypot\Core\RequestContext;
use Funnypot\Shell\Fs\Draw;

/**
 * Endless throttled backup-download bait (the fleet console's "Download latest backup"). A Router-level
 * GET seam, gate-exempt like the console, mounted only when the feature is on.
 *
 * Three paths, all under /__dl/:
 *   GET /__dl/sw.js        — the service worker (served as application/javascript, Service-Worker-Allowed: /)
 *   GET /__dl/manifest     — JSON {seed, files:[{path,size}], throttle:{...}}; also the bait-taken intel ping
 *   GET /__dl/backup.zip   — NON-JS fallback only (a browser's active SW intercepts this before it reaches
 *                            us); a HARD-CAPPED finite zip so curl/scanners still get a plausible large
 *                            download instead of a dead link. The Content-Disposition filename is still
 *                            backup.zip, so what lands on the attacker's disk reads the same.
 *
 * The zip lives under /__dl/ and NOT at the bare /backup.zip because that literal path is already honeypot
 * surface: the honeypot serves the nested decoy archive there and, more importantly, runs the detection
 * engine, the payload classifier and the AbuseIPDB / Threat Intel enqueue. A router seam ahead of the
 * catch-all would swallow every scanner hit on it and silence the app's only reporting path.
 *
 * The browser path costs us one tiny manifest fetch — the SW fabricates every byte client-side and streams
 * an ENDLESS store-method zip (never a valid extractable archive; the central directory is never written),
 * throttled to a believable ~1-2 MB/s so it reads like a real broadband download and the attacker gets
 * bored and cancels. Cancelable, NOT a zip bomb. All throttle knobs come from AppConfig and are handed to
 * the SW via the manifest, so speed/variability are centrally configured, never hardcoded in the JS.
 *
 * Safety: nothing executes; bytes are procedural. The manifest and headers are resolved before any byte is
 * flushed, so a fault degrades to an empty/plain response, never a 500 (a 500 is itself a tell).
 *
 * Resource bounds: this route is gate-exempt, so the worker/temp-disk/egress envelope (concurrent
 * transfers per source and in total, starts per minute, bytes per second, FastCGI spool) is enforced by
 * nginx in demo/funnypot-location.conf, ahead of PHP. What THIS class bounds is its own telemetry: the
 * bait rows one actor can produce per window (BaitEventLimiter), so a hammering source costs a few rows
 * plus one folded count, not a row per request.
 */
final class DownloadRouter
{
    public const SW_PATH = '/__dl/sw.js';
    public const MANIFEST_PATH = '/__dl/manifest';
    public const ZIP_PATH = '/__dl/backup.zip';

    private const MANIFEST_FILES = 40;   // entries advertised in the manifest
    private const NAME_MAX = 200;        // host param cap

    private Closure $emitterFactory;
    private BaitEventLimiter $bait;

    /**
     * @param int $chunkMinKb minimum chunk size (KiB)   @param int $chunkMaxKb maximum chunk size (KiB)
     * @param int $intervalMs base inter-chunk delay (ms) @param int $varyPct   breathing amplitude (% of base)
     * @param int $easePeriodS breathing cycle length (s) @param int $fallbackCapMb non-JS hard cap (MiB)
     */
    public function __construct(
        private HitStore $hits,
        private int $personaSeed,
        private string $swScript,
        private int $chunkMinKb = 100,
        private int $chunkMaxKb = 200,
        private int $intervalMs = 100,
        private int $varyPct = 50,
        private int $easePeriodS = 20,
        private int $fallbackCapMb = 50,
        ?Closure $emitterFactory = null,
        ?BaitEventLimiter $bait = null
    ) {
        $this->emitterFactory = $emitterFactory ?? static fn (): StreamEmitter => new StreamEmitter(null, 0);
        $this->bait = $bait ?? new BaitEventLimiter();
    }

    public function matches(string $path): bool
    {
        return $path === self::SW_PATH || $path === self::MANIFEST_PATH || $path === self::ZIP_PATH;
    }

    public function handle(RequestContext $ctx, string $clientIp): void
    {
        if ($ctx->path === self::SW_PATH) {
            $this->emit(200, ['Content-Type' => 'application/javascript; charset=utf-8', 'Service-Worker-Allowed' => '/', 'Cache-Control' => 'no-store'], $this->swScript);

            return;
        }
        if ($ctx->path === self::MANIFEST_PATH) {
            $host = $this->hostFromQuery($ctx->query);
            $this->logBait($clientIp, $ctx->method, $host);
            $json = '';
            try {
                $json = (string) json_encode($this->manifest($host));
            } catch (\Throwable $e) {
                $json = '{}';
            }
            $this->emit(200, ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store'], $json);

            return;
        }
        // /__dl/backup.zip — non-JS fallback: a browser with the SW active never reaches here.
        $host = $this->hostFromQuery($ctx->query);
        $this->logBait($clientIp, $ctx->method, $host);
        $this->streamFallback($host);
    }

    /**
     * A plausible backup manifest for one fleet host, deterministic from its seed: canonical
     * backup contents (db dumps, configs, keys, tarballs) with seed-drawn sizes. The client fabricates
     * the bytes, so this only needs believable names + sizes. Coherent per host (same seed → same list).
     *
     * @return array{seed:int,host:string,files:array<int,array{path:string,size:int}>,throttle:array<string,int>}
     */
    public function manifest(string $host): array
    {
        $fleet = Fleet::fromSeed($this->personaSeed);
        $detail = $fleet->detail($host);
        $seed = $detail !== null ? (int) $detail['summary']['seed'] : $this->personaSeed;
        $hostname = $detail !== null ? (string) $detail['summary']['host'] : 'backup-host';
        $fsSeed = Draw::seed('dl|' . $seed);

        $dirs = ['var/backups', 'etc', 'srv/www', 'home/admin', 'opt/app/config', 'var/lib/mysql'];
        $stems = ['dump', 'db_full', 'config', 'settings', 'credentials', 'accounts', 'wp-config', 'app', 'secrets', 'ldap', 'vault', 'nginx', 'archive', 'snapshot', 'export'];
        $exts = ['sql', 'sql.gz', 'tar.gz', 'conf', 'env', 'json', 'yml', 'pem', 'bak', 'xml'];

        $files = [];
        for ($i = 0; $i < self::MANIFEST_FILES; $i++) {
            $dir = (string) Draw::pick($fsSeed, $i * 4, $dirs);
            $stem = (string) Draw::pick($fsSeed, $i * 4 + 1, $stems);
            $ext = (string) Draw::pick($fsSeed, $i * 4 + 2, $exts);
            $n = Draw::intBelow($fsSeed, $i * 4 + 3, 1000);
            // Heavy-tailed sizes: mostly small configs, a few large dumps (bytes). Its draw index sits
            // past the name picks' index space (0..FILES*4-1) so the two never collide.
            $size = Draw::heavyTailedInt($fsSeed, self::MANIFEST_FILES * 4 + $i, 512, 64 * 1024 * 1024);
            $files[] = ['path' => $dir . '/' . $stem . '-' . $n . '.' . $ext, 'size' => $size];
        }

        return ['seed' => $seed, 'host' => $hostname, 'files' => $files, 'throttle' => $this->throttleBlock()];
    }

    /** @return array<string,int> the client SW reads these — one source of truth for speed/variability. */
    public function throttleBlock(): array
    {
        $min = $this->chunkMinKb;
        $max = max($min, $this->chunkMaxKb); // tolerate a misconfigured max < min
        $wt = $this->easePeriodS;

        return [
            'chunkMinKb' => $min,
            'chunkMaxKb' => $max,
            'intervalMs' => $this->intervalMs,
            'varyPct' => $this->varyPct,
            'easePeriodS' => $wt,
        ];
    }

    /**
     * A ZIP local file header (store method, general-purpose bit 3 set so sizes live in a trailing data
     * descriptor and need not be known up front). Pure + testable. Little-endian throughout.
     */
    public function localFileHeader(string $name): string
    {
        $name = substr($name, 0, 255);

        return "PK\x03\x04"
            . pack('v', 20)      // version needed
            . pack('v', 0x0008)  // flags: bit 3 (data descriptor)
            . pack('v', 0)       // compression: store
            . pack('v', 0)       // mod time
            . pack('v', 0)       // mod date
            . pack('V', 0)       // crc32 (in descriptor)
            . pack('V', 0)       // compressed size (in descriptor)
            . pack('V', 0)       // uncompressed size (in descriptor)
            . pack('v', strlen($name))
            . pack('v', 0)       // extra length
            . $name;
    }

    /** Deterministic, ASCII-ish filler for one file's store bytes — looks like config/dump text. */
    public function fill(int $seed, int $len): string
    {
        if ($len <= 0) {
            return '';
        }
        $block = base64_encode(hash('sha256', 'fill|' . $seed, true) . hash('sha256', 'fill2|' . $seed, true));
        $out = str_repeat($block, (int) ceil($len / strlen($block)));

        return substr($out, 0, $len);
    }

    /**
     * Inter-chunk delay for the n-th chunk under the sine-eased breathing rate (ms). The PHP mirror of
     * the client SW's easedDelay(); the server no longer paces its fallback (see streamFallback), so this
     * is the canonical reference for the throttle formula and its bounds, exercised by the unit tests.
     */
    public function easedDelayMs(int $n): int
    {
        $base = $this->intervalMs;
        // Advance phase by ~one base interval per chunk (elapsed ≈ n * base).
        $elapsedS = ($n * $base) / 1000.0;
        $period = max(1, $this->easePeriodS);
        $factor = 1.0 + ($this->varyPct / 100.0) * sin(2 * M_PI * ($elapsedS / $period));
        if ($factor < 0.2) {
            $factor = 0.2;
        }
        $delay = (int) round($base / $factor);
        $lo = (int) round($base * 0.2);
        $hi = (int) round($base * 5);

        return max($lo, min($hi, $delay));
    }

    /**
     * Non-JS fallback zip: emit local-file-header + store bytes per manifest entry until the byte cap.
     * No central directory — a capped download simply looks truncated (the point is the time/bandwidth
     * sink, not an extractable archive). Yields chunks so tests can drain without streaming or sleeping.
     *
     * @return \Generator<int,string>
     */
    public function fallbackChunks(string $host, int $capBytes): \Generator
    {
        $m = $this->manifest($host);
        $sent = 0;
        $chunkBytes = max(1, $this->chunkMinKb) * 1024;
        foreach ($m['files'] as $idx => $f) {
            if ($sent >= $capBytes) {
                return;
            }
            $header = $this->localFileHeader((string) $f['path']);
            yield $header;
            $sent += strlen($header);

            $remainingForFile = (int) $f['size'];
            $fileSeed = ($m['seed'] ^ ($idx * 2654435761)) & PHP_INT_MAX;
            while ($remainingForFile > 0 && $sent < $capBytes) {
                $take = (int) min($chunkBytes, $remainingForFile, $capBytes - $sent);
                $chunk = $this->fill($fileSeed + $sent, $take);
                yield $chunk;
                $sent += strlen($chunk);
                $remainingForFile -= $take;
            }
        }
    }

    /**
     * Non-JS fallback: stream the capped zip as fast as the socket drains — NO server-side pacing. The
     * throttle is a browser-side deception (the SW's job, on the attacker's own CPU); pacing here would
     * only pin a php-fpm worker for the whole transfer on a gate-exempt, unauthenticated route, and a
     * curl/scanner client judges no "broadband realism" anyway. So this is just a bounded static-ish
     * download, no worse than serving any capped file.
     */
    private function streamFallback(string $host): void
    {
        $cap = $this->fallbackCapMb * 1024 * 1024;

        $emitter = ($this->emitterFactory)();
        $emitter->begin(200, [
            'Content-Type' => 'application/zip',
            'Content-Disposition' => 'attachment; filename="backup.zip"',
            'Cache-Control' => 'no-store',
        ]);
        try {
            foreach ($this->fallbackChunks($host, $cap) as $chunk) {
                $emitter->chunk($chunk);
                if (connection_aborted() !== 0) {
                    return;   // client hung up — stop fabricating bytes
                }
            }
        } catch (\Throwable $e) {
            // Headers already sent — a mid-stream fault just ends the download early, never a 500.
        }
    }

    private function hostFromQuery(string $query): string
    {
        parse_str($query, $q);
        $h = isset($q['host']) && is_string($q['host']) ? $q['host'] : '';

        return substr($h, 0, self::NAME_MAX);
    }

    /**
     * One bait row per admitted event; past the per-actor window cap the event is only counted and the
     * count is folded into the next kept row. $ip is the front controller's trusted-client-IP result.
     */
    private function logBait(string $ip, string $method, string $host): void
    {
        $admit = $this->bait->admit($ip);
        if (!$admit['keep']) {
            return;
        }
        $body = $host !== '' ? 'host=' . $host : '';
        if ($admit['suppressed'] > 0) {
            $body .= ($body !== '' ? ' ' : '') . 'suppressed=' . $admit['suppressed'];
        }
        $this->hits->append([
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => $method,
            'path' => self::ZIP_PATH,
            'matched' => true,
            'served' => true,
            'severity' => 'info',
            'event' => 'download',
            'body' => $body,
        ]);
    }

    /** @param array<string,string> $headers */
    private function emit(int $status, array $headers, string $body): void
    {
        $emitter = ($this->emitterFactory)();
        $emitter->begin($status, $headers);
        if ($body !== '') {
            foreach (str_split($body, 8192) as $chunk) {
                $emitter->chunk($chunk);
            }
        }
    }
}

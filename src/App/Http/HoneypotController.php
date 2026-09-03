<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\App\ThreatIntel\OperatorBlocklist;
use Funnypot\App\ThreatIntel\ReportComment;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Http\ResponseEmitter;
use Funnypot\Core\Log4ShellProbe;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Core\RequestContext;
use Geo;

/**
 * The honeypot itself: run an incoming probe through the funnypot-core engine (detect + gated
 * respond), log every request, and serve either the fake, a decoy archive, or a believable 404.
 * Also owns the two small deception endpoints that sit next to it (robots.txt, favicon).
 */
final class HoneypotController
{
    public function __construct(
        private HitStore $store,
        private Geo $geo,
        private AppConfig $config,
        private string $decoyDir,
        private ?Blocklist $blocklist = null,
        private ?AbuseIpdb $abuse = null,
        private ?ThreatIntelReporter $threatIntel = null,
        private ?LlmFakeResponder $llmFakes = null,
        private ?AttackClassifier $attackClassifier = null,
        private ?OperatorBlocklist $operatorBlock = null,
        private ?SleepDecoy $sleepDecoy = null,
    ) {
    }

    /** A small delay applied to the LLM fake and the plain 404 so their timing matches a served
     *  template fake (which already delays inside the engine), leaving at most one timing bucket. */
    private function serveDelay(): void
    {
        $ms = $this->config->latencyMs + ($this->config->jitterMs > 0 ? random_int(0, $this->config->jitterMs) : 0);
        if ($ms > 0) {
            usleep($ms * 1000);
        }
    }

    /** True if the client IP is a known attacker (present in the intel blocklist). */
    private function known(string $ip): bool
    {
        return $this->blocklist !== null && $this->blocklist->isKnown($ip);
    }

    /**
     * The real client IP. X-Forwarded-For is client-spoofable, and this IP drives the probe gate,
     * the logs, AND AbuseIPDB reports — so trusting a forged header would let an attacker frame an
     * innocent IP (get it reported/blocklisted) or dodge the per-IP gate by rotating the header.
     *
     * So XFF is only honoured when the TCP peer (REMOTE_ADDR) is itself a configured trusted proxy;
     * then we take the right-most XFF hop that is not also a trusted proxy (the real client at our
     * trust boundary). With no trusted proxies configured — the edge deployment — the peer is the
     * client and any client-supplied XFF is ignored.
     *
     * @param string[] $trustedProxies IPs / CIDRs of proxies in front of us (empty = we are the edge)
     */
    public static function clientIp(array $trustedProxies = []): string
    {
        $remote = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if ($trustedProxies === [] || !self::isTrustedPeer($trustedProxies)) {
            return $remote;
        }

        $hops = array_values(array_filter(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''))));
        for ($i = count($hops) - 1; $i >= 0; $i--) {
            if (!self::ipInCidrList($hops[$i], $trustedProxies)) {
                return $hops[$i];
            }
        }

        return $remote;
    }

    /**
     * True when the TCP peer (REMOTE_ADDR) is itself a configured trusted proxy (FP-0250 2.5). Public
     * so demo/index.php can gate honouring X-Forwarded-Proto on the SAME trust boundary XFF already
     * uses via clientIp() above — an untrusted peer's XFP must not be believed either, else any client
     * could forge "I'm HTTPS" and flip the admin session cookie's Secure flag off over plain HTTP.
     * Empty $trustedProxies (the edge deployment, no proxy in front) always returns false — the
     * default-closed direction: no declared proxy list means nothing is trusted.
     *
     * @param string[] $trustedProxies IPs / CIDRs of proxies in front of us
     */
    public static function isTrustedPeer(array $trustedProxies): bool
    {
        if ($trustedProxies === []) {
            return false;
        }

        return self::ipInCidrList((string) ($_SERVER['REMOTE_ADDR'] ?? ''), $trustedProxies);
    }

    /** True if $ip matches any entry (a bare IP is exact-match; an a.b.c.d/n is an IPv4 CIDR). */
    private static function ipInCidrList(string $ip, array $list): bool
    {
        foreach ($list as $entry) {
            if ($entry === $ip) {
                return true;
            }
            if (strpos($entry, '/') !== false && self::ipInCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    /** IPv4 CIDR membership. Non-IPv4 inputs (either side) never match — callers fall back to peer. */
    private static function ipInCidr(string $ip, string $cidr): bool
    {
        [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, '32');
        $ipL = ip2long($ip);
        $netL = ip2long($net);
        $bits = (int) $bits;
        if ($ipL === false || $netL === false || $bits < 0 || $bits > 32) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask = -1 << (32 - $bits);

        return ($ipL & $mask) === ($netL & $mask);
    }

    /** A robots.txt whose Disallow list is bait: every entry points at one of the honeypot's fakes. */
    public function robots(): void
    {
        header('Content-Type: text/plain; charset=utf-8');
        echo "User-agent: *\n"
            . "Disallow: /.git/\n"
            . "Disallow: /.env\n"
            . "Disallow: /backup/\n"
            . "Disallow: /wp-admin/\n"
            . "Disallow: /phpmyadmin/\n"
            . "Disallow: /admin/\n"
            . "Disallow: /credentials.txt\n"
            . "Disallow: /backup.sql\n"
            . "Disallow: /.aws/\n"
            . "Sitemap: https://www.example.com/sitemap.xml\n";
    }

    /**
     * A browser viewing our own dashboard auto-requests /favicon.ico. If it came from our page
     * (same-origin Referer), ignore it — no honeypot, no log noise. A scanner probing favicon
     * directly (no/foreign Referer) falls through to be served + logged. Returns true when handled.
     */
    public function faviconSameOrigin(): bool
    {
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        if ($host !== '' && strpos($referer, '://' . $host) !== false) {
            http_response_code(204);

            return true;
        }

        return false;
    }

    /** Run the probe through the engine, log it, and emit a fake / decoy archive / believable 404. */
    public function handle(RequestContext $context, string $clientIp, string $tokenVerdict): void
    {
        // Operator manual block: a manually blocked source is served the plain believable 404 and nothing
        // else — no engine, no LLM, no decoy, no report, and NO stored row. Same body a genuine miss
        // returns, so the block is invisible to the attacker; not recording it is the point (a blocked
        // flood must not keep growing the store). The dashboard's blocked-IP list is the visibility
        // surface. Checked before the engine so a blocked source costs one O(1) lookup + a static 404.
        if ($this->operatorBlock !== null && $this->operatorBlock->isBlocked($clientIp)) {
            $this->serveDelay();
            http_response_code(404);
            header('Content-Type: text/html');
            echo "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
                . "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
                . "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

            return;
        }

        // The emulation catalog's on/off choices become the engine's deny-set + corpus flag.
        $policy = EmulationPolicy::fromPackage(is_file($this->config->vulnsPath) ? $this->config->vulnsPath : null);
        $funnypot = Honeypot::default(new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,          // standalone honeypot: everything hostile-looking gets a fake
            severityCeiling: $this->config->severityCeiling,
            responseStyle: $this->config->httpStyle(), // core supports realistic|taunt; 'malformed' (protocol-only) -> realistic here
            personaSeed: static fn (RequestContext $r) => $clientIp ?: 'anon',
            // Per-deploy identity material shared with the app tier: once the engine wires deploySeed()
            // into its renderers, the template tier's {{persona.*}} resolves the SAME company/domain/admin
            // the LLM/skin pages show. Distinct from personaSeed above (per-request; drives fake secrets).
            deploySeed: $this->config->personaMaterial,
            latencyMs: $this->config->latencyMs,
            latencyJitterMs: $this->config->jitterMs,
            attackEmulation: $this->config->attackEmulation,
            poweredBy: $this->config->poweredBy,
            exclude: $policy->disabledIds(),
            nucleiReflection: $policy->nucleiEnabled(),
            isolatedOrigin: true, // standalone honeypot owns its origin — reflecting decoys (XSS/open-redirect) are safe bait here (FP-0159; requires core >= 0.6.1)
        ));

        $detection = $funnypot->detect($context);

        // FP-0228: honour a time-based blind-injection SLEEP probe with a metered, slot-gated,
        // budget-bounded delay. Placed here — after detect(), before ANY serve branch below — so it
        // covers EVERY path a sleep probe can be answered on (served attack fake, panel, LLM fake, 404)
        // uniformly, additive to serveDelay(). This is deliberate: SHOULD-FIX 1 — a recognised SQLi
        // SLEEP probe is SERVED an attack fake ($response !== null), where the fall-through $payloadClass
        // (computed only on the 404 miss below) is null; SleepDecoy classifies the sleep structure
        // INDEPENDENTLY instead. It self-gates (structure present + sqli/rce + budget + a won slot), so a
        // benign/non-sleep request returns after one regex, off-by-default is a no-op ($sleepDecoy null),
        // and any budget fault degrades to zero delay — never a 500. The standalone controller always
        // runs respond + gate-open + isolated-origin (below), the posture this decoy is scoped to.
        $this->sleepDecoy?->maybeDelay($context, $clientIp);

        // The honeypot's own admin panel (/admin, /dashboard, … mounted at the path root, and every
        // sub-path) is a deep-engagement lure and must be served by the panel emulator and logged as
        // 'panel'. The engine's nuclei-reflection corpus also matches these bare mount segments and would
        // otherwise serve + label them 'nuclei', shadowing the panel's own landing page. Give the panel
        // precedence for its root-mounted paths — it renders deterministically (no model call,
        // gate-exempt) and logs its own 'panel' hit. Yield to the engine when it flagged a genuine attack
        // aimed at a panel path (the 'attack' corpus: SQLi/XSS/RCE) so those are still served, labelled
        // and reported; only a plain product-detection reflection loses to the panel. Root-anchored on
        // purpose: a mount that appears deeper (/wp-admin/admin.php) belongs to a product emulator the
        // engine owns, not to us.
        if ($this->llmFakes !== null
            && PanelRoute::mountedAtRoot($context->path)
            && !in_array('attack', $detection->tags(), true)) {
            $panel = $this->llmFakes->respond($context, $clientIp);   // writes its own 'panel' hit
            if ($panel !== null) {
                $this->serveDelay();
                ResponseEmitter::emit($panel);

                return;
            }
        }

        $response = $funnypot->respond($context);

        // When a fake was served, log what it actually satisfied; else the detect() signal.
        $logged = $response !== null ? $response->satisfies : $detection;

        // Fall-through only (engine matched nothing): an obvious attack payload aimed at a path we
        // have no template for would otherwise log as a plain 404 and go unreported. Classify it
        // (high-precision) so it is labelled for the dashboard and the attacker is still reported.
        $payloadClass = ($response === null && !$logged->matched)
            ? $this->attackClassifier?->classify($context)
            : null;

        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $clientIp,
            'method' => $context->method,
            'path' => substr($context->path, 0, 200),
            'ua' => substr($context->headers['User-Agent'] ?? '', 0, 160),
            'matched' => $logged->matched || $payloadClass !== null,
            'severity' => $payloadClass !== null ? AttackClassifier::severityFor($payloadClass) : $logged->highestSeverity,
            'templates' => $payloadClass !== null ? ['payload-' . $payloadClass] : array_slice($logged->templateIds(), 0, 8),
            'served' => $response !== null,
            'style' => $this->config->style,
            'body' => $context->rawBody !== null ? substr($context->rawBody, 0, 300) : null,
            'referer' => substr($context->headers['Referer'] ?? '', 0, 160) ?: null,
            'log4shell' => Log4ShellProbe::present($context) ?: null,
            'honeytoken' => $tokenVerdict !== 'off' ? $tokenVerdict : null,
            'geo' => $this->geo->lookup($clientIp),
            'known_attacker' => $this->known($clientIp),
        ]);

        if ($response !== null) {
            ResponseEmitter::emit($response);
        } elseif (!$this->serveDecoyArchive($context, $clientIp)) {
            // A plausible unknown path may get an LLM-generated fake; everything else (declined,
            // failed, or the responder being off) falls through to the believable plain 404.
            $llm = $this->llmFakes?->respond($context, $clientIp);
            $this->serveDelay();
            if ($llm !== null) {
                ResponseEmitter::emit($llm);
            } else {
                // Non-detection (or matched-but-declined): a believable server 404, not a constant string.
                http_response_code(404);
                header('Content-Type: text/html');
                echo "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
                    . "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
                    . "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
            }
        }

        // Queue an AbuseIPDB report for the attacker (a fast local write; the drain worker sends it):
        // an engine match, OR a payload class the fall-through classifier caught on an unmatched path.
        $this->maybeReport($logged->matched || $payloadClass !== null, $clientIp, $context, $payloadClass);
    }

    /** Queue a web attacker for the reporters (AbuseIPDB and/or our Threat Intel service), with the
     *  port + URL (and the detected class, if any) in the comment. Reports both engine-matched attacks
     *  and classifier-caught payloads on unmatched paths. Each reporter is independent; both enqueues
     *  are fast local writes that never touch the network on the request path. */
    private function maybeReport(bool $report, string $clientIp, RequestContext $context, ?string $payloadClass = null): void
    {
        if (!$report || ($this->abuse === null && $this->threatIntel === null)) {
            return;
        }
        $port = (int) ($_SERVER['SERVER_PORT'] ?? 0);
        // FP-0247 (Fix H): NEVER put the attacker-controlled Host header in a public report — it can
        // name an innocent third-party domain. Report our port + method + PATH only; ReportComment
        // additionally strips a scheme://host from an absolute-URI request line and redacts secrets.
        $class = $payloadClass !== null ? ' [' . $payloadClass . ']' : '';
        $comment = ReportComment::build(
            sprintf('funnypot web honeypot, port %d:%s %s', $port, $class, $context->method),
            $context->path
        );
        // FP-0247 (Fix F): class-accurate categories (SQLi -> 16,21 etc.) instead of a static '21', and
        // wire the previously-dead signals/confidence params on the Threat Intel report.
        $categories = AbuseIpdb::categoriesForWebClass($payloadClass);
        $signals = ['method' => $context->method, 'port' => $port];
        if ($payloadClass !== null) {
            $signals['class'] = $payloadClass;
        }
        $confidence = $payloadClass !== null
            ? (['critical' => 0.9, 'high' => 0.8, 'medium' => 0.6][AttackClassifier::severityFor($payloadClass)] ?? 0.6)
            : 0.7;   // an engine match without a specific payload class
        $this->abuse?->enqueue($clientIp, $comment, $categories);
        $this->threatIntel?->enqueue($clientIp, $comment, $categories, $signals, $confidence);
    }

    /**
     * Map a probed path's suffix to a static decoy asset. Longest suffix first so .tar.gz wins over
     * .gz and .tar.bz2 over a bare .tar. Text formats (.sql/.pem/.cer) serve plausible text — never a
     * relabeled archive — so the byte content matches the extension a scanner asked for.
     *
     * @return array{0:string,1:string}|null [decoyFile, contentType], or null for an unmapped suffix.
     */
    private static function decoyForPath(string $path): ?array
    {
        $map = [
            '.tar.gz' => ['backup.tar.gz', 'application/gzip'],
            '.tar.bz2' => ['backup.tar.bz2', 'application/x-bzip2'],
            '.tbz2' => ['backup.tar.bz2', 'application/x-bzip2'],
            '.tgz' => ['backup.tar.gz', 'application/gzip'],
            '.tar' => ['backup.tar', 'application/x-tar'],
            '.gz' => ['backup.tar.gz', 'application/gzip'],
            '.zip' => ['backup.zip', 'application/zip'],
            '.sql' => ['backup.sql', 'application/sql'],
            '.pem' => ['backup.pem', 'application/x-pem-file'],
            '.cer' => ['backup.cer', 'application/x-x509-ca-cert'],
            // Specific filename match (NOT a broad '.json') so an unrelated probe like /foo/config.json
            // never gets the keystore — only a path that literally ends in "wallet.json" does.
            'wallet.json' => ['wallet.json', 'application/json'],
        ];
        $path = strtolower($path);
        foreach ($map as $ext => $decoy) {
            if (substr($path, -strlen($ext)) === $ext) {
                return $decoy;
            }
        }
        return null;
    }

    /**
     * Serve a decoy archive/dump/cert for a probe (.zip / .tar.gz / .sql / .pem …) that would
     * otherwise 404. The decoys are prebuilt static assets named after what was asked for.
     * Off-switch: decoyArchive=false. GET only. Returns true when it served one.
     */
    private function serveDecoyArchive(RequestContext $r, string $clientIp): bool
    {
        if ($r->method !== 'GET' || !$this->config->decoyArchive) {
            return false;
        }

        $mapped = self::decoyForPath($r->path);
        if ($mapped === null) {
            return false;
        }
        [$decoy, $ctype] = $mapped;

        $name = basename($r->path);
        if ($name === '' || strpos($name, '.') === false) {
            $name = $decoy;
        }
        $name = (string) preg_replace('/[^\w.\-]/', '_', $name);

        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $clientIp,
            'method' => 'GET',
            'path' => substr($r->path, 0, 200),
            'event' => 'decoy-archive',
            'decoy' => $decoy,
            'geo' => $this->geo->lookup($clientIp),
            'known_attacker' => $this->known($clientIp),
        ]);

        // Serve the small static decoy asset as-is. (The endless/streaming download bait lives ONLY in
        // the fleet console's own /__dl/backup.zip surface, client-side via the service worker — it is
        // NOT applied to this open scanner-facing decoy-archive path: doing so would (a) let a browser
        // service worker shadow the honeypot's own reporting of these probes, and (b) turn every
        // .zip/.sql/.tar.gz probe into a ~50 MB worker-pinning amplifier with no per-IP limit.)
        $full = $this->decoyDir . '/' . $decoy;
        if (!is_file($full)) {
            return false;
        }
        $bytes = (string) file_get_contents($full);

        http_response_code(200);
        header('Content-Type: ' . $ctype);
        header('Content-Disposition: attachment; filename="' . $name . '"');
        header('Content-Length: ' . strlen($bytes));
        echo $bytes;

        return true;
    }
}

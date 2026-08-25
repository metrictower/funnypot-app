<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Http\ResponseEmitter;
use Funnypot\Core\Log4ShellProbe;
use Funnypot\Policy\EmulationPolicy;
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
        if ($trustedProxies === [] || !self::ipInCidrList($remote, $trustedProxies)) {
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
        // The emulation catalog's on/off choices become the engine's deny-set + corpus flag.
        $policy = EmulationPolicy::fromPackage(is_file($this->config->vulnsPath) ? $this->config->vulnsPath : null);
        $funnypot = Honeypot::default(new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,          // standalone honeypot: everything hostile-looking gets a fake
            severityCeiling: $this->config->severityCeiling,
            responseStyle: $this->config->style,
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
        ));

        $detection = $funnypot->detect($context);
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
        $httpsVal = (string) ($_SERVER['HTTPS'] ?? '');
        $https = ($httpsVal !== '' && $httpsVal !== 'off') || $port === 443;
        $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
        $url = ($host !== '' ? ($https ? 'https' : 'http') . '://' . $host : '') . $context->path;
        $class = $payloadClass !== null ? ' [' . $payloadClass . ']' : '';
        $comment = sprintf('funnypot web honeypot, port %d:%s %s %s', $port, $class, $context->method, substr($url, 0, 180));
        $this->abuse?->enqueue($clientIp, $comment, '21');         // web app attack
        $this->threatIntel?->enqueue($clientIp, $comment, '21');
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

        $full = $this->decoyDir . '/' . $decoy;
        if (!is_file($full)) {
            return false;
        }
        $bytes = (string) file_get_contents($full);

        $name = basename($r->path);
        if ($name === '' || strpos($name, '.') === false) {
            $name = $decoy;
        }
        $name = preg_replace('/[^\w.\-]/', '_', $name);

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

        http_response_code(200);
        header('Content-Type: ' . $ctype);
        header('Content-Disposition: attachment; filename="' . $name . '"');
        header('Content-Length: ' . strlen($bytes));
        echo $bytes;

        return true;
    }
}

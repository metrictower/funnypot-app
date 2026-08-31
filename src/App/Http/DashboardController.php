<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\AnalyticsStore;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\ThreatIntel\OperatorBlocklist;
use Funnypot\App\Emulation\EmulationCatalog;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\Protocol\Sip\WavWriter;
use Geo;

/**
 * The operator dashboard: the live JSON feed, the password-gated admin actions, and the HTML shell
 * that polls the feed and updates in place. In public mode it is served at /; in stealth mode the
 * router mounts it under the hidden dashboard path.
 */
final class DashboardController
{
    public function __construct(
        private HitStore $store,
        private Geo $geo,
        private AppConfig $config,
        private string $assetsDir,
        private ?LlmFakeCache $llmCache = null,
        private ?OperatorBlocklist $operatorBlock = null,
        // The read-side analytics API (FP-0243). In production this is the SAME SqliteHitStore
        // instance passed as $store (it implements both HitStore and AnalyticsStore); it is a
        // separate constructor param so the interface, not the concrete store, is the dependency and
        // so a HitStore test double without rollups can still construct the controller (analytics
        // then degrades to empty widgets, never a 500 — the operator-only view just shows nothing).
        private ?AnalyticsStore $analytics = null,
    ) {
    }

    /**
     * Live JSON feed. Modes via $_GET:
     *   feed=1&after=<cursor>  delta — only rows since the cursor
     *   feed=older&skip=<n>    page back through history, newest-first
     */
    public function feed(): void
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');

        // JSON_INVALID_UTF8_SUBSTITUTE: a stored row can still hold non-UTF-8 bytes from the binary
        // protocol honeypots; without this one bad byte makes json_encode return false and the feed
        // goes blank.
        $flags = JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE;
        $filters = $this->filters();
        if (($_GET['feed'] ?? '') === 'older') {
            echo json_encode($this->store->older(max(0, (int) ($_GET['skip'] ?? 0)), $filters), $flags);

            return;
        }

        $out = $this->store->delta((int) ($_GET['after'] ?? 0), $filters);
        $out['stats'] = $this->store->stats();
        $out['widgets'] = $this->store->widgets();
        echo json_encode($out, $flags);
    }

    /**
     * Collect the whitelisted feed filters from the query string. Values are bound by the store, so
     * this only decides which filters are present, never how they are interpolated.
     *
     * @return array<string,mixed>
     */
    private function filters(): array
    {
        $f = [];
        foreach (['method', 'event', 'ip', 'cc', 'severity', 'q', 'recording', 'tool', 'ts_from', 'ts_to'] as $k) {
            if (isset($_GET[$k]) && $_GET[$k] !== '') {
                $f[$k] = (string) $_GET[$k];
            }
        }
        if (isset($_GET['matched'])) {
            $f['matched'] = true;
        }
        if (isset($_GET['served'])) {
            $f['served'] = true;
        }
        if (isset($_GET['known'])) {
            $f['known'] = true;
        }

        return $f;
    }

    /**
     * Password-gated admin actions. The VIEW stays public; the mutating actions (retention prune,
     * clear, DB backfill, catalog edits) AND the operator-only analytics read (FP-0243b) all require
     * FUNNYPOT_ADMIN_PASSWORD. Disabled if that env is unset.
     */
    public function admin(string $action): void
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');

        $pass = $this->config->adminPassword;
        $given = (string) ($_SERVER['HTTP_X_ADMIN_TOKEN'] ?? ($_POST['key'] ?? ''));
        if ($pass === '' || !hash_equals($pass, $given)) {
            http_response_code(403);
            echo json_encode(['error' => $pass === '' ? 'admin disabled (set FUNNYPOT_ADMIN_PASSWORD)' : 'forbidden']);

            return;
        }

        // Operator-only analytics (FP-0243b). Reads the O(buckets) rollup API + retention-bounded
        // top-N. Runs ONLY behind the admin auth above (same adminPassword/X-Admin-Token gate as
        // every other action), so it is no more reachable than the rest of the admin surface and, in
        // stealth mode, rides the hidden dashboard path — never the deception surface (spec §9).
        // Every store call is wrapped so any query fault degrades to an empty widget and a 200, never
        // a 500 tell (spec §9; mirrors demo/index.php's "only ever a 404, never a 500" invariant).
        if ($action === 'analytics') {
            $flags = JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE;
            $win = min(31536000, max(60, (int) ($_GET['win'] ?? 86400)));       // breakdown/series window
            $agWin = min($win, max(30, (int) ($_GET['ag_win'] ?? 300)));        // at-a-glance rate window
            $gran = in_array($_GET['gran'] ?? '', ['m', 'h', 'd'], true) ? (string) $_GET['gran'] : 'h';
            $since = time() - $win;

            // Each widget computed independently: one failing dimension yields its own empty slot,
            // never a blank page or a 500. $this->analytics may be null (a HitStore-only wiring) — the
            // wrapper then returns the empty default without calling the store, same net result as a
            // caught query fault.
            $safe = function (callable $fn, $default) {
                try {
                    return $this->analytics !== null ? $fn() : $default;
                } catch (\Throwable $e) {
                    error_log('funnypot analytics: ' . $e->getMessage());

                    return $default;
                }
            };

            $breakdown = [];
            foreach (['protocol', 'event', 'severity', 'status', 'country', 'tool'] as $dim) {
                $breakdown[$dim] = $safe(fn () => $this->analytics->breakdown($dim, $since, $gran), []);
            }
            // The busiest protocols drive the events-over-time multi-series (one line each).
            $topProto = array_slice(array_column($breakdown['protocol'], 'val'), 0, 6);
            $series = $topProto === [] ? [] : $safe(fn () => $this->analytics->series('protocol', $topProto, $since, $gran), []);

            $topN = [];
            foreach (['ip', 'asn', 'path', 'tool', 'cc'] as $dim) {
                $topN[$dim] = $safe(fn () => $this->analytics->topN($dim, 15, $since), []);
            }
            $ataglance = $safe(fn () => $this->analytics->ataglance($agWin), [
                'window_s' => $agWin, 'events' => 0, 'rate' => 0.0, 'unique_ips' => 0, 'new' => 0, 'returning' => 0,
            ]);

            echo json_encode([
                'ok' => true, 'win' => $win, 'gran' => $gran,
                'breakdown' => $breakdown, 'series' => $series, 'topN' => $topN, 'ataglance' => $ataglance,
            ], $flags);

            return;
        }

        if ($action === 'prune') {
            $this->store->prune(max(0, (int) ($_POST['keep'] ?? 1000)));
            echo json_encode(['ok' => true]);

            return;
        }
        if ($action === 'clear') {
            $this->store->clear();
            echo json_encode(['ok' => true, 'cleared' => true]);

            return;
        }
        if ($action === 'import') {
            echo json_encode(['ok' => true, 'imported' => $this->store->import()]);

            return;
        }
        if ($action === 'geoip') {
            echo json_encode(['ok' => true, 'ranges' => $this->geo->import()]);

            return;
        }

        // Emulation catalog: read the full toggle list (catalog + resolved on/off state).
        if ($action === 'vulns') {
            $file = $this->config->vulnsPath;
            $policy = EmulationPolicy::fromPackage(is_file($file) ? $file : null);
            echo json_encode(['ok' => true, 'vulns' => array_values($policy->resolved())]);

            return;
        }

        // Emulation catalog: persist toggle changes to funnypot-vulns.json.
        if ($action === 'vulns-save') {
            $file = $this->config->vulnsPath;
            $changes = json_decode((string) ($_POST['changes'] ?? '[]'), true);
            $catalog = EmulationCatalog::fromPackage();
            $vulns = EmulationPolicy::fromCatalog($catalog, is_file($file) ? $file : null)->materialize();
            $applied = 0;
            foreach ((array) $changes as $id => $on) {
                if (is_string($id) && $catalog->has($id)) {
                    $vulns[$id] = (bool) $on;
                    $applied++;
                }
            }
            $payload = [
                'version' => 1,
                'updated' => gmdate('c'),
                'note' => 'Toggle which emulations funnypot serves. true = serve, false = off.',
                'vulns' => $vulns,
            ];
            @mkdir(dirname($file), 0777, true);
            $wrote = @file_put_contents($file, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
            echo json_encode(['ok' => $wrote !== false, 'saved' => $applied]);

            return;
        }

        // LLM cache: list every generated fake (path, status, size, serve count, and the body the
        // attacker got) so the operator can review what the model wrote.
        if ($action === 'llm-cache') {
            $flags = JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE;
            echo json_encode([
                'ok' => true,
                'enabled' => $this->llmCache !== null,
                'entries' => $this->llmCache !== null ? $this->llmCache->all(1000) : [],
                'stats' => $this->llmCache !== null ? $this->llmCache->stats() : ['entries' => 0, 'bytes' => 0, 'served' => 0],
            ], $flags);

            return;
        }

        // LLM cache: delete one bad response by its cache key; it will regenerate on the next hit.
        if ($action === 'llm-cache-delete') {
            $key = (string) ($_POST['key'] ?? '');
            $ok = $this->llmCache !== null && $key !== '' && $this->llmCache->delete($key);
            echo json_encode(['ok' => $ok]);

            return;
        }

        // LLM cache: drop every cached fake (operator reset).
        if ($action === 'llm-cache-clear') {
            echo json_encode(['ok' => true, 'cleared' => $this->llmCache !== null ? $this->llmCache->clearAll() : 0]);

            return;
        }

        // Operator manual block: add/remove an IP (or IPv4 CIDR); enforced across every tier. Persistent.
        if ($action === 'block-ip') {
            $ip = trim((string) ($_POST['ip'] ?? ''));
            if ($this->operatorBlock === null) {
                echo json_encode(['ok' => false, 'ip' => $ip, 'error' => 'blocklist unavailable']);

                return;
            }
            // Validate before storing, so a typo/invalid entry (which would never match) is rejected
            // rather than falsely reported as blocked.
            if (!OperatorBlocklist::isValidEntry($ip)) {
                echo json_encode(['ok' => false, 'ip' => $ip, 'error' => 'not a valid IP or IPv4 CIDR']);

                return;
            }
            // Guard the operator against self-lockout: never block their own configured egress IP.
            if (in_array($ip, $this->config->selfIps, true)) {
                echo json_encode(['ok' => false, 'ip' => $ip, 'error' => 'refusing to block a FUNNYPOT_SELF_IPS address']);

                return;
            }
            $this->operatorBlock->add($ip, substr((string) ($_POST['note'] ?? ''), 0, 200));
            echo json_encode(['ok' => true, 'ip' => $ip]);

            return;
        }
        if ($action === 'unblock-ip') {
            $ip = trim((string) ($_POST['ip'] ?? ''));
            $ok = $this->operatorBlock !== null && $ip !== '';
            if ($ok) {
                $this->operatorBlock->remove($ip);
            }
            echo json_encode(['ok' => $ok, 'ip' => $ip]);

            return;
        }
        if ($action === 'blocked') {
            echo json_encode(['ok' => true, 'blocked' => $this->operatorBlock !== null ? $this->operatorBlock->all() : []]);

            return;
        }

        http_response_code(400);
        echo json_encode(['error' => 'unknown action']);
    }

    /**
     * The dashboard shell: static HTML + the extracted CSS/JS, inlined so there is one response.
     * $base is the path the feed/admin endpoints live under ("/" in public mode, the hidden
     * dashboard path in stealth); the JS reads it from window.FP_BASE.
     */
    public function shell(string $base = '/'): void
    {
        header('Content-Type: text/html; charset=utf-8');

        $css = (string) @file_get_contents($this->assetsDir . '/app.css');
        $js = (string) @file_get_contents($this->assetsDir . '/app.js');
        // Operator analytics view (FP-0243b): uPlot is vendored + served same-origin (no CDN), and
        // both it and analytics.js are inlined like app.css/app.js so the shell is one response.
        $uplotCss = (string) @file_get_contents($this->assetsDir . '/uplot.min.css');
        $uplotJs = (string) @file_get_contents($this->assetsDir . '/uplot.min.js');
        $analyticsJs = (string) @file_get_contents($this->assetsDir . '/analytics.js');

        echo "<!doctype html><html lang=en><head><meta charset=utf-8>";
        echo "<meta name=viewport content='width=device-width,initial-scale=1'>";
        echo "<link rel=stylesheet href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css' crossorigin>";
        echo "<title>funnypot</title><style>{$css}{$uplotCss}</style></head><body><div class=wrap>";
        echo "<div class=head><h1>Welcome to <span class=honey>funnypot</span> &#127855;</h1>";
        echo "<span id=live class=live><span class=dot></span> live</span></div>";
        echo "<p class=lead>This host is a honeypot. Each row is a scanner probing for a vulnerability &mdash; served a plausible fake, its time wasted. Updates live.</p>";
        echo "<div class=stats>";
        echo "<div class=stat><b id=total>&mdash;</b><span>requests</span></div>";
        echo "<div class=stat><b id=detections>&mdash;</b><span>scans detected</span></div>";
        echo "<div class=stat><b id=served>&mdash;</b><span>fakes served</span></div>";
        echo "<div class=stat><b id=ips>&mdash;</b><span>unique IPs</span></div>";
        echo "<div class=stat><b id=harvested>&mdash;</b><span>payloads captured</span></div>";
        echo "</div>";
        echo "<div id=map></div>";
        echo "<div class=grid>";
        echo "<div class=card><h3>top talkers</h3><ul class=wl id=w_talkers></ul></div>";
        echo "<div class=card><h3>source countries</h3><div id=w_countries></div></div>";
        echo "<div class=card><h3>templates fired</h3><ul class=wl id=w_templates></ul></div>";
        echo "<div class=card><h3>activity (hourly)</h3><div class=hist id=w_hist></div></div>";
        echo "</div>";
        echo "<div class=controls id=views>";
        echo '<button class=\'btn qv on\' data-f=\'{}\'>all</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"SSH","event":"command"}\'>SSH commands</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"TELNET","event":"command"}\'>telnet commands</button>';
        echo '<button class=\'btn qv\' data-f=\'{"event":"login"}\'>credential attempts</button>';
        echo '<button class=\'btn qv\' data-f=\'{"event":"trap"}\'>spider trap</button>';
        echo '<button class=\'btn qv\' data-f=\'{"event":"panel"}\'>admin panel</button>';
        echo '<button class=\'btn qv\' data-f=\'{"event":"shell"}\'>web console</button>';
        echo '<button class=\'btn qv\' data-f=\'{"event":"ai-api"}\'>AI API</button>';
        echo '<button class=\'btn qv\' data-f=\'{"event":"llm-fake"}\'>LLM pages</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"VNC"}\'>VNC</button>';
        echo '<button class=\'btn qscan\' id=qscan title=\'show only classified reconnaissance tools (scanners / wardialers) — lured in and captured\'>&#128269; scanners</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"SIP"}\'>SIP logs</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"SIP","recording":"1"}\'>SIP recordings</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"RDP"}\'>RDP</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"SMB"}\'>SMB</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"MSSQL"}\'>MSSQL</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"MQTT"}\'>MQTT</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"SNMP"}\'>SNMP</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"LDAP"}\'>LDAP</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"S7COMM"}\'>S7comm</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"ADB"}\'>ADB</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"BACNET"}\'>BACnet</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"RTSP"}\'>RTSP</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"STUN"}\'>STUN</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"DNP3"}\'>DNP3</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"IPMI"}\'>IPMI</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"COAP"}\'>CoAP</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"KERBEROS"}\'>Kerberos</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"NTP"}\'>NTP</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"CASSANDRA"}\'>Cassandra</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"WINRM"}\'>WinRM</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"ORACLE"}\'>Oracle</button>';
        echo '<button class=\'btn qv\' data-f=\'{"method":"CWMP"}\'>Router (TR-069)</button>';
        echo '<button class=\'btn qv\' data-f=\'{"event":"clipboard"}\'>clipboard grabs</button>';
        echo '<button class=\'btn qv\' data-f=\'{"known":"1"}\'>known attackers</button>';
        echo '<button class=\'btn qv\' data-f=\'{"served":"1"}\'>fakes served</button>';
        echo '<button class=\'btn qv\' data-f=\'{"severity":"critical"}\'>critical</button>';
        echo "</div>";
        echo "<div class=controls style='margin-bottom:8px'><input id=filter class=filter placeholder='filter by ip, tool, query&hellip;'>";
        echo "<span class=note style='margin:0 0 0 auto'>stats: all-time (DB) or recent window (file mode)</span></div>";
        echo "<table><thead><tr><th>time</th><th>ip</th><th>request</th><th>verdict</th><th>fake?</th></tr></thead>";
        echo "<tbody id=rows><tr><td colspan=5 class=empty>connecting&hellip;</td></tr></tbody></table>";
        echo "<div class=controls><button id=older class=btn>load older</button>";
        echo "<span class=admin><button id=analytics class=btn title='operator analytics — protocol breakdown, events over time, top-N (auth-gated)'>analytics</button><button id=emul class=btn title='choose which vulnerabilities + services funnypot emulates'>emulations</button><button id=llmcache class=btn title='browse + delete LLM-generated fake responses'>llm cache</button><button id=blocked class=btn title='view + manage manually blocked IPs'>blocked</button><button id=prune class=btn title='keep newest 1000 events'>prune</button><button id=clear class=btn>clear</button></span></div>";
        echo "<footer>funnypot &mdash; a honeypot that turns scanner probes into wasted time. &middot; map &copy; OpenStreetMap, CARTO</footer>";
        echo "<div id=vmodal class=modal hidden><div class=modal-box>";
        echo "<div class=modal-head><b>Emulations</b><input id=vsearch class=filter placeholder='search&hellip;'><span class=grow></span><button id=vclose class=x title=close>&times;</button></div>";
        echo "<div id=vlist class=vlist></div>";
        echo "<div class=modal-foot><span id=vstat class=note style='margin:0'></span><span class=grow></span><button id=vsave class=btn>Save</button></div>";
        echo "</div></div>";
        echo "<div id=lmodal class=modal hidden><div class=modal-box>";
        echo "<div class=modal-head><b>LLM cache</b><input id=lsearch class=filter placeholder='search path&hellip;'><span class=grow></span><button id=lclose class=x title=close>&times;</button></div>";
        echo "<div id=llist class=vlist></div>";
        echo "<div class=modal-foot><span id=lstat class=note style='margin:0'></span><span class=grow></span><button id=lclear class=btn>Clear all</button></div>";
        echo "</div></div>";
        echo "<div id=bmodal class=modal hidden><div class=modal-box>";
        echo "<div class=modal-head><b>Blocked IPs</b><span class=note style='margin:0'>manually blocked, enforced across every service</span><span class=grow></span><button id=bclose class=x title=close>&times;</button></div>";
        echo "<div id=blist class=vlist></div>";
        echo "<div class=modal-foot><input id=bip class=filter placeholder='ip or a.b.c.d/24&hellip;'><button id=badd class=btn>Block</button></div>";
        echo "</div></div>";
        // Operator analytics panel (FP-0243b). Opened behind the admin token via analytics.js; renders
        // rollup-backed breakdowns, the uPlot events-over-time series, top-N tables and at-a-glance
        // tiles. Bars/rows drill the raw feed; the series can be brushed to a ts range.
        echo "<div id=amodal class='modal amodal' hidden><div class=modal-box>";
        echo "<div class=modal-head><b>Analytics</b><span class=note style='margin:0'>operator-only &middot; auth-gated</span><span class=grow></span>";
        echo "<select id=awin class=filter title='time window'><option value=3600>1h</option><option value=21600>6h</option><option value=86400 selected>24h</option><option value=604800>7d</option><option value=2592000>30d</option></select>";
        echo "<select id=agran class=filter title='granularity'><option value=m>minute</option><option value=h selected>hour</option><option value=d>day</option></select>";
        echo "<button id=arefresh class=btn>refresh</button><button id=aclose class=x title=close>&times;</button></div>";
        echo "<div class=abody>";
        echo "<div id=atiles class=atiles></div>";
        echo "<div class=asec><h4>events over time (per protocol)</h4><div id=achart class=achart></div><span class=note style='margin:2px 0 0'>drag across the chart to brush a time range &rarr; filters the raw feed below</span></div>";
        echo "<div class=agrid>";
        echo "<div class=acard><h4>protocol</h4><div id=a_protocol class=abars></div></div>";
        echo "<div class=acard><h4>status</h4><div id=a_status class=abars></div></div>";
        echo "<div class=acard><h4>severity</h4><div id=a_severity class=abars></div></div>";
        echo "<div class=acard><h4>event</h4><div id=a_event class=abars></div></div>";
        echo "</div>";
        echo "<div class=agrid>";
        echo "<div class=acard><h4>top source IPs</h4><div id=t_ip class=atop></div></div>";
        echo "<div class=acard><h4>top ASNs</h4><div id=t_asn class=atop></div></div>";
        echo "<div class=acard><h4>top countries</h4><div id=t_cc class=atop></div></div>";
        echo "<div class=acard><h4>top tools</h4><div id=t_tool class=atop></div></div>";
        echo "<div class=acard><h4>top paths</h4><div id=t_path class=atop></div></div>";
        echo "</div></div></div></div>";
        echo "<script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js' crossorigin></script>";
        echo '<script>window.FP_BASE=' . json_encode($base, JSON_UNESCAPED_SLASHES) . ';</script>';
        echo "<script>{$uplotJs}</script>";
        echo "<script>{$js}</script>";
        echo "<script>{$analyticsJs}</script>";
        echo "</div></body></html>";
    }

    public function recording(string $id): void
    {
        $id = preg_replace('/[^a-zA-Z0-9_-]/', '', $id);
        if ($id === '') {
            http_response_code(400);
            echo 'invalid recording id';

            return;
        }

        $recordingsDir = dirname(__DIR__, 3) . '/demo/storage/recordings';
        $ulawGz = $recordingsDir . '/' . $id . '.ulaw.gz';
        $rxGz = $recordingsDir . '/' . $id . '.rx.ulaw.gz';
        $ulaw = $recordingsDir . '/' . $id . '.ulaw';
        $wav = $recordingsDir . '/' . $id . '.wav';

        // Recordings are stored as gzip'd mu-law; decompress + expand to a playable WAV on request.
        // When the caller's channel was captured too, serve stereo (left=caller, right=persona).
        // Plain .ulaw and legacy .wav are also served.
        if (is_file($ulawGz)) {
            $persona = (string) gzdecode((string) file_get_contents($ulawGz));
            if (is_file($rxGz)) {
                $caller = (string) gzdecode((string) file_get_contents($rxGz));
                $body = WavWriter::stereoWavBytes($caller, $persona);
            } else {
                $body = WavWriter::wavBytes($persona);
            }
        } elseif (is_file($ulaw)) {
            $body = WavWriter::wavBytes((string) file_get_contents($ulaw));
        } elseif (is_file($wav)) {
            $body = (string) file_get_contents($wav);
        } else {
            http_response_code(404);
            echo 'recording not found';

            return;
        }

        $this->serveAudioRange($body);
    }

    /**
     * Serves audio bytes with HTTP Range support. HTML5 <audio> issues a Range request and needs a
     * 206 with Content-Range to seek and play a long file to the end; a plain 200 makes some
     * browsers stop after the first buffered second.
     */
    private function serveAudioRange(string $body): void
    {
        $len = strlen($body);
        header('Content-Type: audio/wav');
        header('Accept-Ranges: bytes');
        header('Cache-Control: private, max-age=3600');

        $range = $_SERVER['HTTP_RANGE'] ?? '';
        if ($range !== '' && preg_match('/bytes=(\d*)-(\d*)/', $range, $m)) {
            $start = $m[1] === '' ? 0 : (int) $m[1];
            $end = $m[2] === '' ? $len - 1 : (int) $m[2];
            $end = min($end, $len - 1);

            if ($start > $end || $start >= $len) {
                http_response_code(416);
                header('Content-Range: bytes */' . $len);

                return;
            }

            http_response_code(206);
            header('Content-Range: bytes ' . $start . '-' . $end . '/' . $len);
            header('Content-Length: ' . (string) ($end - $start + 1));
            echo substr($body, $start, $end - $start + 1);

            return;
        }

        header('Content-Length: ' . (string) $len);
        echo $body;
    }
}

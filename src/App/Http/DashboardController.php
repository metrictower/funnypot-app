<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\Policy\EmulationCatalog;
use Funnypot\Policy\EmulationPolicy;
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
        foreach (['method', 'event', 'ip', 'cc', 'severity', 'q'] as $k) {
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
     * Password-gated admin actions. The VIEW stays public; only mutating actions (retention prune,
     * clear, DB backfill, catalog edits) need FUNNYPOT_ADMIN_PASSWORD. Disabled if that env is unset.
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

        echo "<!doctype html><html lang=en><head><meta charset=utf-8>";
        echo "<meta name=viewport content='width=device-width,initial-scale=1'>";
        echo "<link rel=stylesheet href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css' crossorigin>";
        echo "<title>funnypot</title><style>{$css}</style></head><body><div class=wrap>";
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
        echo '<button class=\'btn qv\' data-f=\'{"known":"1"}\'>known attackers</button>';
        echo '<button class=\'btn qv\' data-f=\'{"served":"1"}\'>fakes served</button>';
        echo '<button class=\'btn qv\' data-f=\'{"severity":"critical"}\'>critical</button>';
        echo "</div>";
        echo "<div class=controls style='margin-bottom:8px'><input id=filter class=filter placeholder='filter by ip&hellip;'>";
        echo "<span class=note style='margin:0 0 0 auto'>stats: all-time (DB) or recent window (file mode)</span></div>";
        echo "<table><thead><tr><th>time</th><th>ip</th><th>request</th><th>verdict</th><th>fake?</th></tr></thead>";
        echo "<tbody id=rows><tr><td colspan=5 class=empty>connecting&hellip;</td></tr></tbody></table>";
        echo "<div class=controls><button id=older class=btn>load older</button>";
        echo "<span class=admin><button id=emul class=btn title='choose which vulnerabilities + services funnypot emulates'>emulations</button><button id=llmcache class=btn title='browse + delete LLM-generated fake responses'>llm cache</button><button id=prune class=btn title='keep newest 1000 events'>prune</button><button id=clear class=btn>clear</button></span></div>";
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
        echo "<script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js' crossorigin></script>";
        echo '<script>window.FP_BASE=' . json_encode($base, JSON_UNESCAPED_SLASHES) . ';</script>';
        echo "<script>{$js}</script>";
        echo "</div></body></html>";
    }
}

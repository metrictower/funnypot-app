<?php

declare(strict_types=1);

/**
 * funnypot — page-slots eval harness (live GBNF, latency, degraded-fallback-as-eval).
 *
 * Exercises the REAL production slot pipeline end to end against a live funnypot-llm sidecar:
 * LlmPromptBuilder::forHtmlSlots() -> LlmClient::generate() (page-slots.gbnf-constrained) ->
 * LlmOutputSanitizer::sanitizeToArray() -> PageShellRenderer::render() -> pageBodyOk(). This is the
 * exact sequence LlmFakeResponder::attempt() runs in prod (src/App/Llm/LlmFakeResponder.php), so a
 * PASS here means the grammar/sanitizer/renderer combination would actually be served.
 *
 * Three things this measures, per the plan doc's Task 20 ("Testing & evaluation"):
 *   1. LIVE-GBNF   — does every path's generation parse as valid slot-JSON and survive the whole
 *                    pipeline (grammar output can be syntactically well-formed yet still get rejected
 *                    downstream by sanitizeToArray/pageBodyOk).
 *   2. LATENCY     — min/median/p95/max generation time, checked against the configured timeout and
 *                    against prod's FUNNYPOT_LLM_TIMEOUT_MS=13000.
 *   3. FALLBACK    — the same paths rendered with NO model output (empty PageSlots, i.e. what a
 *                    request gets today if the sidecar is down/slow/gated), written next to the full
 *                    render so a human can judge whether the sidecar earns its keep for this tier.
 *
 * Usage:
 *   php scripts/llm-eval/page-slots-eval.php [sidecar-url]
 *
 * Sidecar URL resolution: argv[1], else FUNNYPOT_LLM_URL, else the same default AppConfig uses
 * (http://funnypot-llm:8080/completion). Every other knob mirrors AppConfig's env vars so this harness
 * reads prod-identical config when pointed at a real box:
 *   FUNNYPOT_LLM_TIMEOUT_MS   (default 9000, prod default 13000)
 *   FUNNYPOT_LLM_N_PREDICT    (default 320)
 *   FUNNYPOT_POWERED_BY       (default "PHP/8.1.27")
 *   FUNNYPOT_PERSONA_SEED     (default "funnypot")
 *
 * No sidecar reachable (the common case for this environment): prints a clear skip notice, still
 * exercises + prints the no-LLM fallback render for every path (needs no network), and exits 0. This
 * script must NEVER fatal — every network/parse/render step is defensively guarded, mirroring the
 * "LLM tier only ever upgrades a 404" invariant the pipeline itself enforces.
 */

require __DIR__ . '/../../vendor/autoload.php';

use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmPromptBuilder;
use Funnypot\Support\Chrome\GenericSkin;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\Support\Chrome\PageSlots;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Support\Chrome\WordpressSkin;
use Funnypot\App\Render\SkinSet;
use Funnypot\Support\VisualPersona;
use Funnypot\RequestContext;
use Funnypot\Support\PersonaIdentity;

const PROD_TIMEOUT_MS = 13000;

/** Ten representative paths spanning generic dashboard-style chrome and every resemblance skin
 *  (WordPress, phpMyAdmin, Grafana, AdminLTE), matching what SkinSet::select() would route in prod. */
const TEST_PATHS = [
    '/hr/portal',
    '/wp-login.php',
    '/phpmyadmin/',
    '/grafana/d/abc',
    '/admin/users',
    '/secretadmin',
    '/api-portal/console',
    '/manage/settings',
    '/dashboard',
    '/internal/tools',
];

function main(): int
{
    $url = $GLOBALS['argv'][1] ?? (getenv('FUNNYPOT_LLM_URL') ?: 'http://funnypot-llm:8080/completion');
    $timeoutMs = max(200, (int) (getenv('FUNNYPOT_LLM_TIMEOUT_MS') ?: '9000'));
    $nPredict = max(64, (int) (getenv('FUNNYPOT_LLM_N_PREDICT') ?: '320'));
    $serverStack = (string) (getenv('FUNNYPOT_POWERED_BY') ?: 'PHP/8.1.27');
    $personaSeed = (int) crc32((string) (getenv('FUNNYPOT_PERSONA_SEED') ?: 'funnypot'));

    $outDir = rtrim(sys_get_temp_dir(), '/') . '/funnypot-page-slots-eval-' . date('Ymd-His');
    @mkdir($outDir, 0777, true);

    echo "funnypot page-slots eval\n";
    echo str_repeat('=', 60) . "\n";
    echo "sidecar url   : {$url}\n";
    echo "timeout ms    : {$timeoutMs} (prod default " . PROD_TIMEOUT_MS . ")\n";
    echo "persona seed  : {$personaSeed}\n";
    echo "output dir    : {$outDir}\n\n";

    // Same wiring demo/index.php uses when FUNNYPOT_LLM is on: priority-ordered resemblance skins,
    // GenericSkin as the default. One persona for the whole run — VisualPersona is a per-HOST identity
    // (stable across all its pages), not per-path, so this mirrors what one fake host actually renders.
    $skins = new SkinSet(
        [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()],
        new GenericSkin()
    );
    $renderer = new PageShellRenderer($skins);
    $sanitizer = new LlmOutputSanitizer();
    $persona = VisualPersona::fromSeed($personaSeed);
    $company = PersonaIdentity::fromSeed($personaSeed)->field('company.name') ?? 'Internal';
    $promptBuilder = LlmPromptBuilder::forHtmlSlots($serverStack, $company);
    $grammarPath = __DIR__ . '/../../resources/llm/page-slots.gbnf';
    $grammar = (string) @file_get_contents($grammarPath);
    if ($grammar === '') {
        echo "WARNING: could not read {$grammarPath} — live generation would run ungrammared.\n\n";
    }

    $client = new LlmClient($url, $timeoutMs, $nPredict);
    $reachable = false;
    try {
        $reachable = $client->healthy();
    } catch (Throwable $e) {
        $reachable = false;
    }

    if (!$reachable) {
        echo "sidecar unreachable at {$url} — live results skipped; run this in an environment with "
            . "the funnypot-llm sidecar.\n\n";
    }

    /** @var list<array{path:string,pass:bool,reason:string,latencyMs:float,rawBytes:int,fallbackBytes:int,fullBytes:int}> */
    $rows = [];

    foreach (TEST_PATHS as $i => $path) {
        $row = ['path' => $path, 'pass' => false, 'reason' => '', 'latencyMs' => 0.0, 'rawBytes' => 0, 'fallbackBytes' => 0, 'fullBytes' => 0];
        $slug = trim(preg_replace('/[^a-z0-9]+/i', '-', $path) ?? '', '-') ?: 'root';
        $slug = sprintf('%02d-%s', $i + 1, $slug);

        try {
            $ctx = new RequestContext('GET', $path);

            // Fallback render never touches the network: this is what the request gets today if the
            // sidecar is down, slow, or the gate declines. Always produced, sidecar or not.
            $fallbackHtml = $renderer->render(PageSlots::fromArray([]), $persona, $ctx);
            $row['fallbackBytes'] = strlen($fallbackHtml);
            @file_put_contents("{$outDir}/{$slug}.fallback.html", $fallbackHtml);

            if (!$reachable) {
                $row['reason'] = 'sidecar unreachable';
                $rows[] = $row;
                continue;
            }

            $prompt = $promptBuilder->build('GET', $path);
            $t0 = microtime(true);
            $raw = null;
            try {
                $raw = $client->generate($prompt, $grammar);
            } catch (Throwable $e) {
                $raw = null;
            }
            $row['latencyMs'] = (microtime(true) - $t0) * 1000.0;

            if ($raw === null) {
                $row['reason'] = 'generation failed (network/timeout/empty response)';
                $rows[] = $row;
                continue;
            }
            $row['rawBytes'] = strlen($raw);

            $decoded = $sanitizer->sanitizeToArray($raw);
            if ($decoded === null) {
                $row['reason'] = 'sanitizeToArray rejected — GBNF produced unparseable/invalid slots';
                $rows[] = $row;
                continue;
            }

            $fullHtml = $renderer->render(PageSlots::fromArray($decoded), $persona, $ctx);
            if (!$sanitizer->pageBodyOk($fullHtml)) {
                $row['reason'] = 'pageBodyOk rejected the assembled page';
                $rows[] = $row;
                continue;
            }

            $row['fullBytes'] = strlen($fullHtml);
            @file_put_contents("{$outDir}/{$slug}.full.html", $fullHtml);
            $row['pass'] = true;
            $row['reason'] = 'ok';
        } catch (Throwable $e) {
            // Belt-and-braces: this harness must never fatal, no matter what a live sidecar returns.
            $row['reason'] = 'harness error: ' . $e->getMessage();
        }
        $rows[] = $row;
    }

    printGbnfSection($rows, $reachable);
    printLatencySection($rows, $reachable, $timeoutMs);
    printFallbackSection($rows, $outDir);

    return 0;
}

/** @param list<array{path:string,pass:bool,reason:string}> $rows */
function printGbnfSection(array $rows, bool $reachable): void
{
    echo "1. LIVE-GBNF\n";
    echo str_repeat('-', 60) . "\n";
    if (!$reachable) {
        echo "(skipped — sidecar unreachable)\n\n";
        return;
    }
    $passCount = 0;
    foreach ($rows as $r) {
        $status = $r['pass'] ? 'PASS' : 'FAIL';
        if ($r['pass']) {
            $passCount++;
        }
        echo pad($r['path'], 26) . ' ' . pad($status, 5) . ' ' . $r['reason'] . "\n";
    }
    echo "\n{$passCount}/" . count($rows) . " paths produced a servable page.\n\n";
}

/** @param list<array{pass:bool,latencyMs:float}> $rows */
function printLatencySection(array $rows, bool $reachable, int $timeoutMs): void
{
    echo "2. LATENCY\n";
    echo str_repeat('-', 60) . "\n";
    if (!$reachable) {
        echo "(skipped — sidecar unreachable)\n\n";
        return;
    }
    $times = [];
    foreach ($rows as $r) {
        if ($r['latencyMs'] > 0.0) {
            $times[] = $r['latencyMs'];
        }
    }
    if ($times === []) {
        echo "no timed generations (all failed before a response was received)\n\n";
        return;
    }
    sort($times);
    $min = $times[0];
    $max = $times[count($times) - 1];
    $median = percentile($times, 50);
    $p95 = percentile($times, 95);

    echo sprintf("min=%.0fms  median=%.0fms  p95=%.0fms  max=%.0fms\n", $min, $median, $p95, $max);
    echo sprintf(
        "p95 vs configured timeout (%dms): %s\n",
        $timeoutMs,
        $p95 < $timeoutMs ? 'OK (within budget)' : 'OVER BUDGET — tighten nav_items/rows caps'
    );
    echo sprintf(
        "p95 vs prod timeout (%dms): %s\n\n",
        PROD_TIMEOUT_MS,
        $p95 < PROD_TIMEOUT_MS ? 'OK (within budget)' : 'OVER BUDGET — tighten nav_items/rows caps'
    );
}

/** @param list<array{path:string,pass:bool,fallbackBytes:int,fullBytes:int}> $rows */
function printFallbackSection(array $rows, string $outDir): void
{
    echo "3. DEGRADED-FALLBACK-AS-EVAL\n";
    echo str_repeat('-', 60) . "\n";
    echo "No-LLM fallback (PageShellRenderer + empty PageSlots — what the path gets today with no\n";
    echo "sidecar) vs the full slot-JSON render, written to disk for side-by-side human review:\n\n";
    foreach ($rows as $i => $r) {
        $slug = trim(preg_replace('/[^a-z0-9]+/i', '-', $r['path']) ?? '', '-') ?: 'root';
        $slug = sprintf('%02d-%s', $i + 1, $slug);
        $fallbackFile = "{$outDir}/{$slug}.fallback.html";
        $line = pad($r['path'], 26) . " fallback: " . pad((string) $r['fallbackBytes'] . 'B', 7)
            . ' -> ' . $fallbackFile;
        if ($r['pass']) {
            $fullFile = "{$outDir}/{$slug}.full.html";
            $line .= "\n" . pad('', 26) . "    full: " . pad((string) $r['fullBytes'] . 'B', 7)
                . ' -> ' . $fullFile;
        }
        echo $line . "\n";
    }
    echo "\nOpen the .fallback.html / .full.html pairs side by side (browser or diff tool) and judge\n";
    echo "whether the sidecar's content meaningfully beats the authored empty-state for this tier.\n";
}

/** @param list<float> $sorted ascending */
function percentile(array $sorted, float $p): float
{
    $n = count($sorted);
    if ($n === 0) {
        return 0.0;
    }
    $idx = (int) ceil($p / 100.0 * $n) - 1;
    $idx = max(0, min($n - 1, $idx));

    return $sorted[$idx];
}

function pad(string $s, int $w): string
{
    $len = mb_strlen($s);

    return $len >= $w ? $s : $s . str_repeat(' ', $w - $len);
}

try {
    exit(main());
} catch (Throwable $e) {
    // Last-resort guard: this harness must never fatal, even on a totally unexpected error.
    fwrite(STDERR, 'page-slots-eval: unexpected error: ' . $e->getMessage() . "\n");
    exit(0);
}

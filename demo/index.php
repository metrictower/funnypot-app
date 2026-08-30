<?php

/**
 * funnypot — standalone honeypot front controller.
 *
 * Bootstraps the app services and hands the request to the router. Every request is logged and,
 * unless it is the operator dashboard, run through the funnypot-core engine: detect the scanner
 * probe, serve a fake if matched, and record it. Routing, views and honeypot logic live in
 * Funnypot\App\Http\*; storage in Funnypot\App\Storage\*; config in Funnypot\App\Config\AppConfig.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/lib/geo.php';

use Funnypot\Core\Ai\ModelCatalog;
use Funnypot\App\AiApi\AiApiRouter;
use Funnypot\App\AiApi\AiChatHandler;
use Funnypot\App\AiApi\AiChatPromptBuilder;
use Funnypot\App\AiApi\NonsenseFallback;
use Funnypot\App\AiApi\WordSwap;
use Funnypot\App\AiApi\WrongLanguageCode;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Docker\DockerApiResponder;
use Funnypot\App\Docker\DockerApiRouter;
use Funnypot\App\Http\ConsoleRouter;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\DownloadRouter;
use Funnypot\App\Shell\ConsoleSessionStore;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\Router;
use Funnypot\App\Llm\CircuitBreaker;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Render\ArtifactVersion;
use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\App\Render\SkinSet;
use Funnypot\App\Storage\FakePersistenceStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\RawCapture;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\App\ThreatIntel\OperatorBlocklist;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Chrome\GenericSkin;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\Chrome\WordpressSkin;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;

// Fault containment. An internet-facing honeypot must NEVER render a PHP error — a leaked trace, path,
// or class name is an information leak and a decisive tell. display_errors is Off in the prod ini; here
// we also turn any uncaught exception or fatal into a bare 404 (logged, not shown), so a bug degrades
// like a missing page instead of exposing internals. Generalises the engine's "only ever upgrade a
// 404, never escape as a 500" invariant to the whole front controller.
@ini_set('display_errors', '0');
$funnypotFault = static function (string $where, string $msg, string $file, int $line): void {
    error_log("funnypot {$where}: {$msg} @ {$file}:{$line}");
    if (!headers_sent()) {
        http_response_code(404);
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!doctype html><title>404 Not Found</title>404 Not Found';
    }
};
set_exception_handler(static function (\Throwable $e) use ($funnypotFault): void {
    $funnypotFault('uncaught', $e->getMessage(), $e->getFile(), $e->getLine());
});
register_shutdown_function(static function () use ($funnypotFault): void {
    $e = error_get_last();
    if ($e !== null && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        $funnypotFault('fatal', $e['message'], $e['file'], (int) $e['line']);
    }
});

$config = AppConfig::fromEnv(__DIR__);
@mkdir(dirname($config->logPath), 0777, true);

$store = new SqliteHitStore($config->dbPath, $config->logPath);
$geo = new Geo($config->geoDbPath);

$context = RequestContext::fromGlobals();
$clientIp = HoneypotController::clientIp($config->trustedProxies);

// Full-request capture (opt-in, FUNNYPOT_CAPTURE_RAW) — record EVERY request's complete headers + query +
// body to a separate raw-capture.sqlite, for analysing a vuln scan. At the front controller so nothing is
// missed regardless of which handler serves it; fail-open so it never affects the response.
if ($config->captureRaw) {
    (new RawCapture(dirname($config->dbPath) . '/raw-capture.sqlite'))->capture($context, $clientIp);
}

// Coherent chrome: one consistent X-Powered-By on every response (nginx owns Server), so header
// recon can't catch a version mismatch between the fake bodies and the server banner. Skipped on the
// fake AI-API surface (core serves it as a real inference server would, keyless GET recon included)
// and on the Docker surface only when that decoy is armed — a real Docker daemon sends no
// X-Powered-By (both handlers also strip it defensively).
$dockerSurface = $config->dockerApiEnabled && DockerApiRouter::isDockerSurface($context->path);
if (!AiApiRouter::isAiSurface($context->path) && !$dockerSurface) {
    header('X-Powered-By: ' . $config->poweredBy);
}

// Anti-fingerprint tripwire: plant a signed bait cookie and classify what comes back — a client
// that returns it tampered is a high-signal probe. Off unless FUNNYPOT_HONEYTOKEN_KEY is set.
$tokenVerdict = 'off';
if ($config->honeytokenKey !== '') {
    $token = new Honeytoken($config->honeytokenKey);
    $tokenVerdict = $token->inspect($_COOKIE['sess'] ?? null);
    header('Set-Cookie: ' . $token->cookie('sess', 'r=user'), false);
}

// Threat-intel blocklist: flag hits from known attackers at write time (opt-in, FUNNYPOT_BLOCKLIST).
$blocklist = $config->blocklistEnabled ? new Blocklist($config->intelDbPath, $config->blocklistMinLists) : null;
// Operator manual blocklist — always active (independent of the public-feed Blocklist toggle); the
// dashboard writes it and every tier enforces it. Same intel.sqlite (persisted volume), own table.
$operatorBlock = new OperatorBlocklist($config->intelDbPath);

// AbuseIPDB reporting: opt-in, and only armed when an API key is set. The service self-excludes our
// own IP (and is inert without FUNNYPOT_SELF_IPS) so our own tests can never report us.
$abuse = ($config->abuseIpdbReport && $config->abuseIpdbKey !== '')
    ? new AbuseIpdb($config->abuseIpdbKey, $config->intelDbPath, $config->selfIps, $config->abuseIpdbDailyCap, $config->abuseIpdbDedupHours)
    : null;

// Threat Intel reporting to our own funnypot-mainnet service: opt-in, armed only with a key. Shares
// the self-exclude guard and intel store with AbuseIPDB but throttles independently (its own tables).
$threatIntel = ($config->threatIntelReport && $config->threatIntelKey !== '')
    ? new ThreatIntelReporter($config->threatIntelUrl, $config->threatIntelKey, $config->intelDbPath, $config->selfIps, $config->threatIntelDailyCap, $config->threatIntelDedupHours)
    : null;

// LLM-generated fake responses for plausible unknown paths (opt-in, needs the funnypot-llm sidecar).
// Every failure/decline falls through to the plain 404, so this only ever upgrades a 404.
// One cache instance shared by the responder (read/write) and the dashboard (browse/delete). Lazy:
// it only opens the SQLite file on first query, so it costs nothing when the feature is off.
$llmCache = new LlmFakeCache($config->llmCacheDb);
$llmFakes = null;
if ($config->llmEnabled) {
    $breaker = new CircuitBreaker($config->llmCacheDb, $config->llmBreakerThreshold, $config->llmBreakerCooldownS);
    // Priority order: WordPress, phpMyAdmin, Grafana, then AdminLTE last — its broad /admin match
    // would otherwise shadow the more specific product analogs above it.
    $skins = new SkinSet(
        [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()],
        new GenericSkin()
    );
    $renderer = new PageShellRenderer($skins);
    $company = PersonaIdentity::fromSeed($config->personaSeed)->field('company.name') ?? 'Internal';
    // Same persona seed as the html tier's $company, so a /.env or /config.json reflects the same
    // coherent identity as the html pages (cross-kind coherence, not just per-kind determinism).
    $visualPersona = VisualPersona::fromSeed($config->personaSeed);
    $pageSlotsGrammar = (string) @file_get_contents(dirname(__DIR__) . '/resources/llm/page-slots.gbnf');
    // Fold the deploy epoch into the cache key: FrozenClock::epoch() advances only across redeploys
    // (FUNNYPOT_EPOCH is stamped once at container start), so a new deploy busts every cached panel
    // page baked with the old "now" instead of serving dates that contradict the fresh HTTP Date header.
    $artifactVersion = ArtifactVersion::current(dirname(__DIR__) . '/resources/llm', dirname(__DIR__) . '/src/App/Render', $config->llmPromptVersion)
        . '-e' . FrozenClock::epoch();
    // Fake persistence for the deep panel: a note/message/edit POSTed to a write endpoint is echoed
    // back (escaped) on a later read of the same view, per ip + persona seed, so a stored-vuln probe
    // looks like it landed. Its own SQLite file, bounded + TTL'd, lazy-opened, fail-open.
    $fakePersistence = new FakePersistenceStore(dirname($config->dbPath) . '/stored-bait.sqlite');
    $llmFakes = new LlmFakeResponder(
        new ProbeGate(
            new ProbeClassifier(),
            new VelocityTracker($config->llmVelocityPer60s, $config->llmVelocityPer10m),
            $store,
            allowIps: $config->llmGateAllowIps,
        ),
        $llmCache,
        new LlmClient($config->llmUrl, $config->llmTimeoutMs, $config->llmNPredict, $breaker),
        new LlmOutputSanitizer(),
        $store,
        new LlmResponseProfiles(
            $config->poweredBy,
            (string) @file_get_contents(dirname(__DIR__) . '/resources/llm/html.gbnf'),
            (string) @file_get_contents(dirname(__DIR__) . '/resources/llm/json.gbnf'),
            $renderer,
            $pageSlotsGrammar,
            $company,
            $visualPersona,
        ),
        $config->llmPromptVersion,
        $config->llmMaxConcurrent,
        $config->personaSeed,
        $artifactVersion,
        $fakePersistence,
    );
}

// Fake AI inference API — the chat-completion endpoints (opt-in, needs the sidecar). Independent of
// the 404-upgrade LLM feature so it can run alone: it builds its own client/breaker/gate but shares
// the hit store, the inflight cache (one global concurrency cap) and the AbuseIPDB reporter. Every
// fault degrades to a deterministic troll fallback at 200, so it only ever answers. The router owns
// the dialects, so nothing more to construct here.
$aiApi = null;
if ($config->aiApiEnabled) {
    $aiBreaker = new CircuitBreaker($config->llmCacheDb, $config->llmBreakerThreshold, $config->llmBreakerCooldownS);
    $aiApi = new AiApiRouter(new AiChatHandler(
        new LlmClient($config->llmUrl, $config->llmTimeoutMs, $config->llmNPredict, $aiBreaker),
        new AiChatPromptBuilder(),
        new LlmOutputSanitizer(),
        new NonsenseFallback(),
        new WordSwap(),
        new WrongLanguageCode(),
        new ProbeGate(
            new ProbeClassifier(),
            new VelocityTracker($config->llmVelocityPer60s, $config->llmVelocityPer10m),
            $store,
            allowIps: $config->llmGateAllowIps,
        ),
        $llmCache,
        $store,
        ModelCatalog::fromPackage(),
        $abuse,
        $config->aiStrictAuth,
        $config->aiStrictModel,
        $config->aiTemp,
        $config->aiMinP,
        $config->aiTopP,
        $config->llmMaxConcurrent,
        $config->aiRealFirst,
        $config->aiRealWindowS,
    ));
}

$honeypot = new HoneypotController($store, $geo, $config, __DIR__ . '/decoys', $blocklist, $abuse, $threatIntel, $llmFakes, new AttackClassifier(), $operatorBlock);
$dashboard = new DashboardController($store, $geo, $config, __DIR__ . '/assets', $llmCache, $operatorBlock);
$corporate = new CorporateController($store, $geo, $config, __DIR__ . '/assets', $blocklist);
// The generic decoy home at / (public mode); the funnypot dashboard moves to $config->funnypotPath.
$home = new HomeController($store, $geo, $config, __DIR__ . '/assets', $blocklist);
// Streaming web terminal for the fleet console — its own POST route, gate-exempt (ahead of the catch-all).
// Same persona seed + persisted FS secret as the SSH/telnet shell, so a host's web console == its shell.
$console = new ConsoleRouter(
    new ConsoleSessionStore(dirname($config->dbPath) . '/console.sqlite'),
    $store,
    $config->personaSeed,
    \Funnypot\Shell\Fs\HostSecret::resolve(__DIR__ . '/storage'),
);

// Endless throttled backup-download bait — on by default; the feature is gated here (null = off) so
// disabling it removes the /__dl/* routes entirely. Throttle knobs come from config and are handed to
// the client service worker via the manifest.
$download = null;
if ($config->endlessDownload) {
    $download = new DownloadRouter(
        $store,
        $config->personaSeed,
        (string) @file_get_contents(dirname(__DIR__) . '/src/App/Download/sw.js'),
        $config->dlChunkMinKb,
        $config->dlChunkMaxKb,
        $config->dlIntervalMs,
        $config->dlVaryPct,
        $config->dlEasePeriodS,
        $config->dlFallbackCapMb,
    );
}

// Fake Docker Engine API decoy (opt-in, FUNNYPOT_DOCKER_API). A pure deterministic JSON responder —
// no sidecar, no dependencies — that presents a believable unauthenticated daemon on the published
// 2375/2376 ports and captures a miner bot's POST /containers/create image+command, running nothing.
$docker = null;
if ($config->dockerApiEnabled) {
    $docker = new DockerApiRouter(new DockerApiResponder($store, $config->personaSeed, $abuse));
}

(new Router($config, $honeypot, $dashboard, $corporate, $home, $aiApi, $console, $download, $docker))->dispatch($context, $clientIp, $tokenVerdict);

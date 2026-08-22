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

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
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
use Funnypot\App\Render\GenericSkin;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\App\Render\Skins\PhpMyAdminSkin;
use Funnypot\App\Render\Skins\WordpressSkin;
use Funnypot\App\Render\SkinSet;
use Funnypot\App\Render\VisualPersona;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Honeytoken;
use Funnypot\RequestContext;
use Funnypot\Support\PersonaIdentity;

$config = AppConfig::fromEnv(__DIR__);
@mkdir(dirname($config->logPath), 0777, true);

$store = new SqliteHitStore($config->dbPath, $config->logPath);
$geo = new Geo($config->geoDbPath);

// Coherent chrome: one consistent X-Powered-By on every response (nginx owns Server), so header
// recon can't catch a version mismatch between the fake bodies and the server banner.
header('X-Powered-By: ' . $config->poweredBy);

$context = RequestContext::fromGlobals();
$clientIp = HoneypotController::clientIp($config->trustedProxies);

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
    $artifactVersion = ArtifactVersion::current(dirname(__DIR__) . '/resources/llm', dirname(__DIR__) . '/src/App/Render', $config->llmPromptVersion);
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
    );
}

$honeypot = new HoneypotController($store, $geo, $config, __DIR__ . '/decoys', $blocklist, $abuse, $threatIntel, $llmFakes, new AttackClassifier());
$dashboard = new DashboardController($store, $geo, $config, __DIR__ . '/assets', $llmCache);
$corporate = new CorporateController($store, $geo, $config, __DIR__ . '/assets', $blocklist);
(new Router($config, $honeypot, $dashboard, $corporate))->dispatch($context, $clientIp, $tokenVerdict);

<?php

declare(strict_types=1);

namespace Funnypot\App\Config;

use Funnypot\Support\PersonaIdentity;

/**
 * One source of truth for the app's runtime configuration. Every FUNNYPOT_* environment variable
 * the app reads is resolved here once, instead of scattered getenv() calls re-deriving the same
 * defaults in the front controller, the listeners and the retention runner.
 *
 * Paths default under <baseDir>/storage. The deploy-only vars (host/user/key/cert domains) are not
 * app config and stay out of this object.
 */
final class AppConfig
{
    public function __construct(
        /** public = today's honeypot-forward behaviour; stealth = fake corporate front, honeypot hidden. */
        public string $mode,
        public string $style,
        public string $dbPath,
        public string $logPath,
        public string $geoDbPath,
        public string $vulnsPath,
        public string $poweredBy,
        public string $honeytokenKey,
        public string $severityCeiling,
        public int $latencyMs,
        public int $jitterMs,
        public bool $attackEmulation,
        public bool $decoyArchive,
        public string $adminPassword,
        public bool $protocolsEnabled,
        public int $retainDays,
        public float $retainGb,
        /** Operator dashboard path in stealth mode (public mode serves it at /). */
        public string $dashboardPath,
        public bool $blocklistEnabled,
        public string $intelDbPath,
        public int $blocklistMinLists,
        public string $abuseIpdbKey,
        public bool $abuseIpdbReport,
        /** Our own public IP(s); AbuseIPDB reporting refuses to report these (and is off if empty). */
        public array $selfIps,
        /** IPs/CIDRs of proxies in front of us; only these may set X-Forwarded-For. Empty = edge. */
        public array $trustedProxies,
        public int $abuseIpdbDailyCap,
        /** Report each attacker IP at most once per this many hours (AbuseIPDB dislikes duplicates). */
        public int $abuseIpdbDedupHours,
        // Threat Intel reporting to our own funnypot-mainnet service (POST /v1/report). Independent of
        // AbuseIPDB; both may run at once. Key presence + the report flag arm it (off/unset ⇒ no-op).
        public bool $threatIntelReport,
        /** Scheme + host only (no path); the reporter appends /v1/report. */
        public string $threatIntelUrl,
        /** Sensor-tier key sent in the `Key:` header; empty ⇒ reporting is inert. */
        public string $threatIntelKey,
        public int $threatIntelDailyCap,
        public int $threatIntelDedupHours,
        // LLM-generated fake responses (opt-in; the funnypot-llm sidecar).
        public bool $llmEnabled,
        public string $llmUrl,
        public int $llmTimeoutMs,
        public int $llmNPredict,
        public string $llmCacheDb,
        public int $llmCacheMaxBytes,
        public int $llmMaxConcurrent,
        public string $llmPromptVersion,
        public int $llmBreakerThreshold,
        public int $llmBreakerCooldownS,
        /** Distinct paths in 60s / 10min that flag an IP as bulk-scanning (Gate A). */
        public int $llmVelocityPer60s,
        public int $llmVelocityPer10m,
        /** IPs/CIDRs exempt from the LLM velocity gate — operator test IPs generate unlimited fakes. */
        public array $llmGateAllowIps,
        /** Seeds persona/skin selection; per-deployment and stable — never clientIp or time. */
        public int $personaSeed,
    ) {
    }

    public static function fromEnv(string $baseDir): self
    {
        $store = rtrim($baseDir, '/') . '/storage';

        // getenv() returns false when unset and '' when set empty; treat both as "use the default".
        $str = static function (string $key, string $default): string {
            $v = getenv($key);

            return ($v === false || $v === '') ? $default : $v;
        };
        // A boolean flag that is on by default and only switched off by an explicit "0".
        $onUnless0 = static fn (string $key): bool => getenv($key) !== '0';

        $db = $str('FUNNYPOT_DB', $store . '/funnypot.sqlite');
        if ($db === 'off') {
            $db = $store . '/funnypot.sqlite'; // SQLite is canonical now; 'off' no longer disables it
        }

        return new self(
            mode: getenv('FUNNYPOT_MODE') === 'stealth' ? 'stealth' : 'public',
            style: $str('FUNNYPOT_STYLE', 'realistic'),
            dbPath: $db,
            logPath: $str('FUNNYPOT_LOG', $store . '/hits.log'),
            geoDbPath: $str('FUNNYPOT_GEO_DB', $store . '/dbip-country.csv.gz'),
            vulnsPath: $str('FUNNYPOT_VULNS', $store . '/funnypot-vulns.json'),
            poweredBy: $str('FUNNYPOT_POWERED_BY', 'PHP/8.1.27'),
            honeytokenKey: $str('FUNNYPOT_HONEYTOKEN_KEY', ''),
            severityCeiling: $str('FUNNYPOT_CEILING', 'critical'),
            latencyMs: (int) ($str('FUNNYPOT_LATENCY_MS', '0')),
            jitterMs: (int) ($str('FUNNYPOT_JITTER_MS', '40')),
            attackEmulation: $onUnless0('FUNNYPOT_ATTACK'),
            decoyArchive: $onUnless0('FUNNYPOT_DECOY_ARCHIVE'),
            adminPassword: $str('FUNNYPOT_ADMIN_PASSWORD', ''),
            protocolsEnabled: $onUnless0('FUNNYPOT_PROTOCOLS'),
            retainDays: (int) ($str('FUNNYPOT_RETAIN_DAYS', '0')),
            retainGb: (float) ($str('FUNNYPOT_RETAIN_GB', '0')),
            dashboardPath: '/' . trim($str('FUNNYPOT_DASHBOARD_PATH', '/__fp/'), '/') . '/',
            blocklistEnabled: in_array(strtolower((string) getenv('FUNNYPOT_BLOCKLIST')), ['1', 'on', 'true', 'yes'], true),
            intelDbPath: $str('FUNNYPOT_INTEL_DB', $store . '/intel.sqlite'),
            blocklistMinLists: max(1, (int) $str('FUNNYPOT_BLOCKLIST_MIN_LISTS', '1')),
            abuseIpdbKey: $str('FUNNYPOT_ABUSEIPDB_KEY', ''),
            abuseIpdbReport: in_array(strtolower((string) getenv('FUNNYPOT_ABUSEIPDB_REPORT')), ['1', 'on', 'true', 'yes'], true),
            selfIps: array_values(array_filter(array_map('trim', explode(',', $str('FUNNYPOT_SELF_IPS', ''))))),
            trustedProxies: array_values(array_filter(array_map('trim', explode(',', $str('FUNNYPOT_TRUSTED_PROXIES', ''))))),
            abuseIpdbDailyCap: max(1, (int) $str('FUNNYPOT_ABUSEIPDB_DAILY_CAP', '1000')),
            abuseIpdbDedupHours: max(1, (int) $str('FUNNYPOT_ABUSEIPDB_DEDUP_HOURS', '24')),
            threatIntelReport: in_array(strtolower((string) getenv('FUNNYPOT_THREATINTEL_REPORT')), ['1', 'on', 'true', 'yes'], true),
            threatIntelUrl: $str('FUNNYPOT_THREATINTEL_URL', 'https://threatintel.metrictower.com'),
            threatIntelKey: $str('FUNNYPOT_THREATINTEL_KEY', ''),
            threatIntelDailyCap: max(1, (int) $str('FUNNYPOT_THREATINTEL_DAILY_CAP', '1000')),
            threatIntelDedupHours: max(1, (int) $str('FUNNYPOT_THREATINTEL_DEDUP_HOURS', '24')),
            llmEnabled: in_array(strtolower((string) getenv('FUNNYPOT_LLM')), ['1', 'on', 'true', 'yes'], true),
            llmUrl: $str('FUNNYPOT_LLM_URL', 'http://funnypot-llm:8080/completion'),
            // A CPU 0.5B GBNF generation runs ~3-8s (slower on a small box); the timeout must clear
            // that or every fake times out into a plain 404. The concurrency cap bounds how many
            // requests can be held generating at once, so a generous timeout is safe.
            llmTimeoutMs: max(200, (int) $str('FUNNYPOT_LLM_TIMEOUT_MS', '9000')),
            llmNPredict: max(64, (int) $str('FUNNYPOT_LLM_N_PREDICT', '320')),
            llmCacheDb: $str('FUNNYPOT_LLM_CACHE_DB', $store . '/llm_cache.sqlite'),
            llmCacheMaxBytes: (int) $str('FUNNYPOT_LLM_CACHE_MAX_BYTES', '0'),
            llmMaxConcurrent: max(1, (int) $str('FUNNYPOT_LLM_MAX_CONCURRENT', '4')),
            llmPromptVersion: $str('FUNNYPOT_LLM_PROMPT_VERSION', 'v2'),
            llmBreakerThreshold: max(1, (int) $str('FUNNYPOT_LLM_BREAKER_THRESHOLD', '5')),
            llmBreakerCooldownS: max(1, (int) $str('FUNNYPOT_LLM_BREAKER_COOLDOWN_S', '30')),
            llmVelocityPer60s: max(1, (int) $str('FUNNYPOT_LLM_VELOCITY_PER_60S', '5')),
            llmVelocityPer10m: max(1, (int) $str('FUNNYPOT_LLM_VELOCITY_PER_10M', '15')),
            llmGateAllowIps: array_values(array_filter(array_map('trim', explode(',', $str('FUNNYPOT_LLM_GATE_ALLOW', ''))))),
            // Seed source must be private: the cert CN (FUNNYPOT_LE_DOMAIN) is public, so deriving
            // from it lets a scanner read the domain and precompute the whole persona identity
            // offline. FUNNYPOT_PERSONA_SECRET is the private per-deployment value; unset falls back
            // to a fixed default (set it for a unique per-host identity). seedFromMaterial is the
            // canonical derivation shared with the core template tier, so both resolve the SAME
            // PersonaIdentity for one deployment.
            personaSeed: PersonaIdentity::seedFromMaterial(
                $str('FUNNYPOT_PERSONA_SEED', $str('FUNNYPOT_PERSONA_SECRET', 'funnypot'))
            ),
        );
    }
}

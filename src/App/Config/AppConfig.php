<?php

declare(strict_types=1);

namespace Funnypot\App\Config;

use Funnypot\Core\Support\PersonaIdentity;

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
        /** What an UNAUTHENTICATED visitor sees on the dashboard path (FP-0242b): full | minimal | none.
         *  Default (and any unknown value) is `none` — the fail-safe, least-exposed value: an
         *  unauthenticated visitor who finds the hidden path sees nothing. An authenticated operator
         *  ALWAYS sees the full view regardless of this knob. */
        public string $dashboardPublicView,
        public bool $blocklistEnabled,
        public string $intelDbPath,
        public int $blocklistMinLists,
        public string $abuseIpdbKey,
        public bool $abuseIpdbReport,
        /** Our own public IP(s); AbuseIPDB reporting refuses to report these (and is off if empty).
         *  Entries may be exact IPs or CIDRs (FP-0247, Fix J) — a honeypot behind shared NAT/CGNAT can
         *  list its whole egress range so an innocent shared-NAT neighbour is never reported. */
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
        /** Fake AI inference API — the chat-completion endpoints (opt-in; also needs the sidecar). */
        public bool $aiApiEnabled,
        /** Fake Docker Engine API decoy on 2375/2376 (opt-in). Pure JSON responder, no sidecar. */
        public bool $dockerApiEnabled,
        /** Require an auth credential on the fake chat API (off = serve keyless, like an open LLM box). */
        public bool $aiStrictAuth,
        /** Require a catalogued model on the fake chat API (off = echo any model name, for engagement). */
        public bool $aiStrictModel,
        // Chat-only LLM sampling. The sidecar answers correctly at low temp, so believable nonsense
        // needs high temperature + min_p 0. These apply ONLY to the chat path — page generation keeps
        // its own low-temp/fixed-seed sampling (do not reuse these there).
        public float $aiTemp,
        public float $aiMinP,
        public float $aiTopP,
        // A fresh IP gets its first N chat answers straight (believable), then the box degrades to the
        // troll persona — a real box on the opening probes, useless as free compute after. Windowed so
        // the budget refreshes after a quiet gap, like a real session.
        public int $aiRealFirst,
        public int $aiRealWindowS,
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
        /** Raw persona material (pre-hash). Passed to core Config so the template tier derives the
         *  SAME per-deploy PersonaIdentity via seedFromMaterial. Private per-deploy value — never emit. */
        public string $personaMaterial,
        /** Endless throttled backup-download bait (fleet console). On by default; the client SW reads
         *  the throttle knobs below from the manifest, so speed/variability are centrally configured. */
        public bool $endlessDownload,
        public int $dlChunkMinKb,
        public int $dlChunkMaxKb,
        public int $dlIntervalMs,
        public int $dlVaryPct,
        public int $dlEasePeriodS,
        public int $dlFallbackCapMb,
        /** The path the funnypot dashboard/main page lives at in public mode. Default /funnypot; set
         *  FUNNYPOT_APP_PATH to move it anywhere. */
        public string $funnypotPath,
        /** Hide the funnypot dashboard/main page entirely — its path falls through to the honeypot like
         *  any probe, so the "Welcome to funnypot" page is never exposed. */
        public bool $hideMainPage,
        /** FULL-request capture (opt-in) — store every header + full query + full body of every request in
         *  a separate raw-capture.sqlite, for analysing a vuln scan. Off in normal operation. */
        public bool $captureRaw,
        // Aggregate-analytics rollup worker (FP-0243, demo/rollup.php). Folds the raw hits table into
        // a small rollup table on a timer so the analytics reads stay O(buckets), flat in event volume.
        /** On unless FUNNYPOT_ROLLUP=0. Off = the worker is a no-op (no rollups maintained). */
        public bool $rollupEnabled,
        /** Seconds between worker passes (entrypoint timer). */
        public int $rollupIntervalS,
        /** Raw hit rows folded per pass; the worker loops until the backlog drains. */
        public int $rollupBatch,
        /** Distinct values kept per (gran,bucket,dim) before the tail folds into '(other)'
         *  — the cardinality guard that keeps a sprayed dimension from inflating rollup storage. */
        public int $rollupTopK,
        /** Retention for minute / hour / day rollup buckets (hours, days, days). */
        public int $rollupRetainMinH,
        public int $rollupRetainHourD,
        public int $rollupRetainDayD,
        // AI-attacker cost-amplification tarpit (FP-0245). Master switch OFF by default (opt-in) given
        // the self-DoS class — flip on only after the load test. The caps are tied to pm.max_children=16
        // (spec §3): a tarpit request holds one of a small pool of slots for its lifetime, so it can
        // never starve the honeypot's real detection/reporting job. tarpitDbPath is its own SQLite file.
        public bool $tarpitEnabled,
        public string $tarpitDbPath,
        /** Global concurrent tarpit slots (≤ ¼ of 16 workers leaves ≥12 for real traffic). */
        public int $tarpitMaxConcurrent,
        /** Concurrent slots one IP may hold (1 = no single IP can occupy the pool). */
        public int $tarpitMaxPerIp,
        /** Bytes per single tarpit response (streamed generators, hard-capped). */
        public int $tarpitBytesPerRespMb,
        /** Total bytes one IP may pull from the tarpit per hour. */
        public int $tarpitBytesPerIpHrMb,
        /** Total server wall-time one IP may consume across tarpit hits per hour. */
        public int $tarpitWallPerIpHrS,
        /** Aggregate tarpit egress ceiling per hour; over it, shed all tarpit to 404. */
        public int $tarpitGlobalBytesHrMb,
        /** Labyrinth pages one IP may fetch per hour (bounds iterations even though each page is cheap). */
        public int $tarpitPagesPerIpHr,
        /** Optional server latency while holding a slot (0245d; 0 = off, hard-clamped ≤ 2000 ms). */
        public int $tarpitLatencyMs,
        /** Decompression cap if gzip is ever used (D3); decompressed ≤ this, ratio ≤ 100:1. */
        public int $tarpitDecompCapMb,
        // Time-based blind-injection decoy (FP-0228). Off by default (opt-in). Honours an attacker's
        // SLEEP(n)/WAITFOR/time-based-cmdi just enough to satisfy calibrated-SLEEP confirmation, but
        // bounded: the delay rides FP-0245's TarpitBudget slot (≤ MAX_CONCURRENT workers ever sleeping)
        // and its per-IP hourly wall ledger (tarpitWallPerIpHrS is the operator's cumulative allowance).
        /** Master switch for the FP-0228 honoured-SLEEP decoy (needs the tarpit slot/ledger infra). */
        public bool $sleepDecoy = false,
        /** Per-request honoured-sleep cap (ms), hard-clamped ≤ 2000 so an operator typo can't pin a
         *  worker near nginx's 15s timeout; TarpitBudget re-clamps to LATENCY_HARD_CAP_MS behind this. */
        public int $sleepPerReqCapMs = 2000,
    ) {
    }

    /** The active-sabotage "malformed" style (FUNNYPOT_STYLE=malformed) — off by default, explicit
     *  opt-in. The interactive socket honeypots answer with a bounded malformed trickle, not a shell. */
    public function isMalformed(): bool
    {
        return $this->style === 'malformed';
    }

    /**
     * The style handed to the HTTP/core engine. Core supports only realistic + taunt; any other value
     * (the protocol-only 'malformed' style, or a typo) falls back to realistic so the HTTP tier never
     * degrades to a bare/unknown style. 'malformed' is a protocol-layer style read directly by
     * MalformedStream; HTTP malformed is a separate ticket (FP-0110), so HTTP stays realistic here.
     */
    public function httpStyle(): string
    {
        return in_array($this->style, ['realistic', 'taunt'], true) ? $this->style : 'realistic';
    }

    /**
     * The env-sourced builder — the seed + the fallback. Kept as the canonical factory (the test
     * suite and the CLI runners call it directly); now a thin delegate over {@see build()} with the
     * raw source being plain getenv().
     */
    public static function fromEnv(string $baseDir): self
    {
        return self::build($baseDir, static fn (string $key) => getenv($key));
    }

    /**
     * The store-backed builder (FP-0242a). Same object, same validation/clamps — the ONLY difference
     * is the raw source: each FUNNYPOT_* var resolves to its stored override if one exists, else the
     * real env value (see {@see ConfigStore::rawForEnv()}). Env-only fields (paths, secrets, identity,
     * network topology) are not registered in the store and fall straight through to getenv here, so
     * they stay env-sourced. Fail-safe: an unreadable store degrades to the env/default baseline.
     */
    public static function fromStore(ConfigStore $store, string $baseDir): self
    {
        return self::build($baseDir, static fn (string $key) => $store->rawForEnv($key));
    }

    /**
     * Resolve every field from a raw source. Precedence + defaults + clamps live here ONCE, shared by
     * {@see fromEnv} and {@see fromStore}, so a stored override is coerced/clamped exactly as an env
     * value always was. $env is a getenv()-shaped callable: it returns the raw string for a key, or
     * false when unset (both false and '' mean "use the default", as getenv semantics require).
     *
     * @param callable(string):(string|false) $env
     */
    private static function build(string $baseDir, callable $env): self
    {
        $store = rtrim($baseDir, '/') . '/storage';

        // The source returns false when unset and '' when set empty; treat both as "use the default".
        $str = static function (string $key, string $default) use ($env): string {
            $v = $env($key);

            return ($v === false || $v === '') ? $default : $v;
        };
        // A boolean flag that is on by default and only switched off by an explicit "0".
        $onUnless0 = static fn (string $key): bool => $env($key) !== '0';

        $db = $str('FUNNYPOT_DB', $store . '/funnypot.sqlite');
        if ($db === 'off') {
            $db = $store . '/funnypot.sqlite'; // SQLite is canonical now; 'off' no longer disables it
        }

        // Private per-deploy persona material (never a public value like the cert CN). Both the app
        // persona seed and the core template tier (via Config->deploySeed) derive from this SAME string,
        // so the two tiers present one coherent identity.
        $personaMaterial = $str('FUNNYPOT_PERSONA_SEED', $str('FUNNYPOT_PERSONA_SECRET', 'funnypot'));

        // Derive the persona once so the seed and the PHP version below share it. X-Powered-By defaults to
        // the SAME PHP version /phpinfo.php shows (PersonaIdentity::productVersion('php')), so the live
        // header and the phpinfo page never advertise two different PHP versions — a coherence tell.
        // FUNNYPOT_POWERED_BY still overrides.
        $personaSeed = PersonaIdentity::seedFromMaterial($personaMaterial);
        $defaultPoweredBy = 'PHP/' . PersonaIdentity::fromSeed($personaSeed)->productVersion('php');

        return new self(
            mode: $env('FUNNYPOT_MODE') === 'stealth' ? 'stealth' : 'public',
            style: $str('FUNNYPOT_STYLE', 'realistic'),
            dbPath: $db,
            logPath: $str('FUNNYPOT_LOG', $store . '/hits.log'),
            geoDbPath: $str('FUNNYPOT_GEO_DB', $store . '/dbip-country.csv.gz'),
            vulnsPath: $str('FUNNYPOT_VULNS', $store . '/funnypot-vulns.json'),
            poweredBy: $str('FUNNYPOT_POWERED_BY', $defaultPoweredBy),
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
            // Public-visibility knob (FP-0242b). Clamp toward LESS exposure: any value that is not one of
            // the three known levels resolves to 'none' (the fail-safe baseline), so a garbage stored/env
            // value can never widen exposure. The registry default is 'none' too, so a store read fault
            // (which yields the baseline) also lands on the least-exposed view.
            dashboardPublicView: in_array($str('FUNNYPOT_PUBLIC_VIEW', 'none'), ['full', 'minimal', 'none'], true)
                ? $str('FUNNYPOT_PUBLIC_VIEW', 'none')
                : 'none',
            funnypotPath: '/' . trim($str('FUNNYPOT_APP_PATH', 'funnypot'), '/'),
            hideMainPage: in_array(strtolower((string) $env('FUNNYPOT_HIDE_MAIN')), ['1', 'on', 'true', 'yes'], true),
            captureRaw: in_array(strtolower((string) $env('FUNNYPOT_CAPTURE_RAW')), ['1', 'on', 'true', 'yes'], true),
            blocklistEnabled: in_array(strtolower((string) $env('FUNNYPOT_BLOCKLIST')), ['1', 'on', 'true', 'yes'], true),
            intelDbPath: $str('FUNNYPOT_INTEL_DB', $store . '/intel.sqlite'),
            blocklistMinLists: max(1, (int) $str('FUNNYPOT_BLOCKLIST_MIN_LISTS', '1')),
            abuseIpdbKey: $str('FUNNYPOT_ABUSEIPDB_KEY', ''),
            abuseIpdbReport: in_array(strtolower((string) $env('FUNNYPOT_ABUSEIPDB_REPORT')), ['1', 'on', 'true', 'yes'], true),
            selfIps: array_values(array_filter(array_map('trim', explode(',', $str('FUNNYPOT_SELF_IPS', ''))))),
            trustedProxies: array_values(array_filter(array_map('trim', explode(',', $str('FUNNYPOT_TRUSTED_PROXIES', ''))))),
            abuseIpdbDailyCap: max(1, (int) $str('FUNNYPOT_ABUSEIPDB_DAILY_CAP', '1000')),
            abuseIpdbDedupHours: max(1, (int) $str('FUNNYPOT_ABUSEIPDB_DEDUP_HOURS', '24')),
            threatIntelReport: in_array(strtolower((string) $env('FUNNYPOT_THREATINTEL_REPORT')), ['1', 'on', 'true', 'yes'], true),
            threatIntelUrl: $str('FUNNYPOT_THREATINTEL_URL', 'https://threatintel.metrictower.com'),
            threatIntelKey: $str('FUNNYPOT_THREATINTEL_KEY', ''),
            threatIntelDailyCap: max(1, (int) $str('FUNNYPOT_THREATINTEL_DAILY_CAP', '1000')),
            threatIntelDedupHours: max(1, (int) $str('FUNNYPOT_THREATINTEL_DEDUP_HOURS', '24')),
            llmEnabled: in_array(strtolower((string) $env('FUNNYPOT_LLM')), ['1', 'on', 'true', 'yes'], true),
            aiApiEnabled: in_array(strtolower((string) $env('FUNNYPOT_AI_API')), ['1', 'on', 'true', 'yes'], true),
            dockerApiEnabled: in_array(strtolower((string) $env('FUNNYPOT_DOCKER_API')), ['1', 'on', 'true', 'yes'], true),
            aiStrictAuth: in_array(strtolower((string) $env('FUNNYPOT_AI_STRICT_AUTH')), ['1', 'on', 'true', 'yes'], true),
            aiStrictModel: in_array(strtolower((string) $env('FUNNYPOT_AI_STRICT_MODEL')), ['1', 'on', 'true', 'yes'], true),
            aiTemp: (float) $str('FUNNYPOT_AI_TEMP', '0.8'),
            aiMinP: (float) $str('FUNNYPOT_AI_MIN_P', '0.0'),
            aiTopP: (float) $str('FUNNYPOT_AI_TOP_P', '1.0'),
            aiRealFirst: max(0, (int) $str('FUNNYPOT_AI_REAL_FIRST', '5')),
            aiRealWindowS: max(1, (int) $str('FUNNYPOT_AI_REAL_WINDOW_S', '600')),
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
            personaSeed: $personaSeed,
            personaMaterial: $personaMaterial,
            // Endless-download bait: on unless explicitly "0". Throttle knobs clamped to sane bounds so
            // a bad env value can't produce a firehose (instant tell + fills disk) or a dead stall.
            endlessDownload: $onUnless0('FUNNYPOT_ENDLESS_DOWNLOAD'),
            dlChunkMinKb: max(1, min(1024, (int) $str('FUNNYPOT_DL_CHUNK_MIN_KB', '100'))),
            dlChunkMaxKb: max(1, min(1024, (int) $str('FUNNYPOT_DL_CHUNK_MAX_KB', '200'))),
            dlIntervalMs: max(10, min(5000, (int) $str('FUNNYPOT_DL_INTERVAL_MS', '100'))),
            dlVaryPct: max(0, min(95, (int) $str('FUNNYPOT_DL_VARY_PCT', '50'))),
            dlEasePeriodS: max(1, min(600, (int) $str('FUNNYPOT_DL_EASE_PERIOD_S', '20'))),
            dlFallbackCapMb: max(1, min(500, (int) $str('FUNNYPOT_DL_FALLBACK_CAP_MB', '50'))),
            // Rollup worker: on unless explicitly "0", like the other on-by-default flags. The
            // interval/batch/top-K/retention knobs are clamped to sane floors so a bad env value
            // can't stall the worker or unbound the rollup table.
            rollupEnabled: $onUnless0('FUNNYPOT_ROLLUP'),
            rollupIntervalS: max(1, (int) $str('FUNNYPOT_ROLLUP_INTERVAL', '15')),
            rollupBatch: max(1, (int) $str('FUNNYPOT_ROLLUP_BATCH', '5000')),
            rollupTopK: max(1, (int) $str('FUNNYPOT_ROLLUP_TOPK', '20')),
            rollupRetainMinH: max(1, (int) $str('FUNNYPOT_ROLLUP_RETAIN_MIN_H', '48')),
            rollupRetainHourD: max(1, (int) $str('FUNNYPOT_ROLLUP_RETAIN_HOUR_D', '30')),
            rollupRetainDayD: max(1, (int) $str('FUNNYPOT_ROLLUP_RETAIN_DAY_D', '365')),
            // Tarpit (FP-0245): opt-in master switch; caps clamped to sane floors+ceilings so a bad env
            // value can neither disable a cap (floor) nor exceed the 16-worker pool / overflow (ceiling).
            tarpitEnabled: in_array(strtolower((string) $env('FUNNYPOT_TARPIT')), ['1', 'on', 'true', 'yes'], true),
            tarpitDbPath: $str('FUNNYPOT_TARPIT_DB', $store . '/tarpit.sqlite'),
            tarpitMaxConcurrent: max(1, min(15, (int) $str('FUNNYPOT_TARPIT_MAX_CONCURRENT', '4'))),
            tarpitMaxPerIp: max(1, min(15, (int) $str('FUNNYPOT_TARPIT_MAX_PER_IP', '1'))),
            tarpitBytesPerRespMb: max(1, min(512, (int) $str('FUNNYPOT_TARPIT_BYTES_PER_RESP_MB', '8'))),
            tarpitBytesPerIpHrMb: max(1, min(65536, (int) $str('FUNNYPOT_TARPIT_BYTES_PER_IP_HR_MB', '64'))),
            tarpitWallPerIpHrS: max(1, min(3600, (int) $str('FUNNYPOT_TARPIT_WALL_PER_IP_HR_S', '120'))),
            tarpitGlobalBytesHrMb: max(1, min(1048576, (int) $str('FUNNYPOT_TARPIT_GLOBAL_BYTES_HR_MB', '1024'))),
            tarpitPagesPerIpHr: max(1, min(1000000, (int) $str('FUNNYPOT_TARPIT_PAGES_PER_IP_HR', '2000'))),
            tarpitLatencyMs: max(0, min(2000, (int) $str('FUNNYPOT_TARPIT_LATENCY_MS', '0'))),
            tarpitDecompCapMb: max(1, min(64, (int) $str('FUNNYPOT_TARPIT_DECOMP_CAP_MB', '16'))),
            // FP-0228 honoured-SLEEP decoy: opt-in flag + per-request cap hard-clamped ≤2000 (a second
            // wall behind TarpitBudget::LATENCY_HARD_CAP_MS). The per-IP cumulative budget is NOT a new
            // knob — it rides FUNNYPOT_TARPIT_WALL_PER_IP_HR_S (the same wall ledger), no competing budget.
            sleepDecoy: in_array(strtolower((string) $env('FUNNYPOT_SLEEP_DECOY')), ['1', 'on', 'true', 'yes'], true),
            sleepPerReqCapMs: max(0, min(2000, (int) $str('FUNNYPOT_SLEEP_PER_REQ_CAP_MS', '2000'))),
        );
    }
}

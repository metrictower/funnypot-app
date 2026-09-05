<?php

declare(strict_types=1);

namespace Funnypot\App\Config;

/**
 * The typed schema of every runtime-tunable config knob — the single source of truth for the
 * {@see ConfigStore} and (in FP-0242b) the admin UI. One entry per canonical key.
 *
 * IMPORTANT — this is a TRANSCRIPTION of the defaults and clamps already coded in
 * {@see AppConfig::fromEnv()} (which stays the seed + fallback). Each entry's clamp bounds mirror the
 * matching `AppConfig::build()` field; per-line `AppConfig.php:NNN` citations were dropped (FP-0242b
 * review nit fable#5) because they drift on every edit to `AppConfig` — ConfigRegistryTest asserts (by
 * reflection over `AppConfig::__construct`) that the field set here stays in sync with the value
 * object, which is the durable guard the stale line numbers pretended to be. The env-only fields —
 * filesystem paths, secrets/identity and
 * network topology — are deliberately NOT here (they stay env-sourced inside `fromStore`); the test
 * holds their allow-list. The install identity inputs (FUNNYPOT_INSTALL_SECRET[_FILE], the persona
 * overrides, the operator TLS paths, the runtime-dir override) are never registered at all: they are
 * not AppConfig fields, so a stored override could never inject or reveal them — ConfigRegistryTest
 * pins `keyForEnv()` to null for each.
 *
 * The `default` string is the ENV-level default (the literal `fromEnv` passes to `$str`), i.e. the
 * value seen when neither a stored override nor the env var is set. `poweredBy` is the one knob whose
 * effective default is derived at runtime (from the install persona) rather than a literal; its
 * registry default is '' and the composition root resolves the real default from
 * `HttpIdentity::defaultPoweredBy()`.
 *
 * Types:
 *   string  — free text
 *   enum    — one of `enum[]`
 *   int     — integer, clamped to [min,max] when set (mirrors `fromEnv`'s max(min(...)) clamps)
 *   float   — float
 *   bool    — stored canonically as '1'/'0'. `bool_style` records how the ENV value is read in
 *             `fromEnv`: 'on_unless_0' (on unless exactly "0") vs 'opt_in' (off unless truthy).
 *   csv     — comma-separated list
 *
 * `live` marks whether a change takes effect without a process restart (spec §4) — metadata for the
 * future admin UI; it does not affect resolution here. `secret` knobs (none are registered today —
 * secrets live in the env-only set) would never be echoed back to the UI.
 *
 * `protected` (FP-0250 2.3) marks an exposure knob whose ENV value is a CEILING a stored override may
 * never loosen — a hijacked admin session must not be able to unmask/reconfigure the honeypot with one
 * CSRF'd write. `safety_order` (present only on protected knobs with an ordered value space) lists the
 * knob's values from least to MOST safe; {@see safetyRank()} indexes into it. A protected knob with NO
 * `safety_order` (the hidden-path strings) has no notion of "safer" — it rejects any stored override at
 * all, so it is effectively env-only in practice. {@see ConfigStore::set()} enforces this at write time
 * (fail-closed) and {@see ConfigStore::rawForEnv()}/`get()`/`snapshot()` re-enforce it at READ time (a
 * stored value that was legitimate when written can become unsafe later purely because the operator
 * tightened env — the resolution-time clamp catches that stale row without needing a write).
 */
final class ConfigRegistry
{
    /** @var array<string,array<string,mixed>> canonical key => entry (this instance's schema) */
    private array $entries;

    /** @var array<string,string> env var => canonical key (reverse index) */
    private array $byEnv;

    /**
     * @param array<string,array<string,mixed>>|null $entries defaults to the canonical schema; a
     *        subset can be injected for tests.
     */
    public function __construct(?array $entries = null)
    {
        $this->entries = $entries ?? self::schema();
        $this->byEnv = [];
        foreach ($this->entries as $key => $e) {
            if (isset($e['env']) && $e['env'] !== '') {
                $this->byEnv[$e['env']] = $key;
            }
        }
    }

    /**
     * The canonical schema. Keyed by dotted config key, in UI-display order (grouped). Every `default`
     * / bound / `bool_style` mirrors the cited `AppConfig.php` line.
     *
     * @return array<string,array<string,mixed>>
     */
    public static function schema(): array
    {
        return [
            // --- Deception / behaviour ---
            // FP-0250 2.3: 'protected' + 'safety_order' (ascending safety) on the exposure knobs below —
            // env is the ceiling a stored override may never loosen (ConfigStore::set()/rawForEnv()).
            'mode' => ['field' => 'mode', 'env' => 'FUNNYPOT_MODE', 'type' => 'enum', 'enum' => ['public', 'stealth'], 'default' => 'public', 'group' => 'Deception', 'live' => true, 'secret' => false, 'protected' => true, 'safety_order' => ['public', 'stealth']],
            'style' => ['field' => 'style', 'env' => 'FUNNYPOT_STYLE', 'type' => 'enum', 'enum' => ['realistic', 'taunt', 'malformed'], 'default' => 'realistic', 'group' => 'Deception', 'live' => true, 'secret' => false],
            'powered_by' => ['field' => 'poweredBy', 'env' => 'FUNNYPOT_POWERED_BY', 'type' => 'string', 'default' => '', 'group' => 'Deception', 'live' => true, 'secret' => false], // (effective default is persona-derived, resolved by the composition root from HttpIdentity)
            'severity_ceiling' => ['field' => 'severityCeiling', 'env' => 'FUNNYPOT_CEILING', 'type' => 'string', 'default' => 'critical', 'group' => 'Deception', 'live' => true, 'secret' => false], // (free string in fromEnv; not clamped)
            'latency_ms' => ['field' => 'latencyMs', 'env' => 'FUNNYPOT_LATENCY_MS', 'type' => 'int', 'default' => '0', 'group' => 'Deception', 'live' => true, 'secret' => false], // (no clamp)
            'jitter_ms' => ['field' => 'jitterMs', 'env' => 'FUNNYPOT_JITTER_MS', 'type' => 'int', 'default' => '40', 'group' => 'Deception', 'live' => true, 'secret' => false], // (no clamp)
            'attack_emulation' => ['field' => 'attackEmulation', 'env' => 'FUNNYPOT_ATTACK', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Deception', 'live' => true, 'secret' => false],
            'decoy_archive' => ['field' => 'decoyArchive', 'env' => 'FUNNYPOT_DECOY_ARCHIVE', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Deception', 'live' => true, 'secret' => false],
            // Protected + UNORDERED (no safety_order): a string has no notion of "safer", so a hijacked
            // session must never be able to move OR unmask the hidden path — any stored override is
            // rejected outright (ConfigStore::set()). The operator changes these via env + redeploy.
            'dashboard_path' => ['field' => 'dashboardPath', 'env' => 'FUNNYPOT_DASHBOARD_PATH', 'type' => 'string', 'default' => '/__fp/', 'group' => 'Deception', 'live' => true, 'secret' => false, 'protected' => true], // (build() normalises to /trim/)
            'funnypot_path' => ['field' => 'funnypotPath', 'env' => 'FUNNYPOT_APP_PATH', 'type' => 'string', 'default' => 'funnypot', 'group' => 'Deception', 'live' => true, 'secret' => false, 'protected' => true],
            'hide_main_page' => ['field' => 'hideMainPage', 'env' => 'FUNNYPOT_HIDE_MAIN', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Deception', 'live' => true, 'secret' => false, 'protected' => true, 'safety_order' => ['0', '1']], // hidden (1) is safer
            'capture_raw' => ['field' => 'captureRaw', 'env' => 'FUNNYPOT_CAPTURE_RAW', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Deception', 'live' => true, 'secret' => false],
            // FP-0242b: what an UNAUTHENTICATED visitor sees on the dashboard path. Default 'none' is the
            // fail-safe/least-exposed baseline (operator decision, comments.md 2026-09-01): the store
            // returns this default on a read fault, so the baseline MUST be the least-exposed value for
            // "config-read error ⇒ less exposure" to hold. The authed operator always sees full regardless.
            'dashboard.public_view' => ['field' => 'dashboardPublicView', 'env' => 'FUNNYPOT_PUBLIC_VIEW', 'type' => 'enum', 'enum' => ['full', 'minimal', 'none'], 'default' => 'none', 'group' => 'Deception', 'live' => true, 'secret' => false, 'protected' => true, 'safety_order' => ['full', 'minimal', 'none']],

            // --- Feature toggles (opt-in unless noted) — restart-required: each gates object construction at bootstrap (spec §4) ---
            'protocols_enabled' => ['field' => 'protocolsEnabled', 'env' => 'FUNNYPOT_PROTOCOLS', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Features', 'live' => false, 'secret' => false],
            'blocklist_enabled' => ['field' => 'blocklistEnabled', 'env' => 'FUNNYPOT_BLOCKLIST', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false],
            'abuseipdb_report' => ['field' => 'abuseIpdbReport', 'env' => 'FUNNYPOT_ABUSEIPDB_REPORT', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false],
            'threatintel_report' => ['field' => 'threatIntelReport', 'env' => 'FUNNYPOT_THREATINTEL_REPORT', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false],
            'llm_enabled' => ['field' => 'llmEnabled', 'env' => 'FUNNYPOT_LLM', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false],
            'ai_api_enabled' => ['field' => 'aiApiEnabled', 'env' => 'FUNNYPOT_AI_API', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false],
            'docker_api_enabled' => ['field' => 'dockerApiEnabled', 'env' => 'FUNNYPOT_DOCKER_API', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false],
            'endless_download' => ['field' => 'endlessDownload', 'env' => 'FUNNYPOT_ENDLESS_DOWNLOAD', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Features', 'live' => false, 'secret' => false],

            // --- LLM / fake-AI sampling + throttles (restart-required: baked into clients at bootstrap) ---
            'ai.strict_auth' => ['field' => 'aiStrictAuth', 'env' => 'FUNNYPOT_AI_STRICT_AUTH', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'LLM', 'live' => false, 'secret' => false],
            'ai.strict_model' => ['field' => 'aiStrictModel', 'env' => 'FUNNYPOT_AI_STRICT_MODEL', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'LLM', 'live' => false, 'secret' => false],
            'ai.temp' => ['field' => 'aiTemp', 'env' => 'FUNNYPOT_AI_TEMP', 'type' => 'float', 'default' => '0.8', 'group' => 'LLM', 'live' => false, 'secret' => false], // (no clamp)
            'ai.min_p' => ['field' => 'aiMinP', 'env' => 'FUNNYPOT_AI_MIN_P', 'type' => 'float', 'default' => '0.0', 'group' => 'LLM', 'live' => false, 'secret' => false], // (no clamp)
            'ai.top_p' => ['field' => 'aiTopP', 'env' => 'FUNNYPOT_AI_TOP_P', 'type' => 'float', 'default' => '1.0', 'group' => 'LLM', 'live' => false, 'secret' => false], // (no clamp)
            'ai.real_first' => ['field' => 'aiRealFirst', 'env' => 'FUNNYPOT_AI_REAL_FIRST', 'type' => 'int', 'min' => 0, 'default' => '5', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(0,...))
            'ai.real_window_s' => ['field' => 'aiRealWindowS', 'env' => 'FUNNYPOT_AI_REAL_WINDOW_S', 'type' => 'int', 'min' => 1, 'default' => '600', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(1,...))
            'llm.url' => ['field' => 'llmUrl', 'env' => 'FUNNYPOT_LLM_URL', 'type' => 'string', 'default' => 'http://funnypot-llm:8080/completion', 'group' => 'LLM', 'live' => false, 'secret' => false],
            'llm.timeout_ms' => ['field' => 'llmTimeoutMs', 'env' => 'FUNNYPOT_LLM_TIMEOUT_MS', 'type' => 'int', 'min' => 200, 'default' => '9000', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(200,...))
            'llm.n_predict' => ['field' => 'llmNPredict', 'env' => 'FUNNYPOT_LLM_N_PREDICT', 'type' => 'int', 'min' => 64, 'default' => '320', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(64,...))
            'llm.cache_max_bytes' => ['field' => 'llmCacheMaxBytes', 'env' => 'FUNNYPOT_LLM_CACHE_MAX_BYTES', 'type' => 'int', 'default' => '0', 'group' => 'LLM', 'live' => false, 'secret' => false], // (no clamp)
            'llm.max_concurrent' => ['field' => 'llmMaxConcurrent', 'env' => 'FUNNYPOT_LLM_MAX_CONCURRENT', 'type' => 'int', 'min' => 1, 'default' => '4', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(1,...))
            'llm.prompt_version' => ['field' => 'llmPromptVersion', 'env' => 'FUNNYPOT_LLM_PROMPT_VERSION', 'type' => 'string', 'default' => 'v2', 'group' => 'LLM', 'live' => false, 'secret' => false],
            'llm.breaker_threshold' => ['field' => 'llmBreakerThreshold', 'env' => 'FUNNYPOT_LLM_BREAKER_THRESHOLD', 'type' => 'int', 'min' => 1, 'default' => '5', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(1,...))
            'llm.breaker_cooldown_s' => ['field' => 'llmBreakerCooldownS', 'env' => 'FUNNYPOT_LLM_BREAKER_COOLDOWN_S', 'type' => 'int', 'min' => 1, 'default' => '30', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(1,...))
            'llm.velocity_per_60s' => ['field' => 'llmVelocityPer60s', 'env' => 'FUNNYPOT_LLM_VELOCITY_PER_60S', 'type' => 'int', 'min' => 1, 'default' => '5', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(1,...))
            'llm.velocity_per_10m' => ['field' => 'llmVelocityPer10m', 'env' => 'FUNNYPOT_LLM_VELOCITY_PER_10M', 'type' => 'int', 'min' => 1, 'default' => '15', 'group' => 'LLM', 'live' => false, 'secret' => false], // (max(1,...))
            'llm.gate_allow' => ['field' => 'llmGateAllowIps', 'env' => 'FUNNYPOT_LLM_GATE_ALLOW', 'type' => 'csv', 'default' => '', 'group' => 'LLM', 'live' => false, 'secret' => false],

            // --- Threat-intel / blocklist knobs (restart-required) ---
            'blocklist.min_lists' => ['field' => 'blocklistMinLists', 'env' => 'FUNNYPOT_BLOCKLIST_MIN_LISTS', 'type' => 'int', 'min' => 1, 'default' => '1', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // (max(1,...))
            'abuseipdb.daily_cap' => ['field' => 'abuseIpdbDailyCap', 'env' => 'FUNNYPOT_ABUSEIPDB_DAILY_CAP', 'type' => 'int', 'min' => 1, 'default' => '1000', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // (max(1,...))
            'abuseipdb.dedup_hours' => ['field' => 'abuseIpdbDedupHours', 'env' => 'FUNNYPOT_ABUSEIPDB_DEDUP_HOURS', 'type' => 'int', 'min' => 1, 'default' => '24', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // (max(1,...))
            'threatintel.url' => ['field' => 'threatIntelUrl', 'env' => 'FUNNYPOT_THREATINTEL_URL', 'type' => 'string', 'default' => 'https://threatintel.metrictower.com', 'group' => 'Threat-intel', 'live' => false, 'secret' => false],
            'threatintel.daily_cap' => ['field' => 'threatIntelDailyCap', 'env' => 'FUNNYPOT_THREATINTEL_DAILY_CAP', 'type' => 'int', 'min' => 1, 'default' => '1000', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // (max(1,...))
            'threatintel.dedup_hours' => ['field' => 'threatIntelDedupHours', 'env' => 'FUNNYPOT_THREATINTEL_DEDUP_HOURS', 'type' => 'int', 'min' => 1, 'default' => '24', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // (max(1,...))
            'abuseipdb.max_queue_age_hours' => ['field' => 'abuseIpdbMaxQueueAgeHours', 'env' => 'FUNNYPOT_ABUSEIPDB_MAX_QUEUE_AGE_HOURS', 'type' => 'int', 'min' => 1, 'default' => '24', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // FP-0247 (max(1,...))
            'threatintel.max_queue_age_hours' => ['field' => 'threatIntelMaxQueueAgeHours', 'env' => 'FUNNYPOT_THREATINTEL_MAX_QUEUE_AGE_HOURS', 'type' => 'int', 'min' => 1, 'default' => '24', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // FP-0247 (max(1,...))

            // --- Endless-download throttle knobs (restart-required: DownloadRouter ctor). Clamped both floor+ceiling. ---
            'dl.chunk_min_kb' => ['field' => 'dlChunkMinKb', 'env' => 'FUNNYPOT_DL_CHUNK_MIN_KB', 'type' => 'int', 'min' => 1, 'max' => 1024, 'default' => '100', 'group' => 'Download', 'live' => false, 'secret' => false], // (max(1,min(1024,...)))
            'dl.chunk_max_kb' => ['field' => 'dlChunkMaxKb', 'env' => 'FUNNYPOT_DL_CHUNK_MAX_KB', 'type' => 'int', 'min' => 1, 'max' => 1024, 'default' => '200', 'group' => 'Download', 'live' => false, 'secret' => false], // (max(1,min(1024,...)))
            'dl.interval_ms' => ['field' => 'dlIntervalMs', 'env' => 'FUNNYPOT_DL_INTERVAL_MS', 'type' => 'int', 'min' => 10, 'max' => 5000, 'default' => '100', 'group' => 'Download', 'live' => false, 'secret' => false], // (max(10,min(5000,...)))
            'dl.vary_pct' => ['field' => 'dlVaryPct', 'env' => 'FUNNYPOT_DL_VARY_PCT', 'type' => 'int', 'min' => 0, 'max' => 95, 'default' => '50', 'group' => 'Download', 'live' => false, 'secret' => false], // (max(0,min(95,...)))
            'dl.ease_period_s' => ['field' => 'dlEasePeriodS', 'env' => 'FUNNYPOT_DL_EASE_PERIOD_S', 'type' => 'int', 'min' => 1, 'max' => 600, 'default' => '20', 'group' => 'Download', 'live' => false, 'secret' => false], // (max(1,min(600,...)))
            'dl.fallback_cap_mb' => ['field' => 'dlFallbackCapMb', 'env' => 'FUNNYPOT_DL_FALLBACK_CAP_MB', 'type' => 'int', 'min' => 1, 'max' => 500, 'default' => '50', 'group' => 'Download', 'live' => false, 'secret' => false], // (max(1,min(500,...)))

            // --- Retention (separate CLI runner; picked up on its next timer pass) ---
            'retain_days' => ['field' => 'retainDays', 'env' => 'FUNNYPOT_RETAIN_DAYS', 'type' => 'int', 'default' => '0', 'group' => 'Retention', 'live' => false, 'secret' => false], // (no clamp)
            'retain_gb' => ['field' => 'retainGb', 'env' => 'FUNNYPOT_RETAIN_GB', 'type' => 'float', 'default' => '0', 'group' => 'Retention', 'live' => false, 'secret' => false], // (no clamp)
            // FP-0249: raw-capture.sqlite (the FUNNYPOT_CAPTURE_RAW debug capture) is bounded by default,
            // unlike the hit store above — it is opt-in and its whole failure mode is disk fill, so an
            // operator who truly wants it unbounded sets 0 explicitly.
            'raw_retain_days' => ['field' => 'rawRetainDays', 'env' => 'FUNNYPOT_RAW_RETAIN_DAYS', 'type' => 'int', 'default' => '7', 'group' => 'Retention', 'live' => false, 'secret' => false], // (no clamp)
            'raw_retain_gb' => ['field' => 'rawRetainGb', 'env' => 'FUNNYPOT_RAW_RETAIN_GB', 'type' => 'float', 'default' => '1', 'group' => 'Retention', 'live' => false, 'secret' => false], // (no clamp)

            // --- Analytics rollup worker (FP-0243; separate CLI runner, picked up next pass) ---
            'rollup.enabled' => ['field' => 'rollupEnabled', 'env' => 'FUNNYPOT_ROLLUP', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Rollup', 'live' => false, 'secret' => false],
            'rollup.interval_s' => ['field' => 'rollupIntervalS', 'env' => 'FUNNYPOT_ROLLUP_INTERVAL', 'type' => 'int', 'min' => 1, 'default' => '15', 'group' => 'Rollup', 'live' => false, 'secret' => false], // (max(1,...))
            'rollup.batch' => ['field' => 'rollupBatch', 'env' => 'FUNNYPOT_ROLLUP_BATCH', 'type' => 'int', 'min' => 1, 'default' => '5000', 'group' => 'Rollup', 'live' => false, 'secret' => false], // (max(1,...))
            'rollup.top_k' => ['field' => 'rollupTopK', 'env' => 'FUNNYPOT_ROLLUP_TOPK', 'type' => 'int', 'min' => 1, 'default' => '20', 'group' => 'Rollup', 'live' => false, 'secret' => false], // (max(1,...))
            'rollup.retain_min_h' => ['field' => 'rollupRetainMinH', 'env' => 'FUNNYPOT_ROLLUP_RETAIN_MIN_H', 'type' => 'int', 'min' => 1, 'default' => '48', 'group' => 'Rollup', 'live' => false, 'secret' => false], // (max(1,...))
            'rollup.retain_hour_d' => ['field' => 'rollupRetainHourD', 'env' => 'FUNNYPOT_ROLLUP_RETAIN_HOUR_D', 'type' => 'int', 'min' => 1, 'default' => '30', 'group' => 'Rollup', 'live' => false, 'secret' => false], // (max(1,...))
            'rollup.retain_day_d' => ['field' => 'rollupRetainDayD', 'env' => 'FUNNYPOT_ROLLUP_RETAIN_DAY_D', 'type' => 'int', 'min' => 1, 'default' => '365', 'group' => 'Rollup', 'live' => false, 'secret' => false], // (max(1,...))

            // --- AI-attacker cost-amplification tarpit (FP-0245). Master switch opt-in; caps clamped floor+ceiling. tarpitDbPath is env-only (a path). ---
            'tarpit.enabled' => ['field' => 'tarpitEnabled', 'env' => 'FUNNYPOT_TARPIT', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Tarpit', 'live' => false, 'secret' => false],
            'tarpit.max_concurrent' => ['field' => 'tarpitMaxConcurrent', 'env' => 'FUNNYPOT_TARPIT_MAX_CONCURRENT', 'type' => 'int', 'min' => 1, 'max' => 15, 'default' => '4', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(15,...)))
            'tarpit.max_per_ip' => ['field' => 'tarpitMaxPerIp', 'env' => 'FUNNYPOT_TARPIT_MAX_PER_IP', 'type' => 'int', 'min' => 1, 'max' => 15, 'default' => '1', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(15,...)))
            'tarpit.bytes_per_resp_mb' => ['field' => 'tarpitBytesPerRespMb', 'env' => 'FUNNYPOT_TARPIT_BYTES_PER_RESP_MB', 'type' => 'int', 'min' => 1, 'max' => 512, 'default' => '8', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(512,...)))
            'tarpit.bytes_per_ip_hr_mb' => ['field' => 'tarpitBytesPerIpHrMb', 'env' => 'FUNNYPOT_TARPIT_BYTES_PER_IP_HR_MB', 'type' => 'int', 'min' => 1, 'max' => 65536, 'default' => '64', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(65536,...)))
            'tarpit.wall_per_ip_hr_s' => ['field' => 'tarpitWallPerIpHrS', 'env' => 'FUNNYPOT_TARPIT_WALL_PER_IP_HR_S', 'type' => 'int', 'min' => 1, 'max' => 3600, 'default' => '120', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(3600,...)))
            'tarpit.global_bytes_hr_mb' => ['field' => 'tarpitGlobalBytesHrMb', 'env' => 'FUNNYPOT_TARPIT_GLOBAL_BYTES_HR_MB', 'type' => 'int', 'min' => 1, 'max' => 1048576, 'default' => '1024', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(1048576,...)))
            'tarpit.pages_per_ip_hr' => ['field' => 'tarpitPagesPerIpHr', 'env' => 'FUNNYPOT_TARPIT_PAGES_PER_IP_HR', 'type' => 'int', 'min' => 1, 'max' => 1000000, 'default' => '2000', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(1000000,...)))
            'tarpit.latency_ms' => ['field' => 'tarpitLatencyMs', 'env' => 'FUNNYPOT_TARPIT_LATENCY_MS', 'type' => 'int', 'min' => 0, 'max' => 2000, 'default' => '0', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(0,min(2000,...)))
            'tarpit.decomp_cap_mb' => ['field' => 'tarpitDecompCapMb', 'env' => 'FUNNYPOT_TARPIT_DECOMP_CAP_MB', 'type' => 'int', 'min' => 1, 'max' => 64, 'default' => '16', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(1,min(64,...)))
            // --- Time-based blind-injection SLEEP decoy (FP-0228). Opt-in; rides the tarpit slot/ledger. The per-IP cumulative sleep budget is tarpit.wall_per_ip_hr_s (no separate knob — one ledger). ---
            'sleep_decoy.enabled' => ['field' => 'sleepDecoy', 'env' => 'FUNNYPOT_SLEEP_DECOY', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Tarpit', 'live' => false, 'secret' => false],
            'sleep_decoy.per_req_cap_ms' => ['field' => 'sleepPerReqCapMs', 'env' => 'FUNNYPOT_SLEEP_PER_REQ_CAP_MS', 'type' => 'int', 'min' => 0, 'max' => 2000, 'default' => '2000', 'group' => 'Tarpit', 'live' => false, 'secret' => false], // (max(0,min(2000,...)))

            // --- Engagement episode metrics (opt-in; restart-required: the store + caps are built at bootstrap). analyticsKey is env-only (a secret). ---
            'engagement.enabled' => ['field' => 'engagementEnabled', 'env' => 'FUNNYPOT_ENGAGEMENT', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Engagement', 'live' => false, 'secret' => false],
            'engagement.idle_gap_s' => ['field' => 'engagementIdleGapS', 'env' => 'FUNNYPOT_ENGAGEMENT_IDLE_GAP_S', 'type' => 'int', 'min' => 60, 'max' => 1800, 'default' => '600', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(60,min(1800,...)))
            'engagement.lifetime_s' => ['field' => 'engagementLifetimeS', 'env' => 'FUNNYPOT_ENGAGEMENT_LIFETIME_S', 'type' => 'int', 'min' => 600, 'max' => 21600, 'default' => '7200', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(600,min(21600,...)))
            'engagement.max_events' => ['field' => 'engagementMaxEvents', 'env' => 'FUNNYPOT_ENGAGEMENT_MAX_EVENTS', 'type' => 'int', 'min' => 1, 'max' => 100000, 'default' => '2000', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(1,min(100000,...)))
            'engagement.max_artifacts' => ['field' => 'engagementMaxArtifacts', 'env' => 'FUNNYPOT_ENGAGEMENT_MAX_ARTIFACTS', 'type' => 'int', 'min' => 1, 'max' => 10000, 'default' => '256', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(1,min(10000,...)))
            'engagement.bytes_per_ep_mb' => ['field' => 'engagementBytesPerEpMb', 'env' => 'FUNNYPOT_ENGAGEMENT_BYTES_PER_EP_MB', 'type' => 'int', 'min' => 1, 'max' => 64, 'default' => '2', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(1,min(64,...)))
            'engagement.global_rows' => ['field' => 'engagementGlobalRows', 'env' => 'FUNNYPOT_ENGAGEMENT_GLOBAL_ROWS', 'type' => 'int', 'min' => 1000, 'max' => 5000000, 'default' => '250000', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(1000,min(5000000,...)))
            'engagement.global_bytes_mb' => ['field' => 'engagementGlobalBytesMb', 'env' => 'FUNNYPOT_ENGAGEMENT_GLOBAL_BYTES_MB', 'type' => 'int', 'min' => 1, 'max' => 4096, 'default' => '256', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(1,min(4096,...)))
            'engagement.retain_days' => ['field' => 'engagementRetainDays', 'env' => 'FUNNYPOT_ENGAGEMENT_RETAIN_DAYS', 'type' => 'int', 'min' => 1, 'max' => 30, 'default' => '30', 'group' => 'Engagement', 'live' => false, 'secret' => false], // (max(1,min(30,...))); further capped by retain_days at runtime
        ];
    }

    /** @return array<string,array<string,mixed>> this instance's entries, key => entry */
    public function entries(): array
    {
        return $this->entries;
    }

    /** @return list<string> canonical keys, in schema order */
    public function keys(): array
    {
        return array_keys($this->entries);
    }

    public function has(string $key): bool
    {
        return isset($this->entries[$key]);
    }

    /** @return array<string,mixed>|null the entry for $key, or null */
    public function get(string $key): ?array
    {
        return $this->entries[$key] ?? null;
    }

    /** The canonical key seeded by env var $env, or null if $env is not a registered knob. */
    public function keyForEnv(string $env): ?string
    {
        return $this->byEnv[$env] ?? null;
    }

    /**
     * True when a stored override for $key is subject to the env-as-ceiling rule (FP-0250 2.3):
     * {@see ConfigStore} must reject/clamp a stored value less safe than the env baseline. Unknown key
     * ⇒ false (nothing to protect — validate() already rejects it elsewhere).
     */
    public function isProtected(string $key): bool
    {
        return (bool) ($this->entries[$key]['protected'] ?? false);
    }

    /**
     * The safety rank of $value for a protected+ORDERED knob: its index into `safety_order` (0 = least
     * safe, higher = safer). Null when $key is not protected, has no `safety_order` (protected+
     * unordered — a string with no notion of "safer", handled separately by the write/read paths), or
     * $value is not one of the listed values (a garbage/unknown value — the caller must treat this as
     * "no rank", never as rank 0, so a malformed value can never be silently treated as least-safe-but-
     * storable; {@see ConfigStore::protectedBaseline()} maps an unranked baseline to the SAFEST value).
     */
    public function safetyRank(string $key, string $value): ?int
    {
        $order = $this->entries[$key]['safety_order'] ?? null;
        if (!is_array($order)) {
            return null;
        }
        $i = array_search($value, $order, true);

        return $i === false ? null : (int) $i;
    }

    /**
     * Validate + coerce a raw admin/CLI input for one key. The write-side counterpart of the
     * clamps `AppConfig::build()` applies on read: enum/type violations are rejected (returned as an
     * error so `ConfigStore::set` can fail closed), numeric values are coerced and clamped to the
     * registered bounds (matching `fromEnv`'s clamp-don't-reject behaviour), bools are normalised to
     * '1'/'0'. The coerced value is always returned as a TEXT string (the store column is TEXT).
     *
     * @param mixed $raw
     * @return array{0:bool,1:string} [true, coercedString] | [false, errorMessage]
     */
    public function validate(string $key, $raw): array
    {
        $e = $this->entries[$key] ?? null;
        if ($e === null) {
            return [false, "unknown config key: {$key}"];
        }
        $type = (string) $e['type'];
        $s = is_bool($raw) ? ($raw ? '1' : '0') : (string) $raw;

        switch ($type) {
            case 'enum':
                $allowed = $e['enum'] ?? [];
                if (!in_array($s, $allowed, true)) {
                    return [false, "{$key}: value must be one of " . implode(', ', $allowed)];
                }

                return [true, $s];

            case 'bool':
                $t = strtolower(trim($s));
                if (in_array($t, ['1', 'on', 'true', 'yes'], true)) {
                    return [true, '1'];
                }
                if (in_array($t, ['0', 'off', 'false', 'no', ''], true)) {
                    return [true, '0'];
                }

                return [false, "{$key}: not a boolean ('{$s}')"];

            case 'int':
                if (!preg_match('/^-?\d+$/', trim($s))) {
                    return [false, "{$key}: not an integer ('{$s}')"];
                }
                $i = (int) trim($s);
                if (isset($e['min'])) {
                    $i = max((int) $e['min'], $i);
                }
                if (isset($e['max'])) {
                    $i = min((int) $e['max'], $i);
                }

                return [true, (string) $i];

            case 'float':
                if (!is_numeric(trim($s))) {
                    return [false, "{$key}: not a number ('{$s}')"];
                }
                $f = (float) trim($s);
                if (isset($e['min'])) {
                    $f = max((float) $e['min'], $f);
                }
                if (isset($e['max'])) {
                    $f = min((float) $e['max'], $f);
                }

                return [true, (string) $f];

            case 'csv':
                // Normalise: trim each item, drop empties (mirrors the array_filter(map trim) in fromEnv).
                $items = array_values(array_filter(array_map('trim', explode(',', $s)), static fn ($v) => $v !== ''));

                return [true, implode(',', $items)];

            case 'string':
            default:
                return [true, $s];
        }
    }
}

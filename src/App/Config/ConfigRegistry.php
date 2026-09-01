<?php

declare(strict_types=1);

namespace Funnypot\App\Config;

/**
 * The typed schema of every runtime-tunable config knob — the single source of truth for the
 * {@see ConfigStore} and (in FP-0242b) the admin UI. One entry per canonical key.
 *
 * IMPORTANT — this is a TRANSCRIPTION of the defaults and clamps already coded in
 * {@see AppConfig::fromEnv()} (which stays the seed + fallback). Each entry cites the
 * `AppConfig.php` source line it mirrors so a reviewer can diff the two by eye, and
 * ConfigRegistryTest asserts (by reflection over `AppConfig::__construct`) that the field set here
 * stays in sync with the value object. The env-only fields — filesystem paths, secrets/identity and
 * network topology — are deliberately NOT here (they stay env-sourced inside `fromStore`); the test
 * holds their allow-list.
 *
 * The `default` string is the ENV-level default (the literal `fromEnv` passes to `$str`), i.e. the
 * value seen when neither a stored override nor the env var is set. `poweredBy` is the one knob whose
 * effective default is derived at runtime (from the persona) rather than a literal; its registry
 * default is '' and the real default is resolved in `AppConfig::build()`.
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
            'mode' => ['field' => 'mode', 'env' => 'FUNNYPOT_MODE', 'type' => 'enum', 'enum' => ['public', 'stealth'], 'default' => 'public', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:186
            'style' => ['field' => 'style', 'env' => 'FUNNYPOT_STYLE', 'type' => 'enum', 'enum' => ['realistic', 'taunt', 'malformed'], 'default' => 'realistic', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:187
            'powered_by' => ['field' => 'poweredBy', 'env' => 'FUNNYPOT_POWERED_BY', 'type' => 'string', 'default' => '', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:192 (effective default is persona-derived, resolved in build())
            'severity_ceiling' => ['field' => 'severityCeiling', 'env' => 'FUNNYPOT_CEILING', 'type' => 'string', 'default' => 'critical', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:194 (free string in fromEnv; not clamped)
            'latency_ms' => ['field' => 'latencyMs', 'env' => 'FUNNYPOT_LATENCY_MS', 'type' => 'int', 'default' => '0', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:195 (no clamp)
            'jitter_ms' => ['field' => 'jitterMs', 'env' => 'FUNNYPOT_JITTER_MS', 'type' => 'int', 'default' => '40', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:196 (no clamp)
            'attack_emulation' => ['field' => 'attackEmulation', 'env' => 'FUNNYPOT_ATTACK', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:197
            'decoy_archive' => ['field' => 'decoyArchive', 'env' => 'FUNNYPOT_DECOY_ARCHIVE', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:198
            'dashboard_path' => ['field' => 'dashboardPath', 'env' => 'FUNNYPOT_DASHBOARD_PATH', 'type' => 'string', 'default' => '/__fp/', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:203 (build() normalises to /trim/)
            'funnypot_path' => ['field' => 'funnypotPath', 'env' => 'FUNNYPOT_APP_PATH', 'type' => 'string', 'default' => 'funnypot', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:204
            'hide_main_page' => ['field' => 'hideMainPage', 'env' => 'FUNNYPOT_HIDE_MAIN', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:205
            'capture_raw' => ['field' => 'captureRaw', 'env' => 'FUNNYPOT_CAPTURE_RAW', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Deception', 'live' => true, 'secret' => false], // AppConfig.php:206

            // --- Feature toggles (opt-in unless noted) — restart-required: each gates object construction at bootstrap (spec §4) ---
            'protocols_enabled' => ['field' => 'protocolsEnabled', 'env' => 'FUNNYPOT_PROTOCOLS', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:200
            'blocklist_enabled' => ['field' => 'blocklistEnabled', 'env' => 'FUNNYPOT_BLOCKLIST', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:207
            'abuseipdb_report' => ['field' => 'abuseIpdbReport', 'env' => 'FUNNYPOT_ABUSEIPDB_REPORT', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:211
            'threatintel_report' => ['field' => 'threatIntelReport', 'env' => 'FUNNYPOT_THREATINTEL_REPORT', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:216
            'llm_enabled' => ['field' => 'llmEnabled', 'env' => 'FUNNYPOT_LLM', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:221
            'ai_api_enabled' => ['field' => 'aiApiEnabled', 'env' => 'FUNNYPOT_AI_API', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:222
            'docker_api_enabled' => ['field' => 'dockerApiEnabled', 'env' => 'FUNNYPOT_DOCKER_API', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:223
            'endless_download' => ['field' => 'endlessDownload', 'env' => 'FUNNYPOT_ENDLESS_DOWNLOAD', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Features', 'live' => false, 'secret' => false], // AppConfig.php:256

            // --- LLM / fake-AI sampling + throttles (restart-required: baked into clients at bootstrap) ---
            'ai.strict_auth' => ['field' => 'aiStrictAuth', 'env' => 'FUNNYPOT_AI_STRICT_AUTH', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:224
            'ai.strict_model' => ['field' => 'aiStrictModel', 'env' => 'FUNNYPOT_AI_STRICT_MODEL', 'type' => 'bool', 'bool_style' => 'opt_in', 'default' => '0', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:225
            'ai.temp' => ['field' => 'aiTemp', 'env' => 'FUNNYPOT_AI_TEMP', 'type' => 'float', 'default' => '0.8', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:226 (no clamp)
            'ai.min_p' => ['field' => 'aiMinP', 'env' => 'FUNNYPOT_AI_MIN_P', 'type' => 'float', 'default' => '0.0', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:227 (no clamp)
            'ai.top_p' => ['field' => 'aiTopP', 'env' => 'FUNNYPOT_AI_TOP_P', 'type' => 'float', 'default' => '1.0', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:228 (no clamp)
            'ai.real_first' => ['field' => 'aiRealFirst', 'env' => 'FUNNYPOT_AI_REAL_FIRST', 'type' => 'int', 'min' => 0, 'default' => '5', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:229 (max(0,...))
            'ai.real_window_s' => ['field' => 'aiRealWindowS', 'env' => 'FUNNYPOT_AI_REAL_WINDOW_S', 'type' => 'int', 'min' => 1, 'default' => '600', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:230 (max(1,...))
            'llm.url' => ['field' => 'llmUrl', 'env' => 'FUNNYPOT_LLM_URL', 'type' => 'string', 'default' => 'http://funnypot-llm:8080/completion', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:231
            'llm.timeout_ms' => ['field' => 'llmTimeoutMs', 'env' => 'FUNNYPOT_LLM_TIMEOUT_MS', 'type' => 'int', 'min' => 200, 'default' => '9000', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:235 (max(200,...))
            'llm.n_predict' => ['field' => 'llmNPredict', 'env' => 'FUNNYPOT_LLM_N_PREDICT', 'type' => 'int', 'min' => 64, 'default' => '320', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:236 (max(64,...))
            'llm.cache_max_bytes' => ['field' => 'llmCacheMaxBytes', 'env' => 'FUNNYPOT_LLM_CACHE_MAX_BYTES', 'type' => 'int', 'default' => '0', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:238 (no clamp)
            'llm.max_concurrent' => ['field' => 'llmMaxConcurrent', 'env' => 'FUNNYPOT_LLM_MAX_CONCURRENT', 'type' => 'int', 'min' => 1, 'default' => '4', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:239 (max(1,...))
            'llm.prompt_version' => ['field' => 'llmPromptVersion', 'env' => 'FUNNYPOT_LLM_PROMPT_VERSION', 'type' => 'string', 'default' => 'v2', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:240
            'llm.breaker_threshold' => ['field' => 'llmBreakerThreshold', 'env' => 'FUNNYPOT_LLM_BREAKER_THRESHOLD', 'type' => 'int', 'min' => 1, 'default' => '5', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:241 (max(1,...))
            'llm.breaker_cooldown_s' => ['field' => 'llmBreakerCooldownS', 'env' => 'FUNNYPOT_LLM_BREAKER_COOLDOWN_S', 'type' => 'int', 'min' => 1, 'default' => '30', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:242 (max(1,...))
            'llm.velocity_per_60s' => ['field' => 'llmVelocityPer60s', 'env' => 'FUNNYPOT_LLM_VELOCITY_PER_60S', 'type' => 'int', 'min' => 1, 'default' => '5', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:243 (max(1,...))
            'llm.velocity_per_10m' => ['field' => 'llmVelocityPer10m', 'env' => 'FUNNYPOT_LLM_VELOCITY_PER_10M', 'type' => 'int', 'min' => 1, 'default' => '15', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:244 (max(1,...))
            'llm.gate_allow' => ['field' => 'llmGateAllowIps', 'env' => 'FUNNYPOT_LLM_GATE_ALLOW', 'type' => 'csv', 'default' => '', 'group' => 'LLM', 'live' => false, 'secret' => false], // AppConfig.php:245

            // --- Threat-intel / blocklist knobs (restart-required) ---
            'blocklist.min_lists' => ['field' => 'blocklistMinLists', 'env' => 'FUNNYPOT_BLOCKLIST_MIN_LISTS', 'type' => 'int', 'min' => 1, 'default' => '1', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // AppConfig.php:209 (max(1,...))
            'abuseipdb.daily_cap' => ['field' => 'abuseIpdbDailyCap', 'env' => 'FUNNYPOT_ABUSEIPDB_DAILY_CAP', 'type' => 'int', 'min' => 1, 'default' => '1000', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // AppConfig.php:214 (max(1,...))
            'abuseipdb.dedup_hours' => ['field' => 'abuseIpdbDedupHours', 'env' => 'FUNNYPOT_ABUSEIPDB_DEDUP_HOURS', 'type' => 'int', 'min' => 1, 'default' => '24', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // AppConfig.php:215 (max(1,...))
            'threatintel.url' => ['field' => 'threatIntelUrl', 'env' => 'FUNNYPOT_THREATINTEL_URL', 'type' => 'string', 'default' => 'https://threatintel.metrictower.com', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // AppConfig.php:217
            'threatintel.daily_cap' => ['field' => 'threatIntelDailyCap', 'env' => 'FUNNYPOT_THREATINTEL_DAILY_CAP', 'type' => 'int', 'min' => 1, 'default' => '1000', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // AppConfig.php:219 (max(1,...))
            'threatintel.dedup_hours' => ['field' => 'threatIntelDedupHours', 'env' => 'FUNNYPOT_THREATINTEL_DEDUP_HOURS', 'type' => 'int', 'min' => 1, 'default' => '24', 'group' => 'Threat-intel', 'live' => false, 'secret' => false], // AppConfig.php:220 (max(1,...))

            // --- Endless-download throttle knobs (restart-required: DownloadRouter ctor). Clamped both floor+ceiling. ---
            'dl.chunk_min_kb' => ['field' => 'dlChunkMinKb', 'env' => 'FUNNYPOT_DL_CHUNK_MIN_KB', 'type' => 'int', 'min' => 1, 'max' => 1024, 'default' => '100', 'group' => 'Download', 'live' => false, 'secret' => false], // AppConfig.php:257 (max(1,min(1024,...)))
            'dl.chunk_max_kb' => ['field' => 'dlChunkMaxKb', 'env' => 'FUNNYPOT_DL_CHUNK_MAX_KB', 'type' => 'int', 'min' => 1, 'max' => 1024, 'default' => '200', 'group' => 'Download', 'live' => false, 'secret' => false], // AppConfig.php:258 (max(1,min(1024,...)))
            'dl.interval_ms' => ['field' => 'dlIntervalMs', 'env' => 'FUNNYPOT_DL_INTERVAL_MS', 'type' => 'int', 'min' => 10, 'max' => 5000, 'default' => '100', 'group' => 'Download', 'live' => false, 'secret' => false], // AppConfig.php:259 (max(10,min(5000,...)))
            'dl.vary_pct' => ['field' => 'dlVaryPct', 'env' => 'FUNNYPOT_DL_VARY_PCT', 'type' => 'int', 'min' => 0, 'max' => 95, 'default' => '50', 'group' => 'Download', 'live' => false, 'secret' => false], // AppConfig.php:260 (max(0,min(95,...)))
            'dl.ease_period_s' => ['field' => 'dlEasePeriodS', 'env' => 'FUNNYPOT_DL_EASE_PERIOD_S', 'type' => 'int', 'min' => 1, 'max' => 600, 'default' => '20', 'group' => 'Download', 'live' => false, 'secret' => false], // AppConfig.php:261 (max(1,min(600,...)))
            'dl.fallback_cap_mb' => ['field' => 'dlFallbackCapMb', 'env' => 'FUNNYPOT_DL_FALLBACK_CAP_MB', 'type' => 'int', 'min' => 1, 'max' => 500, 'default' => '50', 'group' => 'Download', 'live' => false, 'secret' => false], // AppConfig.php:262 (max(1,min(500,...)))

            // --- Retention (separate CLI runner; picked up on its next timer pass) ---
            'retain_days' => ['field' => 'retainDays', 'env' => 'FUNNYPOT_RETAIN_DAYS', 'type' => 'int', 'default' => '0', 'group' => 'Retention', 'live' => false, 'secret' => false], // AppConfig.php:201 (no clamp)
            'retain_gb' => ['field' => 'retainGb', 'env' => 'FUNNYPOT_RETAIN_GB', 'type' => 'float', 'default' => '0', 'group' => 'Retention', 'live' => false, 'secret' => false], // AppConfig.php:202 (no clamp)

            // --- Analytics rollup worker (FP-0243; separate CLI runner, picked up next pass) ---
            'rollup.enabled' => ['field' => 'rollupEnabled', 'env' => 'FUNNYPOT_ROLLUP', 'type' => 'bool', 'bool_style' => 'on_unless_0', 'default' => '1', 'group' => 'Rollup', 'live' => false, 'secret' => false], // AppConfig.php:266
            'rollup.interval_s' => ['field' => 'rollupIntervalS', 'env' => 'FUNNYPOT_ROLLUP_INTERVAL', 'type' => 'int', 'min' => 1, 'default' => '15', 'group' => 'Rollup', 'live' => false, 'secret' => false], // AppConfig.php:267 (max(1,...))
            'rollup.batch' => ['field' => 'rollupBatch', 'env' => 'FUNNYPOT_ROLLUP_BATCH', 'type' => 'int', 'min' => 1, 'default' => '5000', 'group' => 'Rollup', 'live' => false, 'secret' => false], // AppConfig.php:268 (max(1,...))
            'rollup.top_k' => ['field' => 'rollupTopK', 'env' => 'FUNNYPOT_ROLLUP_TOPK', 'type' => 'int', 'min' => 1, 'default' => '20', 'group' => 'Rollup', 'live' => false, 'secret' => false], // AppConfig.php:269 (max(1,...))
            'rollup.retain_min_h' => ['field' => 'rollupRetainMinH', 'env' => 'FUNNYPOT_ROLLUP_RETAIN_MIN_H', 'type' => 'int', 'min' => 1, 'default' => '48', 'group' => 'Rollup', 'live' => false, 'secret' => false], // AppConfig.php:270 (max(1,...))
            'rollup.retain_hour_d' => ['field' => 'rollupRetainHourD', 'env' => 'FUNNYPOT_ROLLUP_RETAIN_HOUR_D', 'type' => 'int', 'min' => 1, 'default' => '30', 'group' => 'Rollup', 'live' => false, 'secret' => false], // AppConfig.php:271 (max(1,...))
            'rollup.retain_day_d' => ['field' => 'rollupRetainDayD', 'env' => 'FUNNYPOT_ROLLUP_RETAIN_DAY_D', 'type' => 'int', 'min' => 1, 'default' => '365', 'group' => 'Rollup', 'live' => false, 'secret' => false], // AppConfig.php:272 (max(1,...))
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

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\Core\Support\PersonaIdentity;
use Throwable;

/**
 * A1 — the bloated, deeply-nested config blob (FP-0245c context-polluter). A synthetic Django-style
 * `settings.py` front-loaded to pollute an AI agent's context: hundreds of lines of nested dicts,
 * per-region service variants, and commented-out "historical" credentials, so an agent that fetches
 * it early re-bills the whole blob on every later reasoning step (the fable R2 ★quadratic insight).
 *
 * Asymmetry + safety, exactly as the ticket demands:
 *   - STREAMED and O(section) memory: the body is fabricated section-by-section by {@see chunks()} and
 *     flushed, never materialised, so a worker's memory is O(one section) regardless of the cap.
 *   - HARD BYTE-CAPPED (BYTES_PER_RESP_MB): a "bloated" blob within a fixed byte budget — the pollution
 *     is in the SHAPE/tokenisation cost, not an unbounded body. connection_aborted() halts fabrication.
 *   - INERT + FINGERPRINT-CLEAN: every credential-shaped value is an {@see InertSecret} token (AWS/
 *     Stripe/reset shapes that authenticate to NOTHING) and the FLAG{...} honeytokens are dead strings;
 *     EVERY generated structural identifier (region/service slugs) is routed through the SAME
 *     {@see InertSecret::derive()} clean-gate, so no slug's digits can coincidentally spell a detector
 *     signature (e.g. a bare 6-digit CRS-rule id). Hostnames are persona-derived synthetic
 *     (.internal / example ranges), never a real host, ARN or third-party endpoint.
 *
 * Coherent with the rest of the deploy: values are drawn from the SAME persona seed the panel/labyrinth
 * use, so the company/db names line up across every fake surface (cross-kind coherence).
 */
final class ConfigDump
{
    public function __construct(private int $personaSeed)
    {
    }

    /**
     * Stream the settings.py through the emitter up to $capBytes, halting on client hang-up ($aborted,
     * injectable for tests; defaults to the real connection_aborted()) or at the wall-clock deadline
     * ({@see SeededStream::DEADLINE_MS} by default, so a slow reader can never hold the worker past the
     * TarpitBudget slot TTL). Returns bytes actually emitted, for the budget ledger. A fixed preamble
     * goes first, then generated sections until the cap or the deadline.
     *
     * The deadline check runs AFTER each section is emitted, so the overshoot is at most one section's
     * fabricate+emit time. It bounds FABRICATION time; a write blocked by a slow reader is bounded by
     * nginx's buffering and send timeouts, not by this check. Ending early yields a shorter body, never
     * a 500.
     *
     * @param callable():int|null   $aborted
     * @param int|null              $deadlineMs wall-clock budget for the whole stream (default SeededStream::DEADLINE_MS)
     * @param callable():float|null $now        monotonic clock in ms (tests inject a fake)
     */
    public function stream(StreamEmitter $e, int $capBytes, ?callable $aborted = null, ?int $deadlineMs = null, ?callable $now = null): int
    {
        $aborted ??= static fn (): int => connection_aborted();
        $now ??= SeededStream::clock();
        $deadlineMs ??= SeededStream::DEADLINE_MS;
        $start = $now();
        $sent = 0;
        foreach ($this->chunks($capBytes) as $chunk) {
            $e->chunk($chunk);
            $sent += strlen($chunk);
            if ($aborted() !== 0 || $now() - $start >= $deadlineMs) {
                break;
            }
        }

        return $sent;
    }

    /**
     * Yield the settings.py in byte-capped pieces (one preamble + one section per step). A \Generator so
     * tests drain it summing strlen() and discarding each piece — the honest O(section) memory measure.
     *
     * @return \Generator<int,string>
     */
    public function chunks(int $capBytes): \Generator
    {
        if ($capBytes <= 0) {
            return;
        }
        $sent = 0;
        $emit = function (string $piece) use (&$sent, $capBytes): \Generator {
            if ($sent >= $capBytes) {
                return;
            }
            if ($sent + strlen($piece) > $capBytes) {
                $piece = substr($piece, 0, $capBytes - $sent);
            }
            $sent += strlen($piece);
            yield $piece;
        };

        yield from $emit($this->preamble());
        $k = 0;
        while ($sent < $capBytes) {
            yield from $emit($this->section($k));
            $k++;
        }
    }

    /** The fixed header + a top-level nested DATABASES/CACHES block naming the coherent persona. */
    private function preamble(): string
    {
        $company = $this->persona('company.name', 'Internal');
        $domain = $this->persona('company.domain', 'internal.example');
        $dbName = $this->persona('db.name', 'app_db');
        $dbUser = $this->persona('db.user', 'app');
        $region = $this->persona('cloud.aws.region', 'us-east-1');
        $dbPass = InertSecret::resetToken($this->personaSeed, 'settings|db|password');
        $secret = InertSecret::resetToken($this->personaSeed, 'settings|django|secret_key');

        return "# -*- coding: utf-8 -*-\n"
            . "# {$company} platform settings (settings.py) — GENERATED, do not edit by hand.\n"
            . "# NOTE: historical per-region credentials retained below during the multi-region cutover.\n"
            . "import os\n\n"
            . "SECRET_KEY = '{$secret}'\n"
            . "DEBUG = False\n"
            . "ALLOWED_HOSTS = ['app.{$domain}', 'internal.{$domain}', '127.0.0.1']\n\n"
            . "DATABASES = {\n"
            . "    'default': {\n"
            . "        'ENGINE': 'django.db.backends.postgresql',\n"
            . "        'NAME': '{$dbName}',\n"
            . "        'USER': '{$dbUser}',\n"
            . "        'PASSWORD': '{$dbPass}',\n"
            . "        'HOST': 'db-primary.{$region}.internal',\n"
            . "        'PORT': '5432',\n"
            . "        'OPTIONS': {'sslmode': 'require', 'connect_timeout': 10},\n"
            . "    },\n"
            . "}\n\n"
            . "# ---- per-region service configuration (nested; kept for rollback) ----\n"
            . "REGIONS = {\n";
    }

    /**
     * One synthetic per-region nested config section, deterministic in (personaSeed, k). Deeply nested
     * dicts with commented "historical" credentials — every secret an inert FakeSecrets/FLAG token.
     */
    private function section(int $k): string
    {
        $slug = $this->slug('settings|slug|' . $k, 6);
        $region = $this->slug('settings|region-id|' . $k, 4);
        $domain = $this->persona('company.domain', 'internal.example');

        $apiKey = InertSecret::apiKey($this->personaSeed, 'settings|region|' . $k . '|aws');
        $stripe = InertSecret::stripeKey($this->personaSeed, 'settings|region|' . $k . '|stripe');
        $oldReset = InertSecret::resetToken($this->personaSeed, 'settings|region|' . $k . '|rotated');
        $flag = $this->flag($k);

        return "    'region-{$region}-{$slug}': {\n"
            . "        'BASE_URL': 'https://svc-{$slug}.{$region}.{$domain}',\n"
            . "        'CACHE': {\n"
            . "            'BACKEND': 'django_redis.cache.RedisCache',\n"
            . "            'LOCATION': 'redis://cache-{$slug}.{$region}.internal:6379/1',\n"
            . "            'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient', 'MAX_ENTRIES': 10000},\n"
            . "        },\n"
            . "        'AWS': {\n"
            . "            'ACCESS_KEY_ID': '{$apiKey}',\n"
            . "            'DEFAULT_REGION': '{$region}',\n"
            . "            # historical (rotated {$oldReset[0]}{$oldReset[1]}{$oldReset[2]}): 'SECRET_ACCESS_KEY': '{$oldReset}'\n"
            . "            'S3_BUCKET': 'assets-{$slug}-{$region}',\n"
            . "        },\n"
            . "        'BILLING': {\n"
            . "            'STRIPE_KEY': '{$stripe}',   # test mode, superseded — see vault\n"
            . "            'FEATURE_FLAGS': {'invoice_v2': True, 'dunning': False, 'proration': True},\n"
            . "        },\n"
            . "        # ops-flag: {$flag}\n"
            . "    },\n";
    }

    /**
     * A fixed-width lowercase-base36 slug (URL/host-safe, inert), deterministic in $key and routed
     * through the systemic clean-gate — so an all-digit slug that happens to read as a bare CRS rule id
     * (e.g. `943936`) is rejected and a clean variant re-derived. Fixed length across variants.
     */
    private function slug(string $key, int $len): string
    {
        $alpha = 'abcdefghijklmnopqrstuvwxyz0123456789';

        return InertSecret::derive($key, function (string $k) use ($alpha, $len): string {
            $h = hash('sha256', $this->personaSeed . '|slug|' . $k);
            $out = '';
            for ($i = 0; $i < $len; $i++) {
                $out .= $alpha[hexdec($h[$i * 2] . $h[$i * 2 + 1]) % 36];
            }

            return $out;
        });
    }

    /** A dead FLAG{...} honeytoken — a deterministic 32-hex string that unlocks nothing anywhere. */
    private function flag(int $k): string
    {
        return InertSecret::flag($this->personaSeed, 'config|' . $k);
    }

    private function persona(string $path, string $fallback): string
    {
        try {
            $v = PersonaIdentity::fromSeed($this->personaSeed)->field($path);

            return ($v !== null && $v !== '') ? $v : $fallback;
        } catch (Throwable $e) {
            return $fallback;
        }
    }
}

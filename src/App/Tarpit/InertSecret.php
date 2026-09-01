<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\Core\Support\Fake\FakeSecrets;

/**
 * Fingerprint-safe wrappers around {@see FakeSecrets} for the FP-0245c context-polluters.
 *
 * FakeSecrets values are inert (they authenticate to nothing) and safe against funnypot-core's own
 * bare-CRS pattern `\b9\d{5}\b` (which needs a word boundary on BOTH sides of the digit run — impossible
 * inside one long alnum run). But the APP-side denylist (resources/app-fingerprint-denylist.php) uses a
 * BROADER pattern, `(?<![#0-9a-fA-F])9\d{5}(?![0-9a-fA-F])\b`, whose leading lookbehind only excludes hex
 * characters. A FakeSecrets shape that contains non-hex letters (an AWS `AKIA…` key, a Stripe key, a
 * bcrypt hash) can therefore END in `…<non-hex-letter>9ddddd`, and when it sits flush against a JSON/YAML
 * delimiter the six trailing digits read as a CRS rule id — a false positive, but one the app's own
 * fingerprint gate (rightly) rejects.
 *
 * Rather than change the append-only denylist or emit a value that trips it, this picks a per-key VARIANT
 * that is clean: it re-derives the FakeSecrets value under `key`, `key|v1`, `key|v2`, … until the value
 * (checked inside delimiters, so a leading/trailing run is caught) matches NOTHING on the app denylist.
 * The result is still a genuine, correctly-shaped, per-(seed,key) inert FakeSecrets token — just one whose
 * digits don't coincidentally spell a detector signature. Deterministic: the same (seed,key) always yields
 * the same clean variant.
 */
final class InertSecret
{
    /** @var array{literals:list<string>,patterns:list<string>}|null */
    private static ?array $denylist = null;

    public static function apiKey(int $seed, string $key): string
    {
        return self::clean(static fn (string $k): string => FakeSecrets::apiKey($seed, $k), $key);
    }

    public static function stripeKey(int $seed, string $key): string
    {
        return self::clean(static fn (string $k): string => FakeSecrets::stripeKey($seed, $k), $key);
    }

    public static function resetToken(int $seed, string $key): string
    {
        return self::clean(static fn (string $k): string => FakeSecrets::resetToken($seed, $k), $key);
    }

    public static function bcryptHash(int $seed, string $key): string
    {
        return self::clean(static fn (string $k): string => FakeSecrets::bcryptHash($seed, $k), $key);
    }

    /** A dead FLAG{<32 hex>} honeytoken, also guaranteed clean against the app denylist. */
    public static function flag(int $seed, string $key): string
    {
        return self::clean(
            static fn (string $k): string => 'FLAG{' . substr(hash('sha256', $seed . '|flag|' . $k), 0, 32) . '}',
            $key
        );
    }

    /**
     * Re-derive under key variants until the value is fingerprint-clean (checked inside delimiters so a
     * boundary run is caught). Bounded loop: a fresh sha256-derived value trips the denylist with
     * vanishing probability, so this almost always returns on the first try; the cap is a safety net.
     *
     * @param callable(string):string $gen
     */
    private static function clean(callable $gen, string $key): string
    {
        for ($i = 0; $i < 64; $i++) {
            $k = $i === 0 ? $key : $key . '|v' . $i;
            $value = $gen($k);
            if (self::isClean('"' . $value . '"')) {
                return $value;
            }
        }

        return $gen($key); // unreachable in practice; return the base value rather than loop forever
    }

    private static function isClean(string $text): bool
    {
        $d = self::denylist();
        foreach ($d['literals'] as $needle) {
            if ($needle !== '' && stripos($text, $needle) !== false) {
                return false;
            }
        }
        foreach ($d['patterns'] as $pattern) {
            if (@preg_match('~' . $pattern . '~i', $text) === 1) {
                return false;
            }
        }

        return true;
    }

    /** @return array{literals:list<string>,patterns:list<string>} */
    private static function denylist(): array
    {
        if (self::$denylist !== null) {
            return self::$denylist;
        }
        $d = require dirname(__DIR__, 3) . '/resources/app-fingerprint-denylist.php';

        return self::$denylist = [
            'literals' => array_values((array) ($d['literals'] ?? [])),
            'patterns' => array_values((array) ($d['patterns'] ?? [])),
        ];
    }
}

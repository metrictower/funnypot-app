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
    /** @var array{literals:list<string>,patterns:list<string>,ownVocabularyPattern:string}|null */
    private static ?array $denylist = null;

    public static function apiKey(int $seed, string $key): string
    {
        return self::derive($key, static fn (string $k): string => FakeSecrets::apiKey($seed, $k));
    }

    public static function stripeKey(int $seed, string $key): string
    {
        return self::derive($key, static fn (string $k): string => FakeSecrets::stripeKey($seed, $k));
    }

    public static function resetToken(int $seed, string $key): string
    {
        return self::derive($key, static fn (string $k): string => FakeSecrets::resetToken($seed, $k));
    }

    public static function bcryptHash(int $seed, string $key): string
    {
        return self::derive($key, static fn (string $k): string => FakeSecrets::bcryptHash($seed, $k));
    }

    /** A dead FLAG{<32 hex>} honeytoken, also guaranteed clean against the app denylist. */
    public static function flag(int $seed, string $key): string
    {
        return self::derive(
            $key,
            static fn (string $k): string => 'FLAG{' . substr(hash('sha256', $seed . '|flag|' . $k), 0, 32) . '}'
        );
    }

    /**
     * The systemic clean-gate. Re-derive a value under key variants (`key`, `key|v1`, `key|v2`, …) until
     * it is fingerprint-clean, so ANY generated string that lands in a served body — a secret, a slug, a
     * filler hex token, a labyrinth id — can be forced clean the same way. $gen must be deterministic in
     * the key it is handed (so the chosen variant is stable). The value is checked inside delimiters, so a
     * digit run at either boundary is caught (the exact false-positive an `AKIA…`/base36/hex tail can hit
     * against the app's broadened bare-CRS pattern). Bounded loop: a fresh sha256-derived value trips the
     * denylist with vanishing probability, so this almost always returns on the first try.
     *
     * @param callable(string):string $gen
     */
    public static function derive(string $key, callable $gen): string
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

    /**
     * True if $text carries NO app-denylist signature (the same gate {@see derive()} enforces) — leak-IN
     * (literals/patterns) AND leak-OUT (own_vocabulary). Callers that already have a fixed, deterministic
     * value (e.g. a remapped token) use this to reject-and-retry in their own derivation loop. Wrap a bare
     * identifier in a boundary char (e.g. a space or quote) before calling if the served context places
     * one there.
     *
     * FP-0112 review #3: this used to check ONLY literals/patterns (leak-IN). A random base36 slug/region
     * id CAN, by pure chance, spell an own_vocabulary word — verified for real: ConfigDump's per-region
     * slug landed on the literal string `bait` at persona seed 4 (`region-bait-67vz4i`), because nothing
     * here rejected it. Every caller of {@see derive()} (ConfigDump's slug(), LogRabbitHole's hexToken(),
     * …) gets this systemically, no caller change needed.
     */
    public static function isClean(string $text): bool
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

        return $d['ownVocabularyPattern'] === '' || preg_match($d['ownVocabularyPattern'], $text) !== 1;
    }

    /** @return array{literals:list<string>,patterns:list<string>,ownVocabularyPattern:string} */
    private static function denylist(): array
    {
        if (self::$denylist !== null) {
            return self::$denylist;
        }
        $d = require dirname(__DIR__, 3) . '/resources/app-fingerprint-denylist.php';
        $ownVocabulary = array_values((array) ($d['own_vocabulary'] ?? []));

        return self::$denylist = [
            'literals' => array_values((array) ($d['literals'] ?? [])),
            'patterns' => array_values((array) ($d['patterns'] ?? [])),
            // Same delimiter-safe, whole-token construction as FingerprintSafetyTest::ownVocabularyPattern()
            // (digits stay word characters — see that method's doc comment for why).
            'ownVocabularyPattern' => $ownVocabulary === []
                ? ''
                : '/(?<![a-zA-Z0-9])(' . implode('|', $ownVocabulary) . ')(?![a-zA-Z0-9])/i',
        ];
    }
}

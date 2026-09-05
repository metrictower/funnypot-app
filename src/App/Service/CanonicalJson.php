<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use InvalidArgumentException;

/**
 * The app's one canonical JSON writer for hashed service-exposure artifacts. The bytes — not
 * json_encode()'s implementation behaviour — are the contract: the same facts always serialize to
 * the same bytes, so a content-derived generation/hash can be compared byte-for-byte across a
 * preparer, a supervisor, a downstream projection and a test.
 *
 * The canonical form is: object keys sorted by unsigned byte order (keys must be ASCII), array
 * element order preserved, UTF-8 strings, non-negative base-10 integers with no leading zero, JSON
 * booleans and null, minimal JSON escaping (only what JSON requires), no insignificant whitespace,
 * no floats, and exactly one trailing LF. {@see encode()} throws on a float, invalid UTF-8, a
 * non-ASCII object key or an unrepresentable value; {@see digest()} is a domain-separated SHA-256
 * over those bytes.
 *
 * This class is consumed by name across the runtime-policy cluster (FP-0319 binds a projection to
 * the digest of an artifact these bytes produce), so it is public and has golden-byte tests of its
 * own; do not fold it into a private method of a manifest class.
 */
final class CanonicalJson
{
    /**
     * Serialize $value to the canonical bytes described above (with the single trailing LF).
     *
     * @param array<array-key,mixed> $value
     * @throws InvalidArgumentException on a float, invalid UTF-8, a non-ASCII key or an unrepresentable value
     */
    public static function encode(array $value): string
    {
        $normalized = self::normalize($value);
        $json = json_encode($normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        return $json . "\n";
    }

    /**
     * Domain-separated digest of the canonical bytes: lowerhex(SHA256(domain || "\0" || encode(payload))).
     * The NUL keeps a chosen domain from being forged out of another payload's leading bytes.
     *
     * @param array<array-key,mixed> $payload
     */
    public static function digest(string $domain, array $payload): string
    {
        return hash('sha256', $domain . "\0" . self::encode($payload));
    }

    /**
     * Recursively validate + canonicalize: lists keep order, maps sort keys by byte order, scalars are
     * checked. Returns a structure json_encode renders to the canonical bytes.
     *
     * @param array<array-key,mixed> $value
     * @return array<array-key,mixed>
     */
    private static function normalize(array $value): array
    {
        if (array_is_list($value)) {
            $out = [];
            foreach ($value as $item) {
                $out[] = self::normalizeValue($item);
            }

            return $out;
        }

        // Object: keys must be ASCII strings; sort by unsigned byte order (ASCII => plain strcmp).
        $keys = array_keys($value);
        foreach ($keys as $k) {
            if (!is_string($k)) {
                throw new InvalidArgumentException('canonical json: object keys must be strings');
            }
            if (preg_match('/^[\x00-\x7f]*$/', $k) !== 1) {
                throw new InvalidArgumentException('canonical json: object key is not ASCII');
            }
        }
        usort($keys, static fn (string $a, string $b): int => strcmp($a, $b));
        $out = [];
        foreach ($keys as $k) {
            $out[$k] = self::normalizeValue($value[$k]);
        }

        return $out;
    }

    /** @param mixed $item @return mixed */
    private static function normalizeValue($item)
    {
        if (is_array($item)) {
            return self::normalize($item);
        }
        if (is_float($item)) {
            throw new InvalidArgumentException('canonical json: floats are not representable');
        }
        if (is_int($item)) {
            if ($item < 0) {
                throw new InvalidArgumentException('canonical json: integers must be non-negative');
            }

            return $item;
        }
        if (is_bool($item) || $item === null) {
            return $item;
        }
        if (is_string($item)) {
            if (!mb_check_encoding($item, 'UTF-8')) {
                throw new InvalidArgumentException('canonical json: string is not valid UTF-8');
            }

            return $item;
        }

        throw new InvalidArgumentException('canonical json: unrepresentable value of type ' . gettype($item));
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use InvalidArgumentException;

/**
 * Personal access tokens, OAuth access tokens and OAuth refresh tokens:
 *
 *   <p>_<kind>_<base62(k8 ‖ acct u8 ‖ serial u8 ‖ mac13)>
 *
 * <p> is 2–4 letters of the persona's company slug and kind is pat|oat|ort. The body is always 31
 * base62 characters. The 13-byte MAC binds the kind and the three addressing fields to a caller-held
 * binding string (the row epoch, the account's and token's lifetime serials and the clean variant),
 * so a token stays valid only while the state that minted it still holds it: a revoked or evicted
 * entry, or a wrapped serial, can never make an old string verify again.
 *
 * Scopes, expiry and status are never in the token; they come from state, so revocation works.
 */
final class TokenCodec
{
    public const KINDS = ['pat', 'oat', 'ort'];
    public const SHAPE = '/\A([a-z]{2,4})_(pat|oat|ort)_([0-9A-Za-z]{31})\z/';

    /** Prefixes real providers use; a persona prefix never equals one. */
    public const VENDOR_PREFIXES = ['ghp', 'gho', 'ghu', 'ghs', 'ghr', 'github', 'glpat', 'xox', 'xoxb', 'xoxp', 'sk', 'pk', 'rk', 'npm', 'pypi', 'hf', 'dop', 'shpat', 'akia'];

    private const BODY_BYTES = 23;
    private const BODY_CHARS = 31;
    private const MAC_BYTES = 13;
    private const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    public function __construct(private string $key, private string $prefix)
    {
        if (preg_match('/\A[a-z]{2,4}\z/', $prefix) !== 1 || in_array($prefix, self::VENDOR_PREFIXES, true)) {
            throw new InvalidArgumentException('bad token prefix');
        }
    }

    /** The persona prefix for a company slug: its first three letters, nudged off any vendor prefix. */
    public static function prefixFor(string $slug): string
    {
        $letters = (string) preg_replace('/[^a-z]/', '', strtolower($slug));
        $letters = str_pad($letters, 4, 'x');
        $p = substr($letters, 0, 3);
        if (in_array($p, self::VENDOR_PREFIXES, true) || in_array(substr($p, 0, 2), self::VENDOR_PREFIXES, true)) {
            $p = $letters[0] . $letters[2] . $letters[3];
        }

        return $p;
    }

    public function prefix(): string
    {
        return $this->prefix;
    }

    /** @param string $k8 the 8 raw bytes addressing the source row */
    public function encode(string $kind, string $k8, int $acct, int $serial, string $bind): string
    {
        if (!in_array($kind, self::KINDS, true) || strlen($k8) !== 8) {
            throw new InvalidArgumentException('bad token fields');
        }
        $head = $k8 . chr($acct & 0xff) . chr($serial & 0xff);
        $mac = substr(hash_hmac('sha256', $kind . "\0" . $head . "\0" . $bind, $this->key, true), 0, self::MAC_BYTES);

        return $this->prefix . '_' . $kind . '_' . self::toBase62($head . $mac);
    }

    /**
     * Shape-check and split a presented token. Pure grammar: no MAC check yet, because the binding
     * comes from state. Anything off-shape is null.
     *
     * @return array{kind:string,k8:string,acct:int,serial:int,mac:string}|null
     */
    public function decode(string $token): ?array
    {
        if (strlen($token) > 64 || preg_match(self::SHAPE, $token, $m) !== 1 || $m[1] !== $this->prefix) {
            return null;
        }
        $raw = self::fromBase62($m[3]);
        if ($raw === null) {
            return null;
        }

        return [
            'kind' => $m[2],
            'k8' => substr($raw, 0, 8),
            'acct' => ord($raw[8]),
            'serial' => ord($raw[9]),
            'mac' => substr($raw, 10, self::MAC_BYTES),
        ];
    }

    /** @param array{kind:string,k8:string,acct:int,serial:int,mac:string} $d */
    public function verify(array $d, string $bind): bool
    {
        $head = $d['k8'] . chr($d['acct']) . chr($d['serial']);
        $mac = substr(hash_hmac('sha256', $d['kind'] . "\0" . $head . "\0" . $bind, $this->key, true), 0, self::MAC_BYTES);

        return hash_equals($mac, $d['mac']);
    }

    private static function toBase62(string $bytes): string
    {
        $digits = array_values((array) unpack('C*', $bytes));
        $out = '';
        while ($digits !== []) {
            $rem = 0;
            $next = [];
            foreach ($digits as $d) {
                $acc = $rem * 256 + $d;
                $q = intdiv($acc, 62);
                $rem = $acc % 62;
                if ($next !== [] || $q > 0) {
                    $next[] = $q;
                }
            }
            $out = self::ALPHABET[$rem] . $out;
            $digits = $next;
        }

        return str_pad($out, self::BODY_CHARS, '0', STR_PAD_LEFT);
    }

    private static function fromBase62(string $chars): ?string
    {
        $num = [];
        $len = strlen($chars);
        for ($i = 0; $i < $len; $i++) {
            $carry = strpos(self::ALPHABET, $chars[$i]);
            if ($carry === false) {
                return null;
            }
            for ($j = count($num) - 1; $j >= 0; $j--) {
                $acc = $num[$j] * 62 + $carry;
                $num[$j] = $acc & 0xff;
                $carry = $acc >> 8;
            }
            while ($carry > 0) {
                array_unshift($num, $carry & 0xff);
                $carry >>= 8;
            }
        }
        if (count($num) > self::BODY_BYTES) {
            return null;
        }
        $raw = str_repeat("\0", self::BODY_BYTES - count($num)) . ($num === [] ? '' : pack('C*', ...$num));

        // Canonical only: a body that does not re-encode to itself is a different spelling.
        return self::toBase62($raw) === $chars ? $raw : null;
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * Reads a fetch URL the way curl and the WHATWG URL parser agree on, in one bounded linear pass.
 *
 * The authority ends at the first `/`, `?` or `#`, and the host follows the last `@` in it, so
 * `http://127.0.0.1:80@listener.tld/` names listener.tld and `http://listener.tld#@127.0.0.1/` does
 * too. A host whose last label is a number is an IPv4 address in any spelling (`2130706433`,
 * `0x7f000001`, `017700000001`, `127.1`, `0`), canonicalised to dotted form; a bracketed host is IPv6.
 * Anything else is a name. Nothing here resolves a name or opens a connection.
 *
 * check() returns [Target, null] or [null, reason]. Reasons are a closed set: length, charset,
 * control, scheme, syntax, host, port.
 */
final class TargetParser
{
    public const MAX_URL = 512;

    private const ALLOWED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:/?#@!$&\'()*+,;=%-[]';

    /** Query names whose values are credentials (SigV4 and SigV2), masked wherever a URL is stored or shown. */
    public const MASKED_QUERY = ['x-amz-credential', 'x-amz-signature', 'x-amz-security-token', 'signature', 'awsaccesskeyid', 'securitytoken'];

    /** @var array<string,true>|null */
    private static ?array $allowed = null;

    /** @return array{0:?Target,1:?string} */
    public static function check(string $url, ?int &$steps = null): array
    {
        $steps = 0;
        $len = strlen($url);
        if ($len === 0 || $len > self::MAX_URL) {
            return [null, 'length'];
        }
        self::$allowed ??= array_fill_keys(str_split(self::ALLOWED), true);
        for ($i = 0; $i < $len; $i++) {
            $steps++;
            if (!isset(self::$allowed[$url[$i]])) {
                return [null, 'charset'];
            }
            if ($url[$i] === '%') {
                if ($i + 2 >= $len || !ctype_xdigit(substr($url, $i + 1, 2))) {
                    return [null, 'syntax'];
                }
                $byte = hexdec(substr($url, $i + 1, 2));
                if ($byte < 0x20 || $byte === 0x7f) {
                    return [null, 'control'];
                }
            }
        }
        $colon = strpos($url, ':');
        if ($colon === false || $colon === 0 || preg_match('/\A[A-Za-z][A-Za-z0-9+.-]{0,15}\z/', substr($url, 0, $colon)) !== 1) {
            return [null, 'syntax'];
        }
        $scheme = strtolower(substr($url, 0, $colon));
        if ($scheme !== 'http' && $scheme !== 'https') {
            return [null, 'scheme'];
        }
        if (substr($url, $colon + 1, 2) !== '//') {
            return [null, 'syntax'];
        }
        $rest = substr($url, $colon + 3);
        $authLen = strcspn($rest, '/?#');
        $steps += $authLen;
        $authority = substr($rest, 0, $authLen);
        $tail = substr($rest, $authLen);
        $at = strrpos($authority, '@');
        $userinfo = $at === false ? null : substr($authority, 0, $at);
        $hostPort = $at === false ? $authority : substr($authority, $at + 1);
        if (($userinfo !== null && strpbrk($userinfo, '[]') !== false) || strpbrk($tail, '[]') !== false) {
            return [null, 'charset'];
        }
        [$hostRaw, $portText, $bad] = self::splitHostPort($hostPort);
        if ($bad !== null) {
            return [null, $bad];
        }
        $port = $scheme === 'https' ? 443 : 80;
        if ($portText !== '') {
            if (strlen($portText) > 5 || !ctype_digit($portText) || (int) $portText < 1 || (int) $portText > 65535) {
                return [null, 'port'];
            }
            $port = (int) $portText;
        }
        $host = self::host($hostRaw, $steps);
        if ($host === null) {
            return [null, 'host'];
        }
        [$canonical, $kind, $ipv4, $ipv6] = $host;
        $pathLen = strcspn($tail, '?#');
        $path = substr($tail, 0, $pathLen);
        $query = '';
        if (($tail[$pathLen] ?? '') === '?') {
            $q = substr($tail, $pathLen + 1);
            $query = substr($q, 0, strcspn($q, '#'));
        }
        $user = null;
        $pass = null;
        if ($userinfo !== null) {
            $c = strpos($userinfo, ':');
            $user = rawurldecode($c === false ? $userinfo : substr($userinfo, 0, $c));
            $pass = $c === false ? null : rawurldecode(substr($userinfo, $c + 1));
        }

        return [new Target($scheme, $hostRaw, $canonical, $kind, $ipv4, $ipv6, $port, $path === '' ? '/' : $path, $query, $user, $pass), null];
    }

    public static function parse(string $url): ?Target
    {
        return self::check($url)[0];
    }

    /** @return array{0:string,1:string,2:?string} [host, port text, error] */
    private static function splitHostPort(string $hp): array
    {
        if ($hp === '') {
            return ['', '', 'host'];
        }
        if ($hp[0] === '[') {
            $close = strpos($hp, ']');
            if ($close === false) {
                return ['', '', 'host'];
            }
            $after = substr($hp, $close + 1);
            if ($after !== '' && $after[0] !== ':') {
                return ['', '', 'host'];
            }

            return [substr($hp, 0, $close + 1), $after === '' ? '' : substr($after, 1), null];
        }
        if (strpbrk($hp, '[]') !== false) {
            return ['', '', 'charset'];
        }
        $c = strrpos($hp, ':');
        if ($c === false) {
            return [$hp, '', null];
        }

        return [substr($hp, 0, $c), substr($hp, $c + 1), null];
    }

    /** @return array{0:string,1:string,2:?int,3:?string}|null [canonical, kind, ipv4, ipv6 binary] */
    private static function host(string $raw, int &$steps): ?array
    {
        if ($raw === '') {
            return null;
        }
        if ($raw[0] === '[') {
            $inner = substr($raw, 1, -1);
            $pct = strpos($inner, '%25');
            if ($pct !== false) {
                $zone = substr($inner, $pct + 3);
                if ($zone === '' || preg_match('/\A[A-Za-z0-9._~-]{1,32}\z/', $zone) !== 1) {
                    return null;
                }
                $inner = substr($inner, 0, $pct);
            }
            $steps += strlen($inner);
            if (!str_contains($inner, ':') || preg_match('/\A[0-9A-Fa-f:.]{2,45}\z/', $inner) !== 1) {
                return null;
            }
            $bin = inet_pton($inner);
            if ($bin === false || strlen($bin) !== 16) {
                return null;
            }

            return ['[' . inet_ntop($bin) . ']', 'ipv6', null, $bin];
        }
        $name = strtolower(rawurldecode($raw));
        $steps += strlen($name);
        if (substr($name, -1) === '.') {
            $name = substr($name, 0, -1);
        }
        if ($name === '' || strlen($name) > 253 || preg_match('/\A[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*\z/', $name) !== 1) {
            return null;
        }
        $labels = explode('.', $name);
        $last = $labels[count($labels) - 1];
        if (ctype_digit($last) || preg_match('/\A0x[0-9a-f]*\z/', $last) === 1) {
            $ip = self::ipv4($labels, $steps);

            return $ip === null ? null : [Target::dotted($ip), 'ipv4', $ip, null];
        }

        return [$name, 'name', null, null];
    }

    /**
     * The inet_aton reading of a numeric host: one to four parts, each decimal, 0x-hex or 0-octal,
     * the last part filling the remaining bytes.
     *
     * @param list<string> $labels
     */
    private static function ipv4(array $labels, int &$steps): ?int
    {
        $n = count($labels);
        if ($n > 4) {
            return null;
        }
        $parts = [];
        foreach ($labels as $l) {
            $steps += strlen($l);
            if ($l === '' || strlen($l) > 63) {
                return null;
            }
            // Leading zeros carry no value, so they never count toward the overflow bound below.
            if (str_starts_with($l, '0x')) {
                $hex = ltrim(substr($l, 2), '0');
                if (strlen($hex) > 8) {
                    return null;
                }
                if ($hex !== '' && !ctype_xdigit($hex)) {
                    return null;
                }
                $parts[] = $hex === '' ? 0 : (int) hexdec($hex);
            } elseif (strlen($l) > 1 && $l[0] === '0') {
                if (preg_match('/\A[0-7]+\z/', $l) !== 1 || strlen(ltrim($l, '0')) > 11) {
                    return null;
                }
                $parts[] = (int) octdec($l);
            } elseif (ctype_digit($l)) {
                if (strlen($l) > 10) {
                    return null;
                }
                $parts[] = (int) $l;
            } else {
                return null;
            }
        }
        $ip = 0;
        for ($i = 0; $i < $n - 1; $i++) {
            if ($parts[$i] > 255) {
                return null;
            }
            $ip = ($ip << 8) | $parts[$i];
        }
        $lastBits = 8 * (5 - $n);
        if ($parts[$n - 1] >= (1 << $lastBits)) {
            return null;
        }

        return ($ip << $lastBits) | $parts[$n - 1];
    }

    /**
     * The URL as stored and shown: userinfo replaced by `***`, and the value of every credential-bearing
     * query parameter, in every pair, replaced by `***`. Everything else stays as written. Masking can
     * lengthen a URL slightly, so a caller that stores the result checks it still fits MAX_URL.
     */
    public static function mask(string $url): string
    {
        $colon = strpos($url, '://');
        if ($colon === false) {
            return $url;
        }
        $head = substr($url, 0, $colon + 3);
        $rest = substr($url, $colon + 3);
        $authLen = strcspn($rest, '/?#');
        $authority = substr($rest, 0, $authLen);
        $tail = substr($rest, $authLen);
        $at = strrpos($authority, '@');
        if ($at !== false) {
            $authority = '***@' . substr($authority, $at + 1);
        }
        $q = strpos($tail, '?');
        if ($q !== false) {
            $hash = strpos($tail, '#', $q);
            $query = $hash === false ? substr($tail, $q + 1) : substr($tail, $q + 1, $hash - $q - 1);
            $pairs = explode('&', $query);
            foreach ($pairs as $i => $pair) {
                $eq = strpos($pair, '=');
                $name = strtolower(rawurldecode($eq === false ? $pair : substr($pair, 0, $eq)));
                if ($eq !== false && in_array($name, self::MASKED_QUERY, true)) {
                    $pairs[$i] = substr($pair, 0, $eq) . '=***';
                }
            }
            $tail = substr($tail, 0, $q + 1) . implode('&', $pairs) . ($hash === false ? '' : substr($tail, $hash));
        }

        return $head . $authority . $tail;
    }

    /**
     * The query's name/value pairs (names lowercased), first occurrence of each name, without any warning.
     * A URL is at most MAX_URL bytes, so this is at most 256 pairs.
     *
     * @return array<string,string>
     */
    public static function queryPairs(string $query): array
    {
        $out = [];
        if ($query === '') {
            return $out;
        }
        foreach (explode('&', $query) as $pair) {
            $eq = strpos($pair, '=');
            $name = strtolower(rawurldecode($eq === false ? $pair : substr($pair, 0, $eq)));
            if ($name !== '' && !isset($out[$name])) {
                $out[$name] = $eq === false ? '' : rawurldecode(str_replace('+', ' ', substr($pair, $eq + 1)));
            }
        }

        return $out;
    }
}

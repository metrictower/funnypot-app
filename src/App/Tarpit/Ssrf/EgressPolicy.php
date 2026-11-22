<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * Where a fetch worker's request would go, as a pure function of the target, the request source and
 * the worker's role.
 *
 * The platform's workers reach the company's internal zones and private address space directly; every
 * other destination goes through an egress proxy that checks the hostname against the role's
 * allowlist before resolving it, and denies everything not on it (the hook and storage workers have
 * an empty allowlist; the import worker may reach github.com:443). So an attacker-observable target
 * (its own listener, its DNS server, a rebinding name, any public address) fails before a byte could
 * reach it, whatever its DNS says.
 *
 * Classes, checked in order: denylisted, loopback, metadata, internal (a name the internal resolver
 * answers), proxied, code_host, unroutable, source (the request source's own /24 on a private network:
 * no route back to it), private (a private IPv4 literal the directory or the generated subnet may
 * claim), private_other.
 */
final class EgressPolicy
{
    public const CODE_HOST = 'github.com';

    public function __construct(private string $domain)
    {
    }

    /**
     * The naive create-time denylist: only the literal spellings a quick filter would catch. Every
     * other spelling of the same address passes and is answered as what it denotes.
     */
    public static function denylisted(Target $t): bool
    {
        $raw = strtolower($t->hostRaw);

        return $raw === 'localhost' || $raw === '[::1]' || $raw === '0.0.0.0'
            || preg_match('/\A(?:127\.\d{1,3}|169\.254)\.\d{1,3}\.\d{1,3}\z/', $raw) === 1;
    }

    public function classify(Target $t, string $sourceIp, Role $role, bool $denylist = false): string
    {
        if ($denylist && self::denylisted($t)) {
            return 'denylisted';
        }
        if ($t->kind === 'name') {
            return $this->name($t, $role);
        }
        if ($t->kind === 'ipv4') {
            return $this->ipv4((int) $t->ipv4, $sourceIp);
        }

        return $this->ipv6((string) $t->ipv6, $sourceIp);
    }

    private function name(Target $t, Role $role): string
    {
        $h = $t->host;
        if ($h === 'localhost' || str_ends_with($h, '.localhost')) {
            return 'loopback';
        }
        if ($h === 'instance-data' || $h === 'instance-data.ec2.internal') {
            return 'metadata';
        }
        // The company's public site is served from outside, like any public name.
        if ($this->domain !== '' && ($h === $this->domain || $h === 'www.' . $this->domain)) {
            return 'proxied';
        }
        if (!str_contains($h, '.') || str_ends_with($h, '.internal')
            || ($this->domain !== '' && ($h === $this->domain || str_ends_with($h, '.' . $this->domain)))) {
            return 'internal';
        }
        if ($role === Role::Import && $h === self::CODE_HOST && $t->port === 443 && $t->scheme === 'https') {
            return 'code_host';
        }

        return 'proxied';
    }

    private function ipv4(int $ip, string $sourceIp): string
    {
        $a = $ip >> 24;
        if ($ip === 0 || $a === 127) {
            return 'loopback';
        }
        if ($a === 0 || $a >= 224 || $ip === 0xffffffff) {
            return 'unroutable';
        }
        if ($ip === 0xa9fea9fe) {
            return 'metadata';
        }
        $src = self::sourceV4($sourceIp);
        if ($src !== null && self::privateV4($src) && self::privateV4($ip) && ($src >> 8) === ($ip >> 8)) {
            return 'source';
        }
        if (self::rfc1918($ip)) {
            return 'private';
        }
        if (self::privateV4($ip)) {
            return 'private_other';
        }

        return 'proxied';
    }

    private function ipv6(string $bin, string $sourceIp): string
    {
        if ($bin === str_repeat("\0", 15) . "\1" || $bin === str_repeat("\0", 16)) {
            return 'loopback';
        }
        if (substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            return $this->ipv4((int) unpack('N', substr($bin, 12, 4))[1], $sourceIp);
        }
        if ($bin === "\xfd\x00\x0e\xc2" . str_repeat("\0", 10) . "\x02\x54") {
            return 'metadata';
        }
        $first = ord($bin[0]);
        if (($first & 0xfe) === 0xfc) {
            $src = filter_var($sourceIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? inet_pton($sourceIp) : false;
            if (is_string($src) && strlen($src) === 16 && substr($src, 0, 8) === substr($bin, 0, 8)) {
                return 'source';
            }

            return 'private_other';
        }
        if ($first === 0xfe && (ord($bin[1]) & 0xc0) === 0x80) {
            return 'private_other';
        }

        return 'proxied';
    }

    private static function sourceV4(string $ip): ?int
    {
        if (preg_match('/\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/', $ip, $m) !== 1) {
            return null;
        }
        foreach ([1, 2, 3, 4] as $i) {
            if ((int) $m[$i] > 255) {
                return null;
            }
        }

        return ((int) $m[1] << 24) | ((int) $m[2] << 16) | ((int) $m[3] << 8) | (int) $m[4];
    }

    public static function rfc1918(int $ip): bool
    {
        return ($ip >> 24) === 10 || ($ip >> 20) === 0xac1 || ($ip >> 16) === 0xc0a8;
    }

    /** RFC 1918, CGNAT and link-local space. */
    public static function privateV4(int $ip): bool
    {
        return self::rfc1918($ip) || ($ip >> 22) === (100 << 2 | 1) || ($ip >> 16) === 0xa9fe;
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

/**
 * IP membership testing (FP-0247, Fixes C/J): exact match plus CIDR containment, for IPv4 and IPv6.
 *
 * Used to widen the self-guard from a single exact egress IP to whole ranges (a honeypot behind
 * shared NAT/CGNAT shares its public range with innocent tenants) and to match curated benign-scanner
 * CIDRs. Every guard built on this is fail-closed: an entry can only ever SUPPRESS a report.
 */
final class IpMatcher
{
    /**
     * True if $ip equals any entry, or falls inside any CIDR entry, in $ipsOrCidrs.
     *
     * @param array<int,string> $ipsOrCidrs exact IPs and/or CIDRs (mixed v4/v6)
     */
    public static function matches(string $ip, array $ipsOrCidrs): bool
    {
        if ($ip === '') {
            return false;
        }
        foreach ($ipsOrCidrs as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            if ($entry === $ip) {
                return true;
            }
            if (strpos($entry, '/') !== false && self::inCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    /** IPv4 or IPv6 CIDR containment. A mixed-family or malformed pair never matches (fail-closed). */
    public static function inCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2 || !ctype_digit($parts[1])) {
            return false;
        }
        $net = $parts[0];
        $bits = (int) $parts[1];

        // IPv4.
        $ipL = ip2long($ip);
        $netL = ip2long($net);
        if ($ipL !== false && $netL !== false) {
            if ($bits > 32) {
                return false;
            }
            if ($bits === 0) {
                return true;
            }
            $mask = (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;

            return (($ipL & 0xFFFFFFFF) & $mask) === (($netL & 0xFFFFFFFF) & $mask);
        }

        // IPv6.
        $ipB = @inet_pton($ip);
        $netB = @inet_pton($net);
        if ($ipB !== false && $netB !== false && strlen($ipB) === 16 && strlen($netB) === 16) {
            if ($bits > 128) {
                return false;
            }
            $whole = intdiv($bits, 8);
            $rem = $bits % 8;
            if ($whole > 0 && strncmp($ipB, $netB, $whole) !== 0) {
                return false;
            }
            if ($rem !== 0) {
                $maskByte = (~0 << (8 - $rem)) & 0xFF;

                return (ord($ipB[$whole]) & $maskByte) === (ord($netB[$whole]) & $maskByte);
            }

            return true;
        }

        return false;   // mixed family or invalid input
    }
}

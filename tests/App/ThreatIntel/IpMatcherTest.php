<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\ThreatIntel;

use Funnypot\App\ThreatIntel\IpMatcher;
use PHPUnit\Framework\TestCase;

/**
 * IP membership math (FP-0247, Fixes C/J): exact + CIDR containment, IPv4 and IPv6, fail-closed on a
 * mixed family or malformed input.
 */
final class IpMatcherTest extends TestCase
{
    public function test_exact_match(): void
    {
        self::assertTrue(IpMatcher::matches('203.0.113.9', ['203.0.113.9']));
        self::assertFalse(IpMatcher::matches('203.0.113.10', ['203.0.113.9']));
        self::assertTrue(IpMatcher::matches('2001:db8::1', ['2001:db8::1']));
    }

    public function test_ipv4_cidr_containment_and_boundaries(): void
    {
        $set = ['203.0.113.0/24', '198.51.100.128/25'];
        self::assertTrue(IpMatcher::matches('203.0.113.0', $set));     // network
        self::assertTrue(IpMatcher::matches('203.0.113.255', $set));   // broadcast
        self::assertFalse(IpMatcher::matches('203.0.114.0', $set));    // just outside
        self::assertTrue(IpMatcher::matches('198.51.100.200', $set));  // upper /25 half
        self::assertFalse(IpMatcher::matches('198.51.100.10', $set));  // lower half, outside
    }

    public function test_slash_zero_matches_all_ipv4(): void
    {
        self::assertTrue(IpMatcher::inCidr('8.8.8.8', '0.0.0.0/0'));
    }

    public function test_ipv6_cidr_containment(): void
    {
        self::assertTrue(IpMatcher::inCidr('2001:db8::1', '2001:db8::/32'));
        self::assertTrue(IpMatcher::inCidr('2001:db8:ffff::1', '2001:db8::/32'));
        self::assertFalse(IpMatcher::inCidr('2001:db9::1', '2001:db8::/32'));
        self::assertTrue(IpMatcher::inCidr('2001:db8::abcd', '2001:db8::ab00/120'));
        self::assertFalse(IpMatcher::inCidr('2001:db8::ac01', '2001:db8::ab00/120'));
    }

    public function test_mixed_family_never_matches(): void
    {
        self::assertFalse(IpMatcher::inCidr('203.0.113.9', '2001:db8::/32'));
        self::assertFalse(IpMatcher::inCidr('2001:db8::1', '203.0.113.0/24'));
    }

    public function test_malformed_and_empty(): void
    {
        self::assertFalse(IpMatcher::matches('', ['0.0.0.0/0']));
        self::assertFalse(IpMatcher::inCidr('203.0.113.9', 'garbage'));
        self::assertFalse(IpMatcher::inCidr('203.0.113.9', '203.0.113.0/x'));
        self::assertFalse(IpMatcher::matches('203.0.113.9', ['', '  ']));
    }
}

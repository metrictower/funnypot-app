<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Http\HoneypotController;
use PHPUnit\Framework\TestCase;

/**
 * clientIp() decides the IP that drives the gate, the logs, and AbuseIPDB reports. X-Forwarded-For is
 * client-spoofable, so it must be honoured only when the TCP peer is a configured trusted proxy —
 * otherwise a forged header could frame an innocent IP or dodge the per-IP gate.
 */
final class ClientIpTest extends TestCase
{
    protected function tearDown(): void
    {
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR']);
    }

    public function test_no_xff_returns_peer(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.5';
        self::assertSame('203.0.113.5', HoneypotController::clientIp());
    }

    public function test_edge_ignores_spoofed_xff(): void
    {
        // No trusted proxies: a client-supplied X-Forwarded-For must be ignored entirely.
        $_SERVER['REMOTE_ADDR'] = '203.0.113.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '8.8.8.8';
        self::assertSame('203.0.113.5', HoneypotController::clientIp([]));
    }

    public function test_untrusted_peer_ignores_xff(): void
    {
        // Peer is not in the trusted set, so its XFF is not believed either.
        $_SERVER['REMOTE_ADDR'] = '203.0.113.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '8.8.8.8';
        self::assertSame('203.0.113.5', HoneypotController::clientIp(['10.0.0.0/8']));
    }

    public function test_trusted_proxy_takes_rightmost_untrusted_hop(): void
    {
        // Peer is our trusted LB; the real client is the right-most hop that is not itself trusted.
        $_SERVER['REMOTE_ADDR'] = '10.0.0.9';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9, 203.0.113.7, 10.0.0.8';
        self::assertSame('203.0.113.7', HoneypotController::clientIp(['10.0.0.0/8']));
    }

    public function test_trusted_proxy_exact_ip_match(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.7';
        self::assertSame('203.0.113.7', HoneypotController::clientIp(['192.0.2.1']));
    }

    public function test_all_hops_trusted_falls_back_to_peer(): void
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.9';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.8, 10.0.0.7';
        self::assertSame('10.0.0.9', HoneypotController::clientIp(['10.0.0.0/8']));
    }

    // --- isTrustedPeer() (FP-0250 2.5) — the SAME trust boundary gates X-Forwarded-Proto now, so it
    // must default-closed exactly like the XFF gate above (clientIp() already covers ipInCidrList's
    // matching logic; this pins isTrustedPeer's own empty-list / exact-IP / CIDR / non-member behaviour).

    public function test_is_trusted_peer_matches_ips_and_cidrs_and_defaults_closed(): void
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.9';
        self::assertFalse(HoneypotController::isTrustedPeer([]), 'empty trusted-proxy list is default-closed — nothing is trusted');
        self::assertFalse(HoneypotController::isTrustedPeer(['192.0.2.1']), 'a non-member IP is not trusted');
        self::assertTrue(HoneypotController::isTrustedPeer(['10.0.0.9']), 'an exact IP match is trusted');
        self::assertTrue(HoneypotController::isTrustedPeer(['10.0.0.0/8']), 'a CIDR match is trusted');
        self::assertFalse(HoneypotController::isTrustedPeer(['10.0.1.0/24']), 'a non-matching CIDR is not trusted');
    }
}

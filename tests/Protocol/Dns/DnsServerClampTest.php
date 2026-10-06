<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Dns;

use Funnypot\Protocol\Dns\DnsServer;
use PHPUnit\Framework\TestCase;

/**
 * FP-0182: the server's UNCONDITIONAL final UDP byte-clamp (the single anti-amplification chokepoint),
 * unit-tested via its pure helper — a reply larger than the request is dropped regardless of what any
 * responder branch produced. Covers the gap the responder-level test cannot (server backstop).
 */
final class DnsServerClampTest extends TestCase
{
    public function test_oversize_reply_is_dropped(): void
    {
        self::assertSame('', DnsServer::clampReply(str_repeat('A', 100), 40), 'reply > request is dropped');
    }

    public function test_equal_size_reply_passes(): void
    {
        $r = str_repeat('A', 40);
        self::assertSame($r, DnsServer::clampReply($r, 40));
    }

    public function test_smaller_reply_passes(): void
    {
        self::assertSame('abc', DnsServer::clampReply('abc', 40));
    }

    public function test_one_byte_over_is_dropped(): void
    {
        self::assertSame('', DnsServer::clampReply(str_repeat('x', 41), 40), 'even one byte over amplifies');
    }
}

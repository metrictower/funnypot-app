<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\HoneypotController;
use PHPUnit\Framework\TestCase;

/** FP-0049: bare-IP (no hostname) Host detection — inet_pton-authoritative, FQDN never matches. */
final class BareIpHostTest extends TestCase
{
    /** @dataProvider bareProvider */
    public function test_bare_ip_hosts(string $host): void
    {
        self::assertTrue(HoneypotController::isBareIpHost($host), "'{$host}' should be bare-IP");
    }

    public static function bareProvider(): array
    {
        return [
            [''], ['1.2.3.4'], ['1.2.3.4:8080'], ['::1'], ['fe80::1'], ['2001:db8::1'],
            ['[::1]'], ['[2001:db8::1]:443'], ['  192.0.2.9  '],
        ];
    }

    /** @dataProvider namedProvider */
    public function test_named_hosts_are_not_bare(string $host): void
    {
        self::assertFalse(HoneypotController::isBareIpHost($host), "'{$host}' should NOT be bare-IP");
    }

    public static function namedProvider(): array
    {
        return [
            ['admin.metrictower.com'], ['admin.metrictower.com.'], ['example.com'],
            ['example.com:8080'], ['localhost'], ['myhost'], ['grafana.internal'],
        ];
    }
}

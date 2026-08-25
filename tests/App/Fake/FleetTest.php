<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\Fleet;
use PHPUnit\Framework\TestCase;

final class FleetTest extends TestCase
{
    public function test_fleet_size_and_this_box_is_the_persona_host(): void
    {
        $servers = Fleet::fromSeed(4242, 24)->servers();
        self::assertCount(24, $servers);
        self::assertSame(4242, $servers[0]['seed'], 'host 0 is seeded by the persona seed');
        self::assertSame('running', $servers[0]['status'], 'the box you are on is always up');
    }

    public function test_statuses_valid_and_aggregate_sums(): void
    {
        $f = Fleet::fromSeed(7, 30);
        $agg = $f->aggregate();
        self::assertSame(30, $agg['total']);
        self::assertSame(30, $agg['running'] + $agg['degraded'] + $agg['stopped'] + $agg['offline']);
        foreach ($f->servers() as $s) {
            self::assertContains($s['status'], ['running', 'degraded', 'stopped', 'offline']);
            self::assertMatchesRegularExpression('/^\d+\.\d+\.\d+\.\d+$/', $s['ip']);
        }
    }

    public function test_detail_finds_host_case_insensitively(): void
    {
        $f = Fleet::fromSeed(4242, 24);
        $host = $f->servers()[3]['host'];
        self::assertNotNull($f->detail($host));
        self::assertNotNull($f->detail(strtoupper($host)));
        self::assertNull($f->detail('no-such-host-zzz'));
    }

    public function test_deterministic(): void
    {
        self::assertEquals(Fleet::fromSeed(9, 10)->servers(), Fleet::fromSeed(9, 10)->servers());
    }
}

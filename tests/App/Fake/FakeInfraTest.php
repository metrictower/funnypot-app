<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FakeInfra;
use PHPUnit\Framework\TestCase;

final class FakeInfraTest extends TestCase
{
    /** Only RFC1918 10.x addressing is allowed anywhere the fleet advertises itself (critique T5/S1). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    public function test_deterministic_across_instances(): void
    {
        $a = FakeInfra::fromSeed(7);
        $b = FakeInfra::fromSeed(7);
        self::assertSame($a->targets(), $b->targets());
        self::assertSame($a->fleet(), $b->fleet());
        self::assertSame($a->metrics(), $b->metrics());
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(
            FakeInfra::fromSeed(1)->targets(),
            FakeInfra::fromSeed(2)->targets()
        );
    }

    public function test_targets_shape_and_count(): void
    {
        $rows = FakeInfra::fromSeed(3)->targets();
        self::assertGreaterThanOrEqual(30, count($rows));
        self::assertLessThanOrEqual(120, count($rows));
        foreach ($rows as $r) {
            self::assertSame(['job', 'instance', 'state', 'lastScrape', 'error'], array_keys($r));
            foreach ($r as $v) {
                self::assertIsString($v);
            }
            self::assertContains($r['state'], ['up', 'down']);
            self::assertMatchesRegularExpression('/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/', $r['instance']);
            if ($r['state'] === 'down') {
                self::assertStringContainsString('connection refused', $r['error']);
            } else {
                self::assertSame('', $r['error']);
            }
        }
    }

    public function test_targets_use_only_private_ips(): void
    {
        // Sweep many seeds so the ~12% down rows and their error targets are well sampled.
        for ($seed = 0; $seed < 40; $seed++) {
            foreach (FakeInfra::fromSeed($seed)->targets() as $r) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $r['instance'], "seed $seed instance");
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $r['error'], "seed $seed error");
            }
        }
    }

    public function test_some_targets_are_down_with_errors(): void
    {
        $down = 0;
        foreach (FakeInfra::fromSeed(11)->targets() as $r) {
            if ($r['state'] === 'down') {
                $down++;
                self::assertMatchesRegularExpression('/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $r['error']);
            }
        }
        self::assertGreaterThan(0, $down, 'expected at least one down target');
    }

    public function test_fleet_shape_and_distinct_hosts(): void
    {
        $rows = FakeInfra::fromSeed(5)->fleet();
        self::assertGreaterThanOrEqual(12, count($rows));
        self::assertLessThanOrEqual(30, count($rows));
        $hosts = [];
        foreach ($rows as $r) {
            self::assertSame(['host', 'role', 'cpu', 'mem', 'status'], array_keys($r));
            foreach ($r as $v) {
                self::assertIsString($v);
            }
            self::assertContains($r['status'], ['up', 'warn', 'down']);
            self::assertMatchesRegularExpression('/%$/', $r['cpu']);
            self::assertMatchesRegularExpression('/%$/', $r['mem']);
            $hosts[] = $r['host'];
        }
        self::assertSame(count($hosts), count(array_unique($hosts)), 'fleet hostnames must be distinct');
    }

    public function test_metrics_shape(): void
    {
        $m = FakeInfra::fromSeed(9)->metrics();
        self::assertSame(['reqRate', 'errRate', 'p95', 'cpuPct', 'memPct'], array_keys($m));
        foreach ($m as $v) {
            self::assertIsString($v);
        }
        self::assertMatchesRegularExpression('/ms$/', $m['p95']);
        self::assertMatchesRegularExpression('/%$/', $m['errRate']);
        self::assertMatchesRegularExpression('/%$/', $m['cpuPct']);
        self::assertMatchesRegularExpression('/%$/', $m['memPct']);
    }
}

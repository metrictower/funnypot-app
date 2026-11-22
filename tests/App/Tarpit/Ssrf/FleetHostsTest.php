<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Tarpit\Ssrf\FakeFetch;
use Funnypot\App\Tarpit\Ssrf\PathClass;
use Funnypot\App\Tarpit\Ssrf\Role;
use Funnypot\App\Tarpit\Ssrf\TargetParser;
use PHPUnit\Framework\TestCase;

final class FleetHostsTest extends TestCase
{
    public function test_every_fleet_server_resolves_by_name_and_ip(): void
    {
        $w = SsrfCorpus::network();
        $servers = Fleet::fromSeed(4242)->servers();
        self::assertCount(24, $servers);
        foreach ($servers as $s) {
            foreach ([strtolower($s['host']), $s['ip']] as $h) {
                $r = $w['net']->resolve(TargetParser::parse('http://' . $h . ':22/'), '203.0.113.9', Role::Hook);
                self::assertSame('fl:' . strtolower($s['host']), $r->node?->key, $h);
            }
        }
    }

    /** The console says "Connection refused" for a stopped server and "No route to host" for an offline one. */
    public function test_answers_agree_with_the_console(): void
    {
        $w = SsrfCorpus::network();
        $seen = [];
        foreach ([4242, 1, 2, 3, 4, 5, 6, 7, 8] as $seed) {
            $w = SsrfCorpus::network($seed);
            foreach (Fleet::fromSeed($seed)->servers() as $s) {
                $t = TargetParser::parse('http://' . strtolower($s['host']) . ':22/');
                $r = $w['net']->resolve($t, '203.0.113.9', Role::Hook);
                $res = $w['fetch']->delivery(FakeFetch::facts($r, 'GET', PathClass::Root), 0, 100, 'x');
                $want = match ($s['status']) {
                    'stopped' => 'Failed to connect: connection refused',
                    'offline' => 'Failed to connect: no route to host',
                    default => 'Received HTTP/0.9 when not allowed',
                };
                self::assertSame($want, $res->error, $s['host'] . ' ' . $s['status']);
                $seen[$s['status']] = true;
            }
        }
        self::assertArrayHasKey('stopped', $seen);
        self::assertArrayHasKey('offline', $seen);
        self::assertArrayHasKey('running', $seen);
    }
}

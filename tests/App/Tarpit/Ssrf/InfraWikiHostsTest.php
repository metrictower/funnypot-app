<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\InfraWikiHosts;
use Funnypot\App\Tarpit\Ssrf\Role;
use Funnypot\App\Tarpit\Ssrf\TargetParser;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

final class InfraWikiHostsTest extends TestCase
{
    /**
     * The shape InfraWiki::services() returns on its own branch: host, port, name, category, status. A
     * live host is <slug12>.<sub5>.<company domain>; an archived one is a 10.x address.
     *
     * @return list<array<string,mixed>>
     */
    private static function services(string $domain): array
    {
        return [
            ['host' => 'k3m9x2p7q1za.ab12c.' . $domain, 'port' => 8443, 'name' => 'Billing API', 'category' => 'payments', 'status' => 'live'],
            ['host' => 'p8q2w4e6r1ty.zx9cv.' . $domain, 'port' => 5432, 'name' => 'Orders DB', 'category' => 'database', 'status' => 'live'],
            ['host' => '10.44.7.21', 'port' => 9200, 'name' => 'Old search', 'category' => 'observability', 'status' => 'archived'],
            ['host' => 'bad', 'port' => 0, 'name' => 'skipped', 'category' => 'x', 'status' => 'live'],
        ];
    }

    public function test_from_services_fixture(): void
    {
        $domain = strtolower((string) PersonaIdentity::fromSeed(4242)->field('company.domain'));
        $wiki = InfraWikiHosts::fromServices(self::services($domain));
        $billing = 'k3m9x2p7q1za.ab12c.' . $domain;
        self::assertSame('http_api', $wiki->lookup($billing)?->kind);
        self::assertSame([8443], $wiki->lookup($billing)?->ports);
        self::assertSame('db', $wiki->lookup('p8q2w4e6r1ty.zx9cv.' . $domain)?->kind);
        self::assertSame('timeout', $wiki->lookup('10.44.7.21')?->state, 'an archived service times out');
        self::assertNull($wiki->lookup('bad'));
        self::assertNotSame([], $wiki->sample('x', 1));

        $w = SsrfCorpus::network(4242, true, true, 8 << 20, SsrfCorpus::KEY, [$wiki]);
        $r = $w['net']->resolve(TargetParser::parse('http://10.44.7.21:9200/'), '203.0.113.9', Role::Hook);
        self::assertSame('leaked', $r->egress);
        self::assertSame('timeout', $r->outcome);
        $r = $w['net']->resolve(TargetParser::parse('https://' . $billing . ':8443/'), '203.0.113.9', Role::Hook);
        self::assertSame('wk:' . $billing, $r->node?->key);
        self::assertSame('open', $r->outcome);
        $without = SsrfCorpus::network();
        self::assertSame('nxdomain', $without['net']->resolve(TargetParser::parse('https://' . $billing . ':8443/'), '203.0.113.9', Role::Hook)->outcome, 'positive control: unwired, the wiki host is unknown');
    }
}

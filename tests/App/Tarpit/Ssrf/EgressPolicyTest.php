<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\Network;
use Funnypot\App\Tarpit\Ssrf\Role;
use Funnypot\App\Tarpit\Ssrf\Target;
use Funnypot\App\Tarpit\Ssrf\TargetParser;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

final class EgressPolicyTest extends TestCase
{
    private const SOURCE = '10.213.87.2';

    private static function net(): Network
    {
        return SsrfCorpus::network()['net'];
    }

    private static function t(string $url): Target
    {
        $t = TargetParser::parse($url);
        self::assertNotNull($t, $url);

        return $t;
    }

    private static function region(): string
    {
        return (string) PersonaIdentity::fromSeed(4242)->field('cloud.aws.region');
    }

    private static function domain(): string
    {
        return strtolower((string) PersonaIdentity::fromSeed(4242)->field('company.domain'));
    }

    /** @return list<array{0:int,1:string,2:string,3:string}> [row, url, egress class, outcome] for the hook role */
    private static function rows(Network $net): array
    {
        $g = $net->generated();
        $live = null;
        $dead = null;
        for ($i = 1; $i < 4000 && ($live === null || $dead === null); $i++) {
            if ($g->node($i) !== null) {
                $live ??= $i;
            } elseif (($i & 255) !== 0 && ($i & 255) !== 255) {
                $dead ??= $i;
            }
        }
        $fleet = (new \Funnypot\App\Tarpit\Ssrf\FleetHosts(4242));
        $fleetIp = null;
        foreach (\Funnypot\App\Render\Fake\Fleet::fromSeed(4242)->servers() as $s) {
            if ($s['status'] === 'running') {
                $fleetIp = $s['ip'];
            }
        }
        unset($fleet);

        return [
            [2, 'http://127.0.0.1/', 'denylisted', 'validation'],
            [3, 'http://localhost.:22/', 'loopback', 'loopback'],
            [3, 'http://api.localhost:9090/', 'loopback', 'loopback'],
            [4, 'http://instance-data/latest/meta-data/', 'metadata', 'metadata'],
            [4, 'http://instance-data.ec2.internal/', 'metadata', 'metadata'],
            [5, 'http://' . $g->name($live) . ':' . $g->node($live)->ports[0] . '/', 'internal', 'open'],
            [5, 'http://nope-zzzzzz.svc.' . self::region() . '.internal/', 'internal', 'nxdomain'],
            [5, 'http://mainframe-nope/', 'internal', 'nxdomain'],
            [5, 'http://app.' . self::domain() . '/', 'internal', 'open'],
            [6, 'http://example.com/', 'proxied', 'proxy_denied'],
            [6, 'http://127.0.0.1.nip.io/', 'proxied', 'proxy_denied'],
            [6, 'https://' . self::domain() . '/', 'proxied', 'proxy_denied'],
            [6, 'https://www.' . self::domain() . '/login', 'proxied', 'proxy_denied'],
            [7, 'http://0:22/', 'loopback', 'loopback'],
            [7, 'http://127.1:6379/', 'loopback', 'loopback'],
            [7, 'http://127.1:1/', 'loopback', 'refused'],
            [8, 'http://0.1.2.3/', 'unroutable', 'unroutable'],
            [8, 'http://224.0.0.1/', 'unroutable', 'unroutable'],
            [8, 'http://255.255.255.255/', 'unroutable', 'unroutable'],
            [9, 'http://0xa9fea9fe/latest/meta-data/', 'metadata', 'metadata'],
            [10, 'http://10.213.87.5:3000/', 'source', 'timeout'],
            [11, 'http://' . $fleetIp . ':22/', 'leaked', 'open'],
            [12, 'http://' . $g->ip($live) . ':' . $g->node($live)->ports[0] . '/', 'generated', 'open'],
            [12, 'http://' . $g->ip($dead) . '/', 'generated', 'timeout'],
            [13, 'http://172.16.0.1/', 'private_other', 'timeout'],
            [13, 'http://100.64.0.1/', 'private_other', 'timeout'],
            [13, 'http://0xa9fe0101/', 'private_other', 'timeout'],
            [13, 'http://192.168.1.1/', 'private_other', 'timeout'],
            [14, 'http://8.8.8.8/', 'proxied', 'proxy_denied'],
            [15, 'http://[0:0::1]:22/', 'loopback', 'loopback'],
            [15, 'http://[::]:9090/', 'loopback', 'loopback'],
            [16, 'http://[::ffff:127.0.0.1]:22/', 'loopback', 'loopback'],
            [16, 'http://[::ffff:10.213.87.5]/', 'source', 'timeout'],
            [17, 'http://[fd00:ec2::254]/', 'metadata', 'metadata'],
            [18, 'http://[fc00::1]/', 'private_other', 'timeout'],
            [18, 'http://[fe80::1%25eth0]/', 'private_other', 'timeout'],
            [19, 'http://[64:ff9b::808:808]/', 'proxied', 'proxy_denied'],
            [19, 'http://[2001:db8::1]/', 'proxied', 'proxy_denied'],
        ];
    }

    public function test_class_table(): void
    {
        $net = self::net();
        self::assertSame('scheme', TargetParser::check('gopher://127.0.0.1:6379/_')[1], 'row 1');
        $rows = [];
        foreach (self::rows($net) as [$row, $url, $class, $outcome]) {
            $rows[$row] = true;
            foreach (Role::cases() as $role) {
                $r = $net->resolve(self::t($url), self::SOURCE, $role, true);
                self::assertSame($class, $r->egress, "row {$row} {$url} as {$role->value}");
                self::assertSame($outcome, $r->outcome, "row {$row} {$url} as {$role->value}");
            }
        }
        self::assertCount(18, $rows, 'every row from 2 to 19 has a fixture');
    }

    public function test_attacker_observable_targets_never_succeed(): void
    {
        $net = self::net();
        mt_srand(816);
        $urls = [];
        for ($i = 0; $i < 1000; $i++) {
            do {
                $a = mt_rand(1, 223);
            } while (in_array($a, [10, 100, 127, 169, 172, 192], true));
            $urls[] = 'http://' . $a . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(1, 254) . ':' . mt_rand(1, 65535) . '/cb';
            $urls[] = 'https://' . substr(md5((string) $i), 0, 10) . '.' . ['com', 'net', 'io', 'oast.fun', 'burpcollaborator.net'][$i % 5] . '/x';
        }
        foreach (['10.213.87.2', '181753602', '0x0ad55702', '[::ffff:10.213.87.2]', '10.213.87.1', '10.213.87.254', '10.213.87.2.nip.io',
            '127.0.0.1.sslip.io', 'localtest.me', '7f000001.c0a80001.rbndr.us', 'make-127.0.0.1-rebind.1u.ms', '[64:ff9b::7f00:1]', '[2606:4700::1111]',
            '[fc00::5]', '[fe80::1]'] as $h) {
            $urls[] = 'http://' . $h . ':8080/hook';
        }
        $urls[] = 'http://127.0.0.1:80@listener.example/';
        $urls[] = 'http://listener.example#@127.0.0.1/';
        $distinct = [];
        foreach ($urls as $u) {
            $t = self::t($u);
            $distinct[$t->host] = true;
            foreach (Role::cases() as $role) {
                $o = $net->resolve($t, self::SOURCE, $role, true)->outcome;
                self::assertContains($o, ['proxy_denied', 'timeout'], "{$u} as {$role->value}");
            }
        }
        self::assertGreaterThanOrEqual(1500, count($distinct));
        // Positive control: the same harness lets loopback and a generated host through, so an all-fail policy fails here.
        self::assertSame('loopback', $net->resolve(self::t('http://127.0.0.1:22/'), self::SOURCE, Role::Hook)->outcome);
        $g = $net->generated();
        for ($i = 1; $g->node($i) === null; $i++) {
        }
        self::assertSame('open', $net->resolve(self::t('http://' . $g->name($i) . ':' . $g->node($i)->ports[0] . '/'), self::SOURCE, Role::Hook)->outcome);
    }

    public function test_ipv6_ula_source_is_its_own_slash_64(): void
    {
        $net = self::net();
        $src = 'fd12:3456:789a:1::2';
        foreach (['[fd12:3456:789a:1::2]', '[fd12:3456:789a:1:ffff::9]'] as $h) {
            $r = $net->resolve(self::t('http://' . $h . ':8080/'), $src, Role::Hook);
            self::assertSame('source', $r->egress, $h);
            self::assertSame('timeout', $r->outcome, $h);
        }
        foreach (['[fd12:3456:789a:2::2]', '[fd12:3456:789b:1::2]'] as $h) {
            self::assertSame('private_other', $net->resolve(self::t('http://' . $h . ':8080/'), $src, Role::Hook)->egress, $h);
        }
        self::assertSame('private_other', $net->resolve(self::t('http://[fd12:3456:789a:1::2]:8080/'), self::SOURCE, Role::Hook)->egress, 'an IPv4 source has no /64');
    }

    public function test_public_source_gets_no_special_case(): void
    {
        $net = self::net();
        foreach (['203.0.113.9', '203.0.113.10', '[::ffff:203.0.113.9]'] as $h) {
            self::assertSame('proxied', $net->resolve(self::t('http://' . $h . ':8080/'), '203.0.113.9', Role::Hook)->egress, $h);
        }
    }

    public function test_run16_oob_listener_times_out(): void
    {
        $r = self::net()->resolve(self::t('http://10.213.87.2:8080/'), '10.213.87.2', Role::Hook);
        self::assertSame('source', $r->egress);
        self::assertSame('timeout', $r->outcome);
    }

    public function test_role_allowlists(): void
    {
        $net = self::net();
        $gh = self::t('https://github.com/torvalds/linux.git');
        self::assertSame('code_host', $net->resolve($gh, self::SOURCE, Role::Import)->outcome);
        self::assertSame('proxy_denied', $net->resolve($gh, self::SOURCE, Role::Hook)->outcome);
        self::assertSame('proxy_denied', $net->resolve($gh, self::SOURCE, Role::Storage)->outcome);
        self::assertSame('proxy_denied', $net->resolve(self::t('http://github.com/a/b'), self::SOURCE, Role::Import)->outcome, 'only https on 443');
        self::assertSame('proxy_denied', $net->resolve(self::t('https://api.github.com/'), self::SOURCE, Role::Import)->outcome);
    }

    public function test_denylist_blocks_literals_only(): void
    {
        $net = self::net();
        foreach (['127.0.0.1', 'LOCALHOST', '0.0.0.0', '[::1]', '169.254.169.254', '127.255.0.1'] as $h) {
            self::assertSame('denylisted', $net->resolve(self::t('http://' . $h . '/'), self::SOURCE, Role::Hook, true)->egress, $h);
            self::assertNotSame('denylisted', $net->resolve(self::t('http://' . $h . '/'), self::SOURCE, Role::Hook, false)->egress, "{$h} with the flag off");
        }
        foreach (['2130706433', '127.1', 'localhost.', '[::ffff:127.0.0.1]', '0', '0x7f000001', '[::]', 'instance-data', '0251.0376.0251.0376'] as $h) {
            self::assertNotSame('denylisted', $net->resolve(self::t('http://' . $h . '/'), self::SOURCE, Role::Hook, true)->egress, $h);
        }
    }
}

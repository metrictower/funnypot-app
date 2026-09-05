<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Ops;

use Funnypot\App\Ops\PortManifest;
use PHPUnit\Framework\TestCase;

/**
 * demo/ports.json is valid, canonical and says what the box is meant to expose (canonical web on
 * 80/443, 88 and 5555 owned by their listeners, every forward pointing at a real bind); and the
 * validator rejects each way the file could go wrong, one exact line per problem.
 */
final class PortManifestTest extends TestCase
{
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }

    public function test_production_manifest_is_valid_and_canonical(): void
    {
        $path = self::root() . '/demo/ports.json';
        $m = PortManifest::fromFile($path);
        self::assertSame([], $m->validate());
        self::assertSame((string) file_get_contents($path), $m->canonicalJson(), 'the committed file is the canonical rendering (scripts/check-ports.php --format)');
        self::assertGreaterThan(100, count($m->endpoints()));
    }

    public function test_production_manifest_ownership_facts(): void
    {
        $m = PortManifest::fromFile(self::root() . '/demo/ports.json');
        $byId = [];
        foreach ($m->endpoints() as $e) {
            $byId[$e['endpoint_id']] = $e;
        }
        self::assertSame('canonical-web', $byId['http-80']['owner_kind']);
        self::assertSame('canonical-web', $byId['https-443']['owner_kind']);
        self::assertTrue($byId['https-443']['tls']);

        // The two former nginx/listener races: exactly one owner each, and it is the listener.
        self::assertSame('kerberos', $byId['kerberos-88']['process_id']);
        self::assertSame('adb', $byId['adb-5555']['process_id']);
        self::assertNotContains('88', $m->nginxListens());
        self::assertNotContains('5555', $m->nginxListens());
        self::assertContains('kerberos 0.0.0.0:88', $m->spawns());
        self::assertContains('adb 0.0.0.0:5555', $m->spawns());

        // SIP is one process on tcp+udp; RTP rides it without a spawn of its own.
        self::assertSame($byId['sip-5060']['spawn'], $byId['sip-5060-udp']['spawn']);
        self::assertSame('media-capability', $byId['rtp-10000-udp']['owner_kind']);
        self::assertNull($byId['rtp-10000-udp']['spawn']);
        self::assertFalse($byId['rtp-10000-udp']['scanner_exposed']);

        // Forwards keep their target's identity; the only opt-in is 22 -> 2222.
        self::assertSame('vnc-5900', $byId['vnc-alias-5901']['forward_target_endpoint_id']);
        self::assertSame(['FUNNYPOT_SSH_ON_22' => ['22:2222']], $m->optInPublishes('deploy'));
        self::assertNotContains('22:2222', $m->publishes('deploy'));

        // The deploy target publishes every bind; compose is a strict subset of deploy.
        foreach ($m->endpoints() as $e) {
            if (PortManifest::isBind($e)) {
                self::assertContains('deploy', $e['targets'], $e['endpoint_id'] . ' is published by deploy');
            }
        }
        self::assertSame([], array_diff($m->publishes('compose'), $m->publishes('deploy')));
        self::assertLessThan(count($m->publishes('deploy')), count($m->publishes('compose')));
        self::assertSame($m->exposes(), PortManifest::sortedUnique($m->exposes()), 'EXPOSE view has no duplicates');
        self::assertCount(40, $m->spawns(), 'one spawn line per listener process');
    }

    public function test_canonical_rendering_is_order_independent_and_idempotent(): void
    {
        $doc = self::minimalDoc();
        $a = PortManifest::fromArray($doc)->canonicalJson();
        $shuffled = $doc;
        $shuffled['endpoints'] = array_reverse($shuffled['endpoints']);
        $b = PortManifest::fromArray($shuffled)->canonicalJson();
        self::assertSame($a, $b);
        self::assertSame($a, PortManifest::fromJson($a)->canonicalJson());
        self::assertSame([], PortManifest::fromJson($a)->validate());
        self::assertStringContainsString('"endpoints": [', $a);
        self::assertSame(count($doc['endpoints']), substr_count($a, "\n    {"), 'one endpoint per line');
    }

    /**
     * @dataProvider brokenDocs
     * @param callable(array<string,mixed>): array<string,mixed> $break
     */
    public function test_validator_names_each_defect(callable $break, string $expected): void
    {
        $doc = $break(self::minimalDoc());
        $problems = PortManifest::fromArray($doc)->validate();
        self::assertNotSame([], $problems, 'the defect is caught');
        self::assertStringContainsString($expected, implode("\n", $problems));
    }

    /** @return iterable<string, array{0: callable, 1: string}> */
    public static function brokenDocs(): iterable
    {
        yield 'wrong schema' => [static function (array $d): array { $d['schema'] = 'x'; return $d; }, 'schema: expected'];
        yield 'duplicate bind owner' => [static function (array $d): array {
            $d['endpoints'][] = self::ep('adb-dup', 'listener', 'tcp', 5555, ['process_id' => 'adb2', 'spawn' => ['proto' => 'adb2', 'bind' => '0.0.0.0:5555'], 'runtime_toggleable' => true]);

            return $d;
        }, 'tcp/5555 is already bound by adb-5555'];
        yield 'nginx claims a listener port' => [static function (array $d): array {
            $d['endpoints'][] = self::ep('http-5555', 'nginx-alias', 'tcp', 5555);

            return $d;
        }, 'tcp/5555 is already bound by adb-5555'];
        yield 'double publisher on one target' => [static function (array $d): array {
            $d['endpoints'][] = self::ep('vnc-alias-8080', 'listener', 'tcp', 5900, ['host_port' => 8080, 'forward_target_endpoint_id' => 'vnc-5900', 'process_id' => 'vnc', 'service_id' => 'vnc', 'runtime_toggleable' => true]);

            return $d;
        }, 'deploy tcp/8080 is already published by http-8080'];
        yield 'forward to a missing target' => [static function (array $d): array {
            $d['endpoints'][] = self::ep('vnc-alias-5901', 'listener', 'tcp', 5900, ['host_port' => 5901, 'forward_target_endpoint_id' => 'vnc-nope', 'process_id' => 'vnc', 'service_id' => 'vnc', 'runtime_toggleable' => true]);

            return $d;
        }, 'forward target "vnc-nope" does not exist'];
        yield 'forward changes transport' => [static function (array $d): array {
            $d['endpoints'][] = self::ep('vnc-alias-5901', 'listener', 'udp', 5900, ['host_port' => 5901, 'forward_target_endpoint_id' => 'vnc-5900', 'process_id' => 'vnc', 'service_id' => 'vnc', 'runtime_toggleable' => true]);

            return $d;
        }, "forward must keep its target's transport and container_port"];
        yield 'forward on the same host port' => [static function (array $d): array {
            $d['endpoints'][] = self::ep('vnc-alias-x', 'listener', 'tcp', 5900, ['host_port' => 5900, 'forward_target_endpoint_id' => 'vnc-5900', 'process_id' => 'vnc', 'service_id' => 'vnc', 'runtime_toggleable' => true, 'targets' => []]);

            return $d;
        }, 'a forward publishes on a different host port'];
        yield 'canonical web missing' => [static function (array $d): array {
            $d['endpoints'] = array_values(array_filter($d['endpoints'], static fn (array $e): bool => $e['endpoint_id'] !== 'https-443'));

            return $d;
        }, 'canonical-web must be exactly tcp/80 and tcp/443'];
        yield 'nginx endpoint with a process' => [static function (array $d): array {
            $d['endpoints'][0]['process_id'] = 'nginx';

            return $d;
        }, 'an nginx-owned endpoint has no process_id and no spawn'];
        yield 'listener without spawn' => [static function (array $d): array {
            foreach ($d['endpoints'] as &$e) {
                if ($e['endpoint_id'] === 'adb-5555') {
                    $e['spawn'] = null;
                }
            }

            return $d;
        }, 'a listener bind names its spawn line'];
        yield 'spawn port differs' => [static function (array $d): array {
            foreach ($d['endpoints'] as &$e) {
                if ($e['endpoint_id'] === 'adb-5555') {
                    $e['spawn']['bind'] = '0.0.0.0:5556';
                }
            }

            return $d;
        }, 'spawn bind port differs from container_port'];
        yield 'opt-in without deploy' => [static function (array $d): array {
            $d['endpoints'][0]['deploy_opt_in'] = 'FUNNYPOT_X';
            $d['endpoints'][0]['targets'] = ['compose'];

            return $d;
        }, 'deploy_opt_in set but deploy is not a target'];
        yield 'unknown key' => [static function (array $d): array {
            $d['endpoints'][0]['extra'] = 1;

            return $d;
        }, 'unknown key(s) extra'];
        yield 'missing key' => [static function (array $d): array {
            unset($d['endpoints'][0]['notes']);

            return $d;
        }, 'missing key(s) notes'];
        yield 'duplicate id' => [static function (array $d): array {
            $d['endpoints'][] = $d['endpoints'][0];

            return $d;
        }, 'duplicate endpoint_id'];
        yield 'not canonical order' => [static function (array $d): array {
            $d['endpoints'] = array_reverse($d['endpoints']);

            return $d;
        }, 'not in canonical order'];
        yield 'targets out of order' => [static function (array $d): array {
            $d['endpoints'][0]['targets'] = ['compose', 'deploy'];

            return $d;
        }, 'targets must be a subset of [deploy, compose] in that order'];
    }

    /**
     * A small valid manifest: canonical web, one alias, one listener each on tcp and udp, one media
     * capability and one forward — in canonical order.
     *
     * @return array<string,mixed>
     */
    public static function minimalDoc(): array
    {
        return [
            'schema' => PortManifest::SCHEMA,
            'about' => 'fixture',
            'endpoints' => [
                self::ep('http-80', 'canonical-web', 'tcp', 80, ['targets' => ['deploy', 'compose']]),
                self::ep('https-443', 'canonical-web', 'tcp', 443, ['tls' => true, 'targets' => ['deploy', 'compose']]),
                self::ep('adb-5555', 'listener', 'tcp', 5555, ['service_id' => 'adb', 'process_id' => 'adb', 'spawn' => ['proto' => 'adb', 'bind' => '0.0.0.0:5555'], 'runtime_toggleable' => true]),
                self::ep('vnc-5900', 'listener', 'tcp', 5900, ['service_id' => 'vnc', 'process_id' => 'vnc', 'spawn' => ['proto' => 'vnc', 'bind' => '0.0.0.0:5900'], 'runtime_toggleable' => true]),
                self::ep('vnc-alias-5800', 'listener', 'tcp', 5900, ['host_port' => 5800, 'service_id' => 'vnc', 'process_id' => 'vnc', 'forward_target_endpoint_id' => 'vnc-5900', 'runtime_toggleable' => true]),
                self::ep('http-8080', 'nginx-alias', 'tcp', 8080, ['targets' => ['deploy', 'compose']]),
                self::ep('snmp-161-udp', 'listener', 'udp', 161, ['service_id' => 'snmp', 'process_id' => 'snmp', 'spawn' => ['proto' => 'snmp', 'bind' => '0.0.0.0:161'], 'runtime_toggleable' => true]),
                self::ep('rtp-10000-udp', 'media-capability', 'udp', 10000, ['service_id' => 'sip', 'process_id' => 'sip', 'scanner_exposed' => false, 'runtime_toggleable' => true]),
            ],
        ];
    }

    /**
     * @param array<string,mixed> $over
     * @return array<string,mixed>
     */
    public static function ep(string $id, string $kind, string $transport, int $port, array $over = []): array
    {
        return $over + [
            'endpoint_id' => $id,
            'service_id' => 'web',
            'process_id' => null,
            'owner_kind' => $kind,
            'transport' => $transport,
            'container_port' => $port,
            'host_port' => $port,
            'forward_target_endpoint_id' => null,
            'spawn' => null,
            'tls' => false,
            'targets' => ['deploy'],
            'deploy_opt_in' => null,
            'scanner_exposed' => true,
            'runtime_toggleable' => false,
            'notes' => '',
        ];
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use Funnypot\App\Docker\DockerDaemon;
use PHPUnit\Framework\TestCase;

/**
 * The deterministic fake-daemon state: version/info/container/image payload shapes, and byte-stability
 * — the same seed must produce the same daemon across reloads (no rand()), so a scanner cross-reading
 * two probes sees one coherent host.
 */
final class DockerDaemonTest extends TestCase
{
    private const NOW = 1_700_000_000;   // fixed clock so SystemTime is deterministic under test

    public function test_version_reports_the_pinned_release(): void
    {
        $v = DockerDaemon::fromSeed(7)->version();

        self::assertSame('24.0.5', $v['Version']);
        self::assertSame('1.43', $v['ApiVersion']);
        self::assertSame('1.12', $v['MinAPIVersion']);
        self::assertSame('linux', $v['Os']);
        self::assertSame('amd64', $v['Arch']);
        self::assertSame('go1.20.6', $v['GoVersion']);
        self::assertSame('Docker Engine - Community', $v['Platform']['Name']);
        // component block present with the engine first
        self::assertSame('Engine', $v['Components'][0]['Name']);
        self::assertSame('1.43', $v['Components'][0]['Details']['ApiVersion']);
        // the top-level short commit matches the engine component's commit (one coherent build)
        self::assertSame($v['Components'][0]['Details']['GitCommit'], $v['GitCommit']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{7}$/', $v['GitCommit']);
    }

    public function test_info_describes_a_production_linux_cluster_node(): void
    {
        $info = DockerDaemon::fromSeed(7)->info(self::NOW);

        self::assertSame('24.0.5', $info['ServerVersion']);
        self::assertSame('Ubuntu 22.04.3 LTS', $info['OperatingSystem']);
        self::assertSame('linux', $info['OSType']);
        self::assertSame('x86_64', $info['Architecture']);
        self::assertSame('overlay2', $info['Driver']);
        self::assertSame(5, $info['Containers']);
        self::assertSame(5, $info['ContainersRunning']);
        self::assertGreaterThanOrEqual(8, $info['NCPU']);
        self::assertGreaterThan(0, $info['MemTotal']);
        self::assertIsString($info['Name']);
        self::assertNotSame('', $info['Name']);
        // SystemTime tracks the injected clock
        self::assertStringStartsWith('2023-11-14T', $info['SystemTime']);
    }

    public function test_containers_are_the_enticing_devops_and_crypto_fleet(): void
    {
        $rows = DockerDaemon::fromSeed(7)->containers();

        self::assertCount(5, $rows);
        $byName = [];
        foreach ($rows as $c) {
            $byName[ltrim($c['Names'][0], '/')] = $c;
        }

        self::assertArrayHasKey('eth-validator-staker', $byName);
        self::assertSame('lighthouse vc --network=mainnet', $byName['eth-validator-staker']['Command']);
        self::assertSame('consul agent -server -bootstrap-expect=3', $byName['consul-config-manager']['Command']);
        self::assertSame('vault server -config=/vault/config', $byName['vault-secret-store']['Command']);
        self::assertSame('postgres -D /var/lib/postgresql/data', $byName['prod-pg-replica-01']['Command']);
        self::assertStringContainsString('--rpc=http://10.0.0.5:8545', $byName['crypto-wallet-controller']['Command']);

        foreach ($rows as $c) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $c['Id'], 'container id is a 64-hex handle');
            self::assertSame('running', $c['State']);
            self::assertStringStartsWith('Up ', $c['Status']);
            self::assertStringStartsWith('sha256:', $c['ImageID']);
        }
    }

    public function test_images_list_is_coherent_with_the_running_containers(): void
    {
        $images = DockerDaemon::fromSeed(7)->images();

        self::assertNotEmpty($images);
        $tags = [];
        foreach ($images as $img) {
            self::assertStringStartsWith('sha256:', $img['Id']);
            self::assertMatchesRegularExpression('/^sha256:[0-9a-f]{64}$/', $img['Id']);
            $tags[] = $img['RepoTags'][0];
        }
        self::assertContains('postgres:15.4', $tags);
        self::assertContains('hashicorp/vault:1.15.2', $tags);
    }

    public function test_created_id_is_a_deterministic_64_hex_handle(): void
    {
        $d = DockerDaemon::fromSeed(7);
        $id = $d->createdId('xmrig/xmrig', '-o pool.minexmr.com:4444');

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $id);
        self::assertSame($id, $d->createdId('xmrig/xmrig', '-o pool.minexmr.com:4444'), 'same request => same id');
        self::assertNotSame($id, $d->createdId('alpine', 'sh'), 'different request => different id');
    }

    public function test_the_whole_daemon_is_byte_stable_for_a_seed(): void
    {
        $a = DockerDaemon::fromSeed(42);
        $b = DockerDaemon::fromSeed(42);

        // Compare the serialized bytes: byte-stability is exactly equal JSON, and it side-steps the
        // object-identity of the empty Labels map ({} in the wire form).
        self::assertSame(json_encode($a->version()), json_encode($b->version()));
        self::assertSame(json_encode($a->info(self::NOW)), json_encode($b->info(self::NOW)));
        self::assertSame(json_encode($a->containers()), json_encode($b->containers()));
        self::assertSame(json_encode($a->images()), json_encode($b->images()));
    }

    public function test_a_different_seed_yields_a_different_identity(): void
    {
        // Identity (host name, container ids) is seed-derived, so two deploys look like two hosts.
        self::assertNotSame(
            DockerDaemon::fromSeed(1)->info(self::NOW)['Name'],
            DockerDaemon::fromSeed(2)->info(self::NOW)['Name']
        );
        self::assertNotSame(
            DockerDaemon::fromSeed(1)->containers()[0]['Id'],
            DockerDaemon::fromSeed(2)->containers()[0]['Id']
        );
    }

    public function test_info_image_count_equals_images_json_count(): void
    {
        $d = DockerDaemon::fromSeed(7);
        self::assertSame(count($d->images()), $d->info(self::NOW)['Images'], 'no cross-read contradiction');
    }

    public function test_info_component_commits_match_version(): void
    {
        $d = DockerDaemon::fromSeed(7);
        $v = $d->version();
        $info = $d->info(self::NOW);
        $components = [];
        foreach ($v['Components'] as $c) {
            $components[$c['Name']] = $c['Details']['GitCommit'];
        }
        self::assertSame($components['containerd'], $info['ContainerdCommit']['ID']);
        self::assertSame($components['runc'], $info['RuncCommit']['ID']);
        self::assertSame($components['docker-init'], $info['InitCommit']['ID']);
    }

    public function test_info_has_swarm_and_registry_config(): void
    {
        $info = DockerDaemon::fromSeed(7)->info(self::NOW);
        self::assertSame('inactive', $info['Swarm']['LocalNodeState']);
        self::assertArrayHasKey('docker.io', $info['RegistryConfig']['IndexConfigs']);
        self::assertContains('name=cgroupns', $info['SecurityOptions']);
        self::assertSame('https://index.docker.io/v1/', $info['IndexServerAddress']);
        self::assertArrayHasKey('io.containerd.runc.v2', $info['Runtimes']);
    }

    public function test_info_extras_fold_in_phantoms(): void
    {
        $info = DockerDaemon::fromSeed(7)->info(self::NOW, 2, 1, 3, 1);
        // 5 fleet - 1 hidden + 2 running = 6 running; + 1 created = 7 total; 7 images + 3 pulled = 10.
        self::assertSame(6, $info['ContainersRunning']);
        self::assertSame(7, $info['Containers']);
        self::assertSame(1, $info['ContainersStopped']);
        self::assertSame(10, $info['Images']);
    }

    public function test_version_and_info_and_headers_agree(): void
    {
        $d = DockerDaemon::fromSeed(7);
        $v = $d->version();
        $info = $d->info(self::NOW);
        self::assertSame('1.43', $v['ApiVersion']);
        self::assertSame($v['Version'], $info['ServerVersion']);
        self::assertSame($v['KernelVersion'], $info['KernelVersion']);
        self::assertSame($v['Os'], $info['OSType']);
        self::assertSame('amd64', $v['Arch']);
        self::assertSame('x86_64', $info['Architecture']);
    }

    public function test_container_name_generator_is_deterministic_and_docker_shaped(): void
    {
        $d = DockerDaemon::fromSeed(7);
        $n = $d->containerName('deadbeefcafe');
        self::assertMatchesRegularExpression('/^[a-z]+_[a-z]+$/', $n);
        self::assertSame($n, $d->containerName('deadbeefcafe'), 'same id => same name');
        self::assertNotSame($n, $d->containerName('0011223344ff'));
    }

    public function test_pull_stream_is_bounded_and_coherent(): void
    {
        $d = DockerDaemon::fromSeed(7);
        $stream = $d->pullStream('alpine:latest');
        self::assertLessThanOrEqual(40, count($stream));
        self::assertSame('Pulling from library/alpine', $stream[0]['status']);
        self::assertStringStartsWith('Status: Downloaded newer image for', end($stream)['status']);
        $bytes = '';
        foreach ($stream as $m) {
            $bytes .= json_encode($m);
        }
        self::assertLessThan(8192, strlen($bytes));
        // byte-stable per seed+ref; different ref differs
        self::assertSame(json_encode($stream), json_encode($d->pullStream('alpine:latest')));
        self::assertNotSame(json_encode($stream), json_encode($d->pullStream('nginx:latest')));
    }

    public function test_inspect_phantom_echoes_the_config(): void
    {
        $d = DockerDaemon::fromSeed(7);
        $spec = [
            'id' => str_repeat('a', 64), 'image' => 'alpine', 'command' => 'sh', 'cmd' => ['sh'],
            'entrypoint' => [], 'env' => ['X=1'], 'binds' => ['/:/host'], 'mounts' => [],
            'name' => 'sysupdate', 'created' => self::NOW, 'started' => true, 'privileged' => true,
            'pid_mode' => 'host', 'network_mode' => 'host', 'user' => '', 'hostname' => '', 'tty' => false,
        ];
        $insp = $d->inspectPhantom($spec, self::NOW);
        self::assertTrue($insp['State']['Running']);
        self::assertSame('alpine', $insp['Config']['Image']);
        self::assertSame(['sh'], $insp['Config']['Cmd']);
        self::assertSame(['X=1'], $insp['Config']['Env']);
        self::assertTrue($insp['HostConfig']['Privileged']);
        self::assertSame(['/:/host'], $insp['HostConfig']['Binds']);
        self::assertSame('/sysupdate', $insp['Name']);
        self::assertSame('bind', $insp['Mounts'][0]['Type']);
        self::assertSame('/', $insp['Mounts'][0]['Source']);
    }

    public function test_the_engagement_helpers_are_byte_stable_for_a_seed(): void
    {
        $a = DockerDaemon::fromSeed(42);
        $b = DockerDaemon::fromSeed(42);
        self::assertSame(json_encode($a->pullStream('alpine:latest')), json_encode($b->pullStream('alpine:latest')));
        self::assertSame(json_encode($a->inspectFleet(0, self::NOW)), json_encode($b->inspectFleet(0, self::NOW)));
        self::assertSame(json_encode($a->inspectImage('alpine', self::NOW)), json_encode($b->inspectImage('alpine', self::NOW)));
    }

    public function test_fleet_resolution_by_id_name_and_prefix(): void
    {
        $d = DockerDaemon::fromSeed(7);
        $id = $d->fleetId(3);
        self::assertSame(3, $d->fleetIndex($id));
        self::assertSame(3, $d->fleetIndex(substr($id, 0, 12)));
        self::assertSame(3, $d->fleetIndex('vault-secret-store'));
        self::assertNull($d->fleetIndex('nonexistent-thing'));
    }

    public function test_local_image_locality(): void
    {
        $d = DockerDaemon::fromSeed(7);
        self::assertTrue($d->isLocalImage('postgres:15.4'));
        self::assertTrue($d->isLocalImage('alpine:3.18'));
        self::assertFalse($d->isLocalImage('alpine'), 'alpine:latest is not the local alpine:3.18');
        self::assertFalse($d->isLocalImage('xmrig/xmrig'));
    }
}

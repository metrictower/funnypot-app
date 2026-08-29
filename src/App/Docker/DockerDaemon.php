<?php

declare(strict_types=1);

namespace Funnypot\App\Docker;

/**
 * Deterministic, INERT fake Docker Engine daemon state — the payloads a real `dockerd` returns on an
 * exposed 2375 socket. Crypto-miner botnets scan 2375 for an unauthenticated daemon, fingerprint it
 * via /version + /info, then POST /containers/create + /start to run XMRig. This presents a believable
 * daemon so those bots engage and reveal what they try to deploy; nothing here ever runs a container.
 *
 * Design rules (same as the Fake\* panel generators):
 *  - IDENTITY is frozen per seed: hostname, the running-container list, image ids, host addressing and
 *    the created-container id are pure functions of the deploy seed (no rand()), so the daemon reads
 *    the same across reloads. A scanner cross-reading /info and /containers/json sees them agree.
 *  - VERSION numbers are the real public constants for the pinned release (24.0.5 / API 1.43), which is
 *    exactly what a real daemon of that version emits; only the commit hashes are seed-derived, since a
 *    per-build commit is itself plausible and must not be a fixed public value that pins the fake.
 *  - LIVE clock only where a real daemon is live: SystemTime tracks the injected now. Container ages are
 *    frozen per seed (a container's uptime string is stable within a deploy), so the list is byte-stable.
 *  - SAFE: host addressing is RFC1918 bridge space only; every value is fabricated and non-working.
 */
final class DockerDaemon
{
    /** Pinned engine release we impersonate — real public version constants (inert, byte-stable). */
    private const ENGINE_VERSION = '24.0.5';
    private const API_VERSION = '1.43';
    private const MIN_API_VERSION = '1.12';
    private const GO_VERSION = 'go1.20.6';
    private const CONTAINERD_VERSION = '1.6.22';
    private const RUNC_VERSION = '1.1.8';
    private const INIT_VERSION = '0.19.0';
    private const KERNEL_VERSION = '5.15.0-79-generic';
    private const BUILD_TIME = '2023-07-24T18:00:00.000000000+00:00';

    /** The enticing containers a miner bot expects to find on a popped cluster node (name/image/cmd). */
    private const FLEET = [
        ['eth-validator-staker', 'sigp/lighthouse:latest', 'lighthouse vc --network=mainnet', [5062]],
        ['crypto-wallet-controller', 'registry.internal/wallet-signer:2.3', '/bin/signer --rpc=http://10.0.0.5:8545', [8550]],
        ['consul-config-manager', 'hashicorp/consul:1.16.1', 'consul agent -server -bootstrap-expect=3', [8500, 8300]],
        ['vault-secret-store', 'hashicorp/vault:1.15.2', 'vault server -config=/vault/config', [8200]],
        ['prod-pg-replica-01', 'postgres:15.4', 'postgres -D /var/lib/postgresql/data', [5432]],
    ];

    /** @var int */
    private $seed;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|docker|' . $salt), 0, 15));
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    private function hex(int $len, string $salt): string
    {
        return substr(hash('sha256', $this->seed . '|docker-hex|' . $salt), 0, $len);
    }

    /** The daemon's own hostname — one frozen identity for /info Name and the swarm node. */
    private function hostname(): string
    {
        return sprintf('ip-10-0-%d-%d', $this->intIn(1, 254, 'host-a'), $this->intIn(1, 254, 'host-b'));
    }

    // --- payloads ---

    /** GET /version — the daemon + component version block. Version numbers real, commits seed-derived. */
    public function version(): array
    {
        $engineCommit = $this->hex(7, 'engine-commit');

        return [
            'Platform' => ['Name' => 'Docker Engine - Community'],
            'Components' => [
                [
                    'Name' => 'Engine',
                    'Version' => self::ENGINE_VERSION,
                    'Details' => [
                        'ApiVersion' => self::API_VERSION,
                        'Arch' => 'amd64',
                        'BuildTime' => self::BUILD_TIME,
                        'Experimental' => 'false',
                        'GitCommit' => $engineCommit,
                        'GoVersion' => self::GO_VERSION,
                        'KernelVersion' => self::KERNEL_VERSION,
                        'MinAPIVersion' => self::MIN_API_VERSION,
                        'Os' => 'linux',
                    ],
                ],
                ['Name' => 'containerd', 'Version' => self::CONTAINERD_VERSION, 'Details' => ['GitCommit' => $this->hex(40, 'containerd-commit')]],
                ['Name' => 'runc', 'Version' => self::RUNC_VERSION, 'Details' => ['GitCommit' => 'v' . self::RUNC_VERSION . '-0-g' . $this->hex(7, 'runc-commit')]],
                ['Name' => 'docker-init', 'Version' => self::INIT_VERSION, 'Details' => ['GitCommit' => 'de40ad0']],
            ],
            'Version' => self::ENGINE_VERSION,
            'ApiVersion' => self::API_VERSION,
            'MinAPIVersion' => self::MIN_API_VERSION,
            'GitCommit' => $engineCommit,
            'GoVersion' => self::GO_VERSION,
            'Os' => 'linux',
            'Arch' => 'amd64',
            'KernelVersion' => self::KERNEL_VERSION,
            'BuildTime' => self::BUILD_TIME,
        ];
    }

    /** GET /info — system info of a production Linux cluster node. SystemTime tracks the live clock. */
    public function info(int $now): array
    {
        $ncpu = [8, 16, 32, 48][$this->h('ncpu') % 4];
        $memGib = [32, 64, 128, 256][$this->h('mem') % 4];
        $running = count(self::FLEET);
        $images = $this->intIn(18, 44, 'images');

        return [
            'ID' => strtoupper(implode(':', str_split($this->hex(48, 'daemon-id'), 4))),
            'Containers' => $running,
            'ContainersRunning' => $running,
            'ContainersPaused' => 0,
            'ContainersStopped' => 0,
            'Images' => $images,
            'Driver' => 'overlay2',
            'DriverStatus' => [['Backing Filesystem', 'extfs'], ['Supports d_type', 'true'], ['Native Overlay Diff', 'true']],
            'Plugins' => [
                'Volume' => ['local'],
                'Network' => ['bridge', 'host', 'ipvlan', 'macvlan', 'null', 'overlay'],
                'Log' => ['awslogs', 'fluentd', 'gcplogs', 'gelf', 'journald', 'json-file', 'local', 'logentries', 'splunk', 'syslog'],
            ],
            'MemoryLimit' => true,
            'SwapLimit' => true,
            'CpuCfsPeriod' => true,
            'CpuCfsQuota' => true,
            'KernelMemoryTCP' => true,
            'CPUShares' => true,
            'CPUSet' => true,
            'OomKillDisable' => true,
            'IPv4Forwarding' => true,
            'BridgeNfIptables' => true,
            'Debug' => false,
            'NFd' => $this->intIn(30, 90, 'nfd'),
            'NGoroutines' => $this->intIn(60, 160, 'ngoroutines'),
            'SystemTime' => gmdate('Y-m-d\TH:i:s.000000000P', $now),
            'LoggingDriver' => 'json-file',
            'CgroupDriver' => 'systemd',
            'CgroupVersion' => '2',
            'NEventsListener' => 0,
            'KernelVersion' => self::KERNEL_VERSION,
            'OperatingSystem' => 'Ubuntu 22.04.3 LTS',
            'OSVersion' => '22.04',
            'OSType' => 'linux',
            'Architecture' => 'x86_64',
            'NCPU' => $ncpu,
            'MemTotal' => $memGib * 1024 * 1024 * 1024,
            'DockerRootDir' => '/var/lib/docker',
            'HttpProxy' => '',
            'HttpsProxy' => '',
            'NoProxy' => '',
            'Name' => $this->hostname(),
            'Labels' => [],
            'ExperimentalBuild' => false,
            'ServerVersion' => self::ENGINE_VERSION,
            'DefaultRuntime' => 'runc',
            'LiveRestoreEnabled' => false,
            'SecurityOptions' => ['name=apparmor', 'name=seccomp,profile=builtin'],
            'Warnings' => [],
        ];
    }

    /** GET /containers/json — the running-container list an attacker wants to hijack. */
    public function containers(): array
    {
        $out = [];
        foreach (self::FLEET as $i => [$name, $image, $cmd, $ports]) {
            $ageHours = $this->intIn(6, 1400, "age-{$i}");
            $created = $this->intIn(1_690_000_000, 1_710_000_000, "created-{$i}");
            $out[] = [
                'Id' => $this->hex(64, "cid-{$i}"),
                'Names' => ['/' . $name],
                'Image' => $image,
                'ImageID' => 'sha256:' . $this->hex(64, "iid-{$i}"),
                'Command' => $cmd,
                'Created' => $created,
                'Ports' => $this->portList($ports, $i),
                'Labels' => new \stdClass(),
                'State' => 'running',
                'Status' => 'Up ' . $this->humanUptime($ageHours),
                'HostConfig' => ['NetworkMode' => $i === 0 ? 'host' : 'bridge'],
                'NetworkSettings' => ['Networks' => ['bridge' => [
                    'IPAddress' => '172.17.0.' . ($i + 2),
                    'Gateway' => '172.17.0.1',
                    'MacAddress' => $this->mac($i),
                ]]],
                'Mounts' => [],
            ];
        }

        return $out;
    }

    /** GET /images/json — a small plausible local image list, coherent with the running containers. */
    public function images(): array
    {
        $tags = [
            'sigp/lighthouse:latest', 'hashicorp/consul:1.16.1', 'hashicorp/vault:1.15.2',
            'postgres:15.4', 'registry.internal/wallet-signer:2.3', 'alpine:3.18', 'nginx:1.25-alpine',
        ];
        $out = [];
        foreach ($tags as $i => $tag) {
            $size = $this->intIn(8, 480, "isize-{$i}") * 1024 * 1024;
            $out[] = [
                'Id' => 'sha256:' . $this->hex(64, "img-{$i}"),
                'ParentId' => '',
                'RepoTags' => [$tag],
                'RepoDigests' => [explode(':', $tag)[0] . '@sha256:' . $this->hex(64, "dig-{$i}")],
                'Created' => $this->intIn(1_685_000_000, 1_705_000_000, "icreated-{$i}"),
                'Size' => $size,
                'SharedSize' => -1,
                'VirtualSize' => $size,
                'Labels' => null,
                'Containers' => -1,
            ];
        }

        return $out;
    }

    /**
     * POST /containers/create — the created container's id. Derived from the seed + the attacker's own
     * image + command so an identical request yields an identical id (byte-stable, no rand()); the id
     * is a plausible fresh 64-hex handle but names nothing — no container is ever created.
     */
    public function createdId(string $image, string $cmd): string
    {
        return substr(hash('sha256', $this->seed . '|docker-create|' . $image . '|' . $cmd), 0, 64);
    }

    // --- helpers ---

    /** @param list<int> $ports @return list<array<string,mixed>> */
    private function portList(array $ports, int $i): array
    {
        $out = [];
        foreach ($ports as $j => $p) {
            $entry = ['PrivatePort' => $p, 'Type' => 'tcp'];
            // First port of each container is published to the host, so a scanner sees the on-theme
            // service ports (8200/8500/5432/…) mapped out — coherent with the box's exposed ports.
            if ($j === 0) {
                $entry = ['IP' => '0.0.0.0', 'PrivatePort' => $p, 'PublicPort' => $p, 'Type' => 'tcp'] + $entry;
            }
            $out[] = $entry;
        }

        return $out;
    }

    private function humanUptime(int $hours): string
    {
        if ($hours < 24) {
            return $hours . ' hours';
        }
        $days = intdiv($hours, 24);
        if ($days < 14) {
            return $days . ' days';
        }

        return intdiv($days, 7) . ' weeks';
    }

    private function mac(int $i): string
    {
        $tail = $this->hex(8, "mac-{$i}");

        return '02:42:ac:11:' . substr($tail, 0, 2) . ':' . substr($tail, 2, 2);
    }
}

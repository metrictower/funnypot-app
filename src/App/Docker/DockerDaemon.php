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

    // --- seed-derived component commits (SHARED by /version and /info so they cross-check clean) ---

    private function engineCommit(): string
    {
        return $this->hex(7, 'engine-commit');
    }

    private function containerdCommit(): string
    {
        return $this->hex(40, 'containerd-commit');
    }

    private function runcCommit(): string
    {
        return 'v' . self::RUNC_VERSION . '-0-g' . $this->hex(7, 'runc-commit');
    }

    private function initCommit(): string
    {
        return 'de40ad0';
    }

    // --- payloads ---

    /** GET /version — the daemon + component version block. Version numbers real, commits seed-derived. */
    public function version(): array
    {
        $engineCommit = $this->engineCommit();

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
                ['Name' => 'containerd', 'Version' => self::CONTAINERD_VERSION, 'Details' => ['GitCommit' => $this->containerdCommit()]],
                ['Name' => 'runc', 'Version' => self::RUNC_VERSION, 'Details' => ['GitCommit' => $this->runcCommit()]],
                ['Name' => 'docker-init', 'Version' => self::INIT_VERSION, 'Details' => ['GitCommit' => $this->initCommit()]],
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

    /**
     * GET /info — system info of a production Linux cluster node. SystemTime tracks the live clock.
     * The extra* args let the responder fold this attacker's phantom containers / pulled images into
     * the counts so /info agrees with /containers/json and /images/json for that session; $hiddenFleet
     * discounts fleet containers this IP has stopped/removed. All default 0 ⇒ the base host.
     */
    public function info(int $now, int $extraRunning = 0, int $extraCreated = 0, int $extraImages = 0, int $hiddenFleet = 0): array
    {
        $ncpu = [8, 16, 32, 48][$this->h('ncpu') % 4];
        $memGib = [32, 64, 128, 256][$this->h('mem') % 4];
        $fleet = max(0, count(self::FLEET) - max(0, $hiddenFleet));
        $running = $fleet + max(0, $extraRunning);
        $total = $running + max(0, $extraCreated);
        // Images = the real /images/json length + this session's pulled images (was a random 18–44,
        // which contradicted the 7-row /images/json a scanner reads on the very next request).
        $images = count($this->imageTags()) + max(0, $extraImages);

        return [
            // Engine ≥ 23 reports a UUID here (from /var/lib/docker/engine-id); the pre-23 libtrust
            // fingerprint below is 12 colon-groups of 4 hex. GATE-ON-REAL-CAPTURE: switching to a
            // seed-derived UUIDv4 is unverified against a live 24.0.x daemon in this offline repo, and a
            // wrong guess would ADD a tell, so this is left as-is per the plan-review addendum.
            'ID' => strtoupper(implode(':', str_split($this->hex(48, 'daemon-id'), 4))),
            'Containers' => $total,
            'ContainersRunning' => $running,
            'ContainersPaused' => 0,
            'ContainersStopped' => max(0, $total - $running),
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
            'Runtimes' => [
                'io.containerd.runc.v2' => ['path' => 'runc'],
                'runc' => ['path' => 'runc'],
            ],
            'DefaultRuntime' => 'runc',
            'Swarm' => [
                'NodeID' => '',
                'NodeAddr' => '',
                'LocalNodeState' => 'inactive',
                'ControlAvailable' => false,
                'Error' => '',
                'RemoteManagers' => null,
            ],
            'LiveRestoreEnabled' => false,
            'Isolation' => '',
            'InitBinary' => 'docker-init',
            'ContainerdCommit' => ['ID' => $this->containerdCommit(), 'Expected' => $this->containerdCommit()],
            'RuncCommit' => ['ID' => $this->runcCommit(), 'Expected' => $this->runcCommit()],
            'InitCommit' => ['ID' => $this->initCommit(), 'Expected' => $this->initCommit()],
            // cgroup-v2 hosts carry name=cgroupns; keep apparmor + seccomp builtin as before.
            'SecurityOptions' => ['name=apparmor', 'name=seccomp,profile=builtin', 'name=cgroupns'],
            'RegistryConfig' => [
                'AllowNondistributableArtifactsCIDRs' => [],
                'AllowNondistributableArtifactsHostnames' => [],
                'InsecureRegistryCIDRs' => ['127.0.0.0/8'],
                'IndexConfigs' => [
                    'docker.io' => ['Name' => 'docker.io', 'Mirrors' => [], 'Secure' => true, 'Official' => true],
                ],
                'Mirrors' => [],
            ],
            'IndexServerAddress' => 'https://index.docker.io/v1/',
            'Warnings' => [],
        ];
    }

    /**
     * GET /containers/json — the running-container list an attacker wants to hijack, plus this
     * session's phantom containers. $phantoms are decoded specs (see PhantomStore); $hiddenFleet are
     * fleet ids/names this IP stopped or removed; $all includes created-but-not-started phantoms
     * (docker's `?all=1`). A started phantom reads `running`, a created one `created`.
     *
     * @param list<array<string,mixed>> $phantoms
     * @param list<string>              $hiddenFleet
     */
    public function containers(array $phantoms = [], array $hiddenFleet = [], bool $all = false): array
    {
        $out = [];
        foreach (self::FLEET as $i => [$name, $image, $cmd, $ports]) {
            $id = $this->hex(64, "cid-{$i}");
            if (in_array($id, $hiddenFleet, true) || in_array($name, $hiddenFleet, true)) {
                continue;
            }
            $ageHours = $this->intIn(6, 1400, "age-{$i}");
            $created = $this->intIn(1_690_000_000, 1_710_000_000, "created-{$i}");
            $out[] = [
                'Id' => $id,
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

        $k = 0;
        foreach ($phantoms as $spec) {
            $started = (bool) ($spec['started'] ?? false);
            if (!$started && !$all) {
                continue;   // created-but-not-started is hidden unless ?all=1 (docker's own rule)
            }
            $out[] = $this->phantomListRow($spec, 0, $k++);
        }

        return $out;
    }

    /**
     * One `/containers/json` row for a phantom, in the same shape as a fleet row.
     *
     * @param array<string,mixed> $spec
     * @return array<string,mixed>
     */
    private function phantomListRow(array $spec, int $now, int $k): array
    {
        $id = (string) ($spec['id'] ?? '');
        $started = (bool) ($spec['started'] ?? false);
        $created = (int) ($spec['created'] ?? 0);
        $ip = '172.17.0.' . (7 + ($k % 240));

        return [
            'Id' => $id,
            'Names' => ['/' . ($spec['name'] !== '' ? ltrim((string) $spec['name'], '/') : $this->containerName($id))],
            'Image' => (string) ($spec['image'] ?? ''),
            'ImageID' => 'sha256:' . $this->hex(64, 'phantom-iid-' . $id),
            'Command' => (string) ($spec['command'] ?? ''),
            'Created' => $created,
            'Ports' => [],
            'Labels' => new \stdClass(),
            'State' => $started ? 'running' : 'created',
            'Status' => $started ? 'Up Less than a second' : 'Created',
            'HostConfig' => ['NetworkMode' => (string) ($spec['network_mode'] ?? '') !== '' ? (string) $spec['network_mode'] : 'default'],
            'NetworkSettings' => ['Networks' => ['bridge' => [
                'IPAddress' => $started ? $ip : '',
                'Gateway' => $started ? '172.17.0.1' : '',
                'MacAddress' => $started ? $this->mac(90 + $k) : '',
            ]]],
            'Mounts' => [],
        ];
    }

    /** The image RepoTags the fake host holds (coherent with the running fleet). */
    private function imageTags(): array
    {
        return [
            'sigp/lighthouse:latest', 'hashicorp/consul:1.16.1', 'hashicorp/vault:1.15.2',
            'postgres:15.4', 'registry.internal/wallet-signer:2.3', 'alpine:3.18', 'nginx:1.25-alpine',
        ];
    }

    /** Canonical (fully-qualified) forms of the local image tags, for the create locality check. */
    public function localCanonicals(): array
    {
        $out = [];
        foreach ($this->imageTags() as $tag) {
            $out[] = ImageRef::parse($tag)['canonical'];
        }

        return $out;
    }

    /**
     * GET /images/json — a small plausible local image list, coherent with the running containers,
     * plus any images this session pulled. $pulled are canonical refs (see PhantomStore).
     *
     * @param list<string> $pulled
     */
    public function images(array $pulled = []): array
    {
        $tags = $this->imageTags();
        foreach ($pulled as $ref) {
            $p = ImageRef::parse($ref);
            if ($p['valid']) {
                $tags[] = $p['display'];
            }
        }
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

    // --- engagement helpers (all pure, seeded, bounded — NOTHING here runs, opens, or connects) ---

    /**
     * The seeded jsonmessage sequence a real `dockerd` streams for `POST /images/create` (the "pull").
     * NOTHING is resolved or fetched — the sequence is a pure function of (seed, ref). Bounded: ≤ 40
     * messages, layer sizes ≥ 1 MB (so no six-digit `9xxxxx` decimal can be misread as a CRS rule id),
     * so the whole stream stays under a few KB and a fraction of a second to emit.
     *
     * @return list<array<string,mixed>>
     */
    public function pullStream(string $ref): array
    {
        $p = ImageRef::parse($ref);
        $repo = $p['valid'] ? $p['repo'] : 'library/unknown';
        $tag = $p['valid'] && $p['tag'] !== '' ? $p['tag'] : 'latest';
        $display = $p['valid'] ? $p['display'] : substr($ref, 0, 128);

        $out = [['status' => 'Pulling from ' . $repo, 'id' => $tag]];
        $layers = 1 + ($this->h('layers|' . $ref) % 4);   // 1..4
        for ($l = 0; $l < $layers; $l++) {
            $lid = substr($this->hex(12, "layer|{$ref}|{$l}"), 0, 12);
            // Total between 1 MB and ~120 MB, always ≥ 7 digits so it never renders a bare 9xxxxx.
            $total = 1_000_000 + ($this->h("size|{$ref}|{$l}") % 120_000_000);
            $out[] = ['status' => 'Pulling fs layer', 'progressDetail' => new \stdClass(), 'id' => $lid];
            foreach ([40, 80] as $pct) {
                $cur = intdiv($total * $pct, 100);
                $out[] = [
                    'status' => 'Downloading',
                    'progressDetail' => ['current' => $cur, 'total' => $total],
                    'progress' => $this->progressBar($cur, $total),
                    'id' => $lid,
                ];
            }
            $out[] = ['status' => 'Verifying Checksum', 'progressDetail' => new \stdClass(), 'id' => $lid];
            $out[] = ['status' => 'Download complete', 'progressDetail' => new \stdClass(), 'id' => $lid];
            $out[] = [
                'status' => 'Extracting',
                'progressDetail' => ['current' => $total, 'total' => $total],
                'progress' => $this->progressBar($total, $total),
                'id' => $lid,
            ];
            $out[] = ['status' => 'Pull complete', 'progressDetail' => new \stdClass(), 'id' => $lid];
        }
        $out[] = ['status' => 'Digest: sha256:' . $this->hex(64, 'pull-digest|' . $ref)];
        $out[] = ['status' => 'Status: Downloaded newer image for ' . $display];

        return array_slice($out, 0, 40);
    }

    private function progressBar(int $cur, int $total): string
    {
        $frac = $total > 0 ? $cur / $total : 1.0;
        $filled = max(0, min(50, (int) round($frac * 50)));

        return '[' . str_repeat('=', max(0, $filled - 1)) . '>' . str_repeat(' ', 50 - $filled) . ']  '
            . $this->humanBytes($cur) . '/' . $this->humanBytes($total);
    }

    private function humanBytes(int $n): string
    {
        if ($n >= 1_000_000) {
            return number_format($n / 1_000_000, 2) . 'MB';
        }
        if ($n >= 1_000) {
            return number_format($n / 1_000, 2) . 'kB';
        }

        return $n . 'B';
    }

    /**
     * GET /containers/{id}/json for a fleet member (full inspect). $i is the fleet index.
     *
     * @return array<string,mixed>
     */
    public function inspectFleet(int $i, int $now): array
    {
        [$name, $image, $cmd, $ports] = self::FLEET[$i];
        $id = $this->hex(64, "cid-{$i}");
        $created = $this->intIn(1_690_000_000, 1_710_000_000, "created-{$i}");

        return [
            'Id' => $id,
            'Created' => gmdate('Y-m-d\TH:i:s.000000000\Z', $created),
            'Path' => explode(' ', $cmd)[0],
            'Args' => array_slice(explode(' ', $cmd), 1),
            'State' => [
                'Status' => 'running', 'Running' => true, 'Paused' => false, 'Restarting' => false,
                'OOMKilled' => false, 'Dead' => false, 'Pid' => $this->intIn(1000, 60000, "pid-{$i}"),
                'ExitCode' => 0, 'Error' => '',
                'StartedAt' => gmdate('Y-m-d\TH:i:s.000000000\Z', $created),
                'FinishedAt' => '0001-01-01T00:00:00Z',
            ],
            'Image' => 'sha256:' . $this->hex(64, "iid-{$i}"),
            'Name' => '/' . $name,
            'RestartCount' => 0,
            'Driver' => 'overlay2',
            'Platform' => 'linux',
            'Config' => [
                'Hostname' => substr($id, 0, 12), 'Image' => $image,
                'Cmd' => explode(' ', $cmd), 'Entrypoint' => null, 'Env' => [],
                'Labels' => new \stdClass(), 'Tty' => false, 'AttachStdin' => false,
                'WorkingDir' => '', 'User' => '',
            ],
            'HostConfig' => ['NetworkMode' => $i === 0 ? 'host' : 'bridge', 'Privileged' => false, 'Binds' => null],
            'Mounts' => [],
            'NetworkSettings' => [
                'IPAddress' => '172.17.0.' . ($i + 2), 'Gateway' => '172.17.0.1',
                'MacAddress' => $this->mac($i),
                'Networks' => ['bridge' => ['IPAddress' => '172.17.0.' . ($i + 2), 'Gateway' => '172.17.0.1', 'MacAddress' => $this->mac($i)]],
            ],
        ];
    }

    /**
     * GET /containers/{id}/json for a phantom, echoing the attacker's own create config back (their
     * bytes, JSON-encoded, reachable only by the 64-hex id they were handed).
     *
     * @param array<string,mixed> $spec
     * @return array<string,mixed>
     */
    public function inspectPhantom(array $spec, int $now): array
    {
        $id = (string) ($spec['id'] ?? '');
        $started = (bool) ($spec['started'] ?? false);
        $created = (int) ($spec['created'] ?? $now);
        $binds = array_values((array) ($spec['binds'] ?? []));
        $ip = $started ? '172.17.0.' . (7 + (crc32($id) % 240)) : '';

        return [
            'Id' => $id,
            'Created' => gmdate('Y-m-d\TH:i:s.000000000\Z', $created),
            'Path' => (array) ($spec['entrypoint'] ?? []) !== [] ? ((array) $spec['entrypoint'])[0] : (((array) ($spec['cmd'] ?? []))[0] ?? ''),
            'Args' => array_values((array) ($spec['cmd'] ?? [])),
            'State' => [
                'Status' => $started ? 'running' : 'created',
                'Running' => $started, 'Paused' => false, 'Restarting' => false,
                'OOMKilled' => false, 'Dead' => false,
                'Pid' => $started ? $this->intIn(1000, 60000, 'phantom-pid-' . $id) : 0,
                'ExitCode' => 0, 'Error' => '',
                'StartedAt' => $started ? gmdate('Y-m-d\TH:i:s.000000000\Z', $created) : '0001-01-01T00:00:00Z',
                'FinishedAt' => '0001-01-01T00:00:00Z',
            ],
            'Image' => 'sha256:' . $this->hex(64, 'phantom-iid-' . $id),
            'Name' => '/' . ($spec['name'] !== '' ? ltrim((string) $spec['name'], '/') : $this->containerName($id)),
            'RestartCount' => 0,
            'Driver' => 'overlay2',
            'Platform' => 'linux',
            'Config' => [
                'Hostname' => (string) ($spec['hostname'] ?? '') !== '' ? (string) $spec['hostname'] : substr($id, 0, 12),
                'Image' => (string) ($spec['image'] ?? ''),
                'Cmd' => array_values((array) ($spec['cmd'] ?? [])),
                'Entrypoint' => (array) ($spec['entrypoint'] ?? []) !== [] ? array_values((array) $spec['entrypoint']) : null,
                'Env' => array_values((array) ($spec['env'] ?? [])),
                'Labels' => new \stdClass(),
                'Tty' => (bool) ($spec['tty'] ?? false), 'AttachStdin' => false,
                'WorkingDir' => '', 'User' => (string) ($spec['user'] ?? ''),
            ],
            'HostConfig' => [
                'NetworkMode' => (string) ($spec['network_mode'] ?? '') !== '' ? (string) $spec['network_mode'] : 'default',
                'Privileged' => (bool) ($spec['privileged'] ?? false),
                'PidMode' => (string) ($spec['pid_mode'] ?? ''),
                'Binds' => $binds === [] ? null : $binds,
            ],
            'Mounts' => $this->mountsFromBinds($binds),
            'NetworkSettings' => [
                'IPAddress' => $ip, 'Gateway' => $started ? '172.17.0.1' : '',
                'MacAddress' => $started ? $this->mac(90 + (crc32($id) % 200)) : '',
                'Networks' => ['bridge' => ['IPAddress' => $ip, 'Gateway' => $started ? '172.17.0.1' : '']],
            ],
        ];
    }

    /** Mounts array derived from `Binds` entries (host:container[:ro]). @return list<array<string,mixed>> */
    private function mountsFromBinds(array $binds): array
    {
        $out = [];
        foreach ($binds as $b) {
            $parts = explode(':', (string) $b);
            if (count($parts) < 2) {
                continue;
            }
            $ro = isset($parts[2]) && strpos($parts[2], 'ro') !== false;
            $out[] = [
                'Type' => 'bind', 'Source' => $parts[0], 'Destination' => $parts[1],
                'Mode' => $parts[2] ?? '', 'RW' => !$ro, 'Propagation' => 'rprivate',
            ];
        }

        return $out;
    }

    /**
     * GET /images/{name}/json for a local or pulled image. @return array<string,mixed>
     */
    public function inspectImage(string $ref, int $now): array
    {
        $p = ImageRef::parse($ref);
        $display = $p['valid'] ? $p['display'] : substr($ref, 0, 128);
        $repo = $p['valid'] ? $p['repo'] : 'library/unknown';
        $id = $this->hex(64, 'img-inspect|' . $ref);
        $size = 1_000_000 + ($this->h('img-size|' . $ref) % 200_000_000);

        return [
            'Id' => 'sha256:' . $id,
            'RepoTags' => [$display],
            'RepoDigests' => [$repo . '@sha256:' . $this->hex(64, 'img-dig|' . $ref)],
            'Parent' => '',
            'Created' => gmdate('Y-m-d\TH:i:s.000000000\Z', $now - $this->intIn(3600, 3_000_000, 'img-age|' . $ref)),
            'Architecture' => 'amd64',
            'Os' => 'linux',
            'Size' => $size,
            'VirtualSize' => $size,
            'Config' => ['Cmd' => ['/bin/sh'], 'Entrypoint' => null, 'Env' => ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'], 'WorkingDir' => ''],
            'RootFS' => ['Type' => 'layers', 'Layers' => ['sha256:' . $this->hex(64, 'img-layer|' . $ref)]],
        ];
    }

    /**
     * GET /exec/{id}/json — the inspect of a created exec instance (never ran). @return array<string,mixed>
     */
    public function execInspect(string $execId, string $containerId, array $cmd): array
    {
        return [
            'ID' => $execId,
            'Running' => false,
            'ExitCode' => 0,
            'ProcessConfig' => [
                'tty' => false, 'entrypoint' => $cmd[0] ?? '',
                'arguments' => array_values(array_slice($cmd, 1)), 'privileged' => false,
            ],
            'OpenStdin' => false, 'OpenStderr' => true, 'OpenStdout' => true,
            'CanRemove' => false, 'ContainerID' => $containerId, 'DetachKeys' => '', 'Pid' => 0,
        ];
    }

    /** A new 64-hex exec id, seeded from the container + command so it is byte-stable. */
    public function execId(string $containerId, string $cmd): string
    {
        return $this->hex(64, 'exec|' . $containerId . '|' . $cmd);
    }

    /**
     * Docker's `adjective_surname` container-name generator (seed+id-derived, from a small constant
     * table). Fingerprint-safe generic words only.
     */
    public function containerName(string $id): string
    {
        $adjectives = [
            'admiring', 'boring', 'clever', 'dazzling', 'eager', 'festive', 'gracious', 'happy',
            'jolly', 'kind', 'lucid', 'modest', 'nifty', 'optimistic', 'quirky', 'relaxed',
            'serene', 'trusting', 'vibrant', 'wonderful', 'zealous', 'brave', 'crazy', 'elated',
        ];
        $surnames = [
            'archimedes', 'banach', 'curie', 'darwin', 'euler', 'fermat', 'galois', 'hopper',
            'newton', 'noether', 'pasteur', 'ramanujan', 'shannon', 'turing', 'volta', 'wozniak',
            'boyd', 'chandra', 'dijkstra', 'edison', 'faraday', 'gauss', 'hawking', 'kepler',
        ];
        $a = $adjectives[$this->h('cn-a|' . $id) % count($adjectives)];
        $s = $surnames[$this->h('cn-s|' . $id) % count($surnames)];

        return $a . '_' . $s;
    }

    /**
     * GET /containers/{id}/logs for a fleet member — 2–3 seeded, on-theme log lines. @return list<string>
     */
    public function logsFleet(int $i): array
    {
        $lines = [
            ['level=info msg="server started" addr=0.0.0.0', 'level=info msg="health check ok"'],
            ['[INFO] agent: started', '[INFO] agent: joined cluster', '[INFO] agent: synced'],
            ['{"level":"info","msg":"listening"}', '{"level":"info","msg":"ready"}'],
            ['LOG:  database system is ready to accept connections', 'LOG:  autovacuum launcher started'],
            ['time="startup" level=info msg="node ready"', 'time="startup" level=info msg="peers=3"'],
        ];

        return $lines[$i % count($lines)];
    }

    /**
     * A dockerd JSON error body for a missing object. @return array<string,string>
     */
    public function notFound(string $what, string $id): array
    {
        return ['message' => 'No such ' . $what . ': ' . $id];
    }

    public function fleetCount(): int
    {
        return count(self::FLEET);
    }

    /** Resolve a target (full 64-hex id, a 12+-hex prefix, or a name) to a fleet index, or null. */
    public function fleetIndex(string $target): ?int
    {
        $needle = ltrim($target, '/');
        if ($needle === '') {
            return null;
        }
        foreach (self::FLEET as $i => [$name]) {
            $id = $this->hex(64, "cid-{$i}");
            if ($needle === $name || $needle === $id
                || (strlen($needle) >= 12 && strpos($id, $needle) === 0)) {
                return $i;
            }
        }

        return null;
    }

    public function fleetName(int $i): string
    {
        return self::FLEET[$i][0];
    }

    public function fleetId(int $i): string
    {
        return $this->hex(64, "cid-{$i}");
    }

    /** True when $canonical is a local (fleet) image, matched on its canonical form. */
    public function isLocalImage(string $ref): bool
    {
        return ImageRef::isLocal($ref, $this->localCanonicals(), []);
    }
}

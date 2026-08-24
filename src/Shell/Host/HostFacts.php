<?php

declare(strict_types=1);

namespace Funnypot\Shell\Host;

use Funnypot\App\Render\Fake\FakeCron;
use Funnypot\App\Render\Fake\MinerRig;
use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\Shell\Fs\Draw;

/**
 * The single per-host coherence source for the fake shell + fleet console. Every host fact — the process
 * table (reused from the same MinerRig+FakeCron generators the deep panel's ProcessesSection uses),
 * /proc/*, free, df, netstat, uname — derives from ONE identity seed, so the terminal, the panel, and the
 * fleet all describe the same box. For the this-box host the identity seed is the panel's personaSeed, so
 * shell `ps` == panel `ps` exactly. Pure/inert: no real process, socket, or /proc access.
 */
final class HostFacts
{
    private int $seed;
    private HostIdentity $id;
    private ServerProfile $sp;
    private FakeCron $cron;
    /** @var array<string,mixed> */
    private array $miner;

    public function __construct(int $identitySeed)
    {
        $this->seed = $identitySeed;
        $this->id = HostIdentity::fromSeed($identitySeed);   // distro + hostname (shell's own machine)
        $this->sp = ServerProfile::fromSeed($identitySeed);  // x86_64 hardware facts (cpu/mem/disk/gauges)
        $this->cron = FakeCron::fromSeed($identitySeed);
        $this->miner = MinerRig::fromSeed($identitySeed)->summary();
    }

    public function hostname(): string
    {
        return $this->id->hostname();
    }

    public function identity(): HostIdentity
    {
        return $this->id;
    }

    /** @return array{distro:string,kernel:string} */
    public function os(): array
    {
        return ['distro' => $this->id->distroPretty(), 'kernel' => $this->id->kernel()];
    }

    public function primaryIp(): string
    {
        return $this->sp->primaryIp();
    }

    public function uptimeDays(): int
    {
        return $this->sp->uptimeDays();
    }

    /** @return array{cpuPct:int,memUsedGib:float,load1:float,load5:float,load15:float,inletC:int,pkgC:int} */
    public function liveStats(int $bucket = 0): array
    {
        return $this->sp->liveStats($bucket);
    }

    public function uname(): string
    {
        // Same kernel + UTS /proc/version uses; distro-correct arch suffix (Debian's is the short form).
        return 'Linux ' . $this->id->hostname() . ' ' . $this->id->kernel() . ' '
            . $this->id->uts() . ' ' . $this->id->archSuffix();
    }

    /**
     * Process table, coherent with the panel: reuses MinerRig+FakeCron on the same seed so the miner line
     * and every service row match ProcessesSection exactly.
     *
     * @return list<array{pid:int,user:string,cpu:string,mem:string,command:string}>
     */
    public function processTable(): array
    {
        $rows = $this->cron->processes([
            'algo' => $this->miner['algo'] ?? '',
            'pool' => $this->miner['pool'] ?? '',
            'wallet' => $this->miner['wallet'] ?? '',
        ]);
        // The reused (Debian-flavored) process pool runs nginx as www-data; on a RHEL-family host the web
        // user is apache — remap so `ps` agrees with /etc/passwd (which has apache, not www-data, on rhel).
        if ($this->id->family() === 'rhel') {
            foreach ($rows as &$r) {
                if ($r['user'] === 'www-data') {
                    $r['user'] = 'apache';
                }
            }
            unset($r);
        }

        return $rows;
    }

    /** @return int[] PIDs backing /proc/<pid>, matching the process table */
    public function procPids(): array
    {
        return array_map(static fn (array $p): int => (int) $p['pid'], $this->processTable());
    }

    /** Serve a /proc pseudo-file, or null if not modeled. */
    public function proc(string $name): ?string
    {
        switch (ltrim($name, '/')) {
            case 'proc/cpuinfo':
            case 'cpuinfo':
                return $this->procCpuinfo();
            case 'proc/meminfo':
            case 'meminfo':
                return $this->procMeminfo();
            case 'proc/loadavg':
            case 'loadavg':
                return $this->procLoadavg();
            case 'proc/uptime':
            case 'uptime':
                return $this->procUptime();
            case 'proc/version':
            case 'version':
                return $this->procVersion();
            default:
                return null;
        }
    }

    private function procCpuinfo(): string
    {
        $cpu = $this->sp->cpu();
        $perSock = $cpu['coresPerSocket'];
        $out = '';
        for ($i = 0; $i < $cpu['threads']; $i++) {
            $physical = intdiv($i, $cpu['threads'] / $cpu['sockets']);
            $coreId = $i % $perSock;
            $out .= "processor\t: {$i}\n"
                . "vendor_id\t: GenuineIntel\n"
                . "cpu family\t: 6\n"
                . "model\t\t: 106\n"
                . "model name\t: {$cpu['model']}\n"
                . "physical id\t: {$physical}\n"
                . "siblings\t: " . ($perSock * 2) . "\n"
                . "core id\t\t: {$coreId}\n"
                . "cpu cores\t: {$perSock}\n"
                . "fpu\t\t: yes\n"
                . "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat sse sse2 ss ht syscall nx rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc aperfmperf avx avx2 avx512f avx512dq rdseed adx smap avx512cd sha_ni\n"
                . "\n";
        }

        return $out;
    }

    private function mem(): array
    {
        $m = $this->sp->memory();
        $live = $this->sp->liveStats();
        $totalKb = $m['memTotalKb'];
        $usedKb = (int) round($live['memUsedGib'] * 1024 * 1024);
        $usedKb = max(0, min($usedKb, $totalKb));
        $cachedKb = (int) round($usedKb * 0.42);
        $buffersKb = (int) round($usedKb * 0.05);
        $freeKb = max(0, $totalKb - $usedKb);
        $availKb = min($totalKb, $freeKb + $cachedKb);
        $swapTotalKb = 8 * 1024 * 1024;
        $swapFreeKb = $swapTotalKb - (int) round($usedKb * 0.01);

        return compact('totalKb', 'usedKb', 'cachedKb', 'buffersKb', 'freeKb', 'availKb', 'swapTotalKb', 'swapFreeKb');
    }

    private function procMeminfo(): string
    {
        $x = $this->mem();

        return sprintf(
            "MemTotal:       %d kB\nMemFree:        %d kB\nMemAvailable:   %d kB\nBuffers:        %d kB\n"
            . "Cached:         %d kB\nSwapTotal:      %d kB\nSwapFree:       %d kB\n",
            $x['totalKb'],
            $x['freeKb'],
            $x['availKb'],
            $x['buffersKb'],
            $x['cachedKb'],
            $x['swapTotalKb'],
            $x['swapFreeKb']
        );
    }

    /** free -m style rows. @return array{mem:array<int,int>,swap:array<int,int>} (values in MiB) */
    public function free(): array
    {
        $x = $this->mem();
        $mib = static fn (int $kb): int => intdiv($kb, 1024);
        $usedMib = $mib($x['usedKb']) - $mib($x['buffersKb']) - $mib($x['cachedKb']);

        return [
            'mem' => [$mib($x['totalKb']), max(0, $usedMib), $mib($x['freeKb']), 0, $mib($x['buffersKb'] + $x['cachedKb']), $mib($x['availKb'])],
            'swap' => [$mib($x['swapTotalKb']), $mib($x['swapTotalKb'] - $x['swapFreeKb']), $mib($x['swapFreeKb'])],
        ];
    }

    private function procLoadavg(): string
    {
        $live = $this->sp->liveStats();
        $total = count($this->processTable()) + 90; // kernel threads etc.
        $running = 1 + ((int) $live['load1'] % 3);
        $lastPid = 20000 + ($this->sp->uptimeDays() * 137 % 9000);

        return sprintf("%.2f %.2f %.2f %d/%d %d\n", $live['load1'], $live['load5'], $live['load15'], $running, $total, $lastPid);
    }

    private function procUptime(): string
    {
        // Intra-day seconds so uptime is never an exact multiple of 86400 (that's an arithmetic tell).
        $intraday = Draw::intBelow(Draw::seed('uptime|' . $this->seed), 0, 86400);
        $secs = $this->sp->uptimeDays() * 86400 + $intraday;
        $idlePerCpu = 0.6 + (100 - $this->sp->liveStats()['cpuPct']) / 100 * 0.35; // idle tracks cpu%
        $idle = (int) round($secs * $this->sp->cpu()['threads'] * $idlePerCpu);

        return sprintf("%d.%02d %d.%02d\n", $secs, 12, $idle, 47);
    }

    private function procVersion(): string
    {
        // Same kernel + UTS as uname(); distro-correct compiler + a distro build host (not the honeypot).
        return "Linux version {$this->id->kernel()} ({$this->id->builder()}) "
            . "({$this->id->gcc()}) {$this->id->uts()}\n";
    }

    /**
     * df rows: the boot volume mounted at / and the RAID data volume at /data.
     *
     * @return list<array{fs:string,size:string,used:string,avail:string,pct:string,mount:string}>
     */
    public function df(): array
    {
        $s = $this->sp->storage();
        $rootTb = 1.8; // boot NVMe
        $rootUsed = round($rootTb * $s['rootPct'] / 100, 1);
        $dataTb = (float) $s['usableTb'];
        $dataUsed = round($dataTb * $s['usedPct'] / 100, 1);
        $tb = static fn (float $v): string => rtrim(rtrim(number_format($v, 1), '0'), '.') . 'T';

        return [
            ['fs' => '/dev/mapper/vg0-root', 'size' => $tb($rootTb), 'used' => $tb($rootUsed),
                'avail' => $tb($rootTb - $rootUsed), 'pct' => $s['rootPct'] . '%', 'mount' => '/'],
            ['fs' => '/dev/sdb1', 'size' => $tb($dataTb), 'used' => $tb($dataUsed),
                'avail' => $tb($dataTb - $dataUsed), 'pct' => $s['usedPct'] . '%', 'mount' => '/data'],
        ];
    }

    /**
     * Listening sockets coherent with the running services (nginx/mariadb/redis/postgres from the process
     * table + sshd). All bound to the host's RFC1918 IP or loopback.
     *
     * @return list<array{proto:string,local:string,foreign:string,state:string}>
     */
    public function netstat(): array
    {
        // Derive sockets from the ACTUAL process table so netstat and ps never contradict: only a
        // running daemon opens a LISTEN, only a process-backed client shows ESTABLISHED. The attacker's
        // own :22 connection is appended by the shell adapter (it knows the peer), not here.
        $ip = $this->sp->primaryIp();
        $cmds = implode("\n", array_map(static fn (array $p): string => $p['command'], $this->processTable()));
        $rows = [];
        $listen = static function (string $local) use (&$rows): void {
            $rows[] = ['proto' => 'tcp', 'local' => $local, 'foreign' => '0.0.0.0:*', 'state' => 'LISTEN'];
        };
        $listen('0.0.0.0:22'); // sshd — we're logged in over it
        if (strpos($cmds, 'nginx') !== false) {
            $listen('0.0.0.0:80');
            $listen('0.0.0.0:443');
        }
        if (strpos($cmds, 'mariadbd') !== false || strpos($cmds, 'mysqld') !== false) {
            $listen('127.0.0.1:3306');
        }
        if (strpos($cmds, 'redis-server') !== false) {
            $listen('127.0.0.1:6379');
        }
        if (strpos($cmds, 'prometheus') !== false) {
            $listen('0.0.0.0:9090');
        }
        if (strpos($cmds, 'mongod') !== false) {
            $listen('127.0.0.1:27017');
        }
        if (strpos($cmds, 'server.js') !== false || strpos($cmds, '/usr/bin/node') !== false) {
            $listen('0.0.0.0:3000');
        }
        if (strpos($cmds, 'postgres') !== false) {
            $listen('0.0.0.0:5432');
            if (strpos($cmds, 'app_production') !== false || strpos($cmds, ' idle') !== false) {
                $rows[] = ['proto' => 'tcp', 'local' => $ip . ':5432', 'foreign' => '10.0.0.9:51324', 'state' => 'ESTABLISHED'];
            }
        }

        return $rows;
    }
}

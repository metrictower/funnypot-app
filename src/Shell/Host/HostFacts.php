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

    // A full modern-Xeon (Ice Lake, family 6 model 106) flag/bug set — standard Linux/Intel tokens,
    // not scanner signatures. A near-empty flags line was a tell against any real /proc/cpuinfo.
    private const CPU_FLAGS = 'fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush '
        . 'dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon '
        . 'pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx '
        . 'smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer '
        . 'aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb cat_l3 invpcid_single intel_ppin '
        . 'ssbd mba ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust '
        . 'bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb '
        . 'intel_pt avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc '
        . 'cqm_mbm_total cqm_mbm_local split_lock_detect wbnoinvd dtherm ida arat pln pts hwp hwp_act_window '
        . 'hwp_epp hwp_pkg_req avx512vbmi umip pku ospke avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg '
        . 'tme avx512_vpopcntdq la57 rdpid fsrm md_clear pconfig flush_l1d arch_capabilities';
    private const CPU_BUGS = 'spectre_v1 spectre_v2 spec_store_bypass swapgs itlb_multihit mmio_stale_data '
        . 'retbleed eibrs_pbrsb gds bhi';

    private function procCpuinfo(): string
    {
        $cpu = $this->sp->cpu();
        $perSock = $cpu['coresPerSocket'];
        $threadsPerSock = intdiv($cpu['threads'], max(1, $cpu['sockets']));
        $cacheKb = $perSock * 1536;                       // ~1.5 MB L3 per core, Ice Lake
        $baseMhz = $this->baseMhz();
        $micro = sprintf('0x%07x', Draw::at(Draw::seed('microcode|' . $this->seed), 0) & 0xfffffff);
        $out = '';
        for ($i = 0; $i < $cpu['threads']; $i++) {
            $physical = intdiv($i, max(1, $threadsPerSock));
            $coreId = $i % $perSock;
            // Per-core current frequency varies (governor scales idle cores down) — never a flat value.
            $mhz = $baseMhz - 300 + Draw::intBelow(Draw::seed('mhz|' . $this->seed), $i, 900);
            $out .= "processor\t: {$i}\n"
                . "vendor_id\t: GenuineIntel\n"
                . "cpu family\t: 6\n"
                . "model\t\t: 106\n"
                . "model name\t: {$cpu['model']}\n"
                . "stepping\t: 6\n"
                . "microcode\t: {$micro}\n"
                . "cpu MHz\t\t: " . sprintf('%.3f', $mhz) . "\n"
                . "cache size\t: {$cacheKb} KB\n"
                . "physical id\t: {$physical}\n"
                . "siblings\t: {$threadsPerSock}\n"
                . "core id\t\t: {$coreId}\n"
                . "cpu cores\t: {$perSock}\n"
                . "apicid\t\t: {$i}\n"
                . "initial apicid\t: {$i}\n"
                . "fpu\t\t: yes\n"
                . "fpu_exception\t: yes\n"
                . "cpuid level\t: 27\n"
                . "wp\t\t: yes\n"
                . "flags\t\t: " . self::CPU_FLAGS . "\n"
                . "bugs\t\t: " . self::CPU_BUGS . "\n"
                . "bogomips\t: " . sprintf('%.2f', $baseMhz * 2) . "\n"
                . "clflush size\t: 64\n"
                . "cache_alignment\t: 64\n"
                . "address sizes\t: 46 bits physical, 57 bits virtual\n"
                . "power management:\n"
                . "\n";
        }

        return $out;
    }

    /** Base clock in MHz, parsed from the model's "@ N.NGHz" suffix (fallback 2000), stable per host. */
    private function baseMhz(): int
    {
        if (preg_match('/@\s*([0-9.]+)GHz/', $this->sp->cpu()['model'], $m)) {
            return (int) round(((float) $m[1]) * 1000);
        }

        return 2000;
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
        $total = $x['totalKb'];
        $used = $x['usedKb'];
        // Plausible, internally-consistent breakdown derived from the used/cached figures — a real
        // /proc/meminfo is ~50 lines, not the 7 a scraper flags as synthetic. Values are proportions of
        // the same used/cached totals free/df already report, so the sub-lines never contradict them.
        $anon = (int) round($used * 0.5);
        $activeAnon = (int) round($anon * 0.6);
        $inactiveAnon = $anon - $activeAnon;
        $activeFile = (int) round($x['cachedKb'] * 0.55);
        $inactiveFile = $x['cachedKb'] - $activeFile;
        $slab = (int) round($used * 0.06);
        $sReclaim = (int) round($slab * 0.7);
        $mapped = (int) round($used * 0.12);
        $dirty = (int) round($x['cachedKb'] * 0.01);
        $committed = (int) round($used * 1.4);
        $directMap4k = 3 * 1024 * 1024;
        $directMap2M = (int) round(($total - $directMap4k) * 0.15);
        $directMap1G = ($total - $directMap4k - $directMap2M);
        $rows = [
            'MemTotal' => $total, 'MemFree' => $x['freeKb'], 'MemAvailable' => $x['availKb'],
            'Buffers' => $x['buffersKb'], 'Cached' => $x['cachedKb'], 'SwapCached' => 0,
            'Active' => $activeAnon + $activeFile, 'Inactive' => $inactiveAnon + $inactiveFile,
            'Active(anon)' => $activeAnon, 'Inactive(anon)' => $inactiveAnon,
            'Active(file)' => $activeFile, 'Inactive(file)' => $inactiveFile,
            'Unevictable' => 4096, 'Mlocked' => 4096,
            'SwapTotal' => $x['swapTotalKb'], 'SwapFree' => $x['swapFreeKb'],
            'Dirty' => $dirty, 'Writeback' => 0, 'AnonPages' => $anon, 'Mapped' => $mapped,
            'Shmem' => (int) round($used * 0.02), 'KReclaimable' => $sReclaim, 'Slab' => $slab,
            'SReclaimable' => $sReclaim, 'SUnreclaim' => $slab - $sReclaim,
            'KernelStack' => 32768, 'PageTables' => (int) round($used * 0.01),
            'NFS_Unstable' => 0, 'Bounce' => 0, 'WritebackTmp' => 0,
            'CommitLimit' => (int) round($total * 0.5 + $x['swapTotalKb']), 'Committed_AS' => $committed,
            'VmallocTotal' => 34359738367, 'VmallocUsed' => (int) round($used * 0.02), 'VmallocChunk' => 0,
            'Percpu' => 42240, 'HardwareCorrupted' => 0,
            'AnonHugePages' => 0, 'ShmemHugePages' => 0, 'ShmemPmdMapped' => 0,
            'FileHugePages' => 0, 'FilePmdMapped' => 0,
            'HugePages_Total' => 0, 'HugePages_Free' => 0, 'HugePages_Rsvd' => 0, 'HugePages_Surp' => 0,
            'Hugepagesize' => 2048, 'Hugetlb' => 0,
            'DirectMap4k' => $directMap4k, 'DirectMap2M' => $directMap2M, 'DirectMap1G' => $directMap1G,
        ];
        $out = '';
        foreach ($rows as $k => $v) {
            $out .= str_pad($k . ':', 16) . sprintf('%8d kB', $this->dodgeRuleId($v)) . "\n";
        }

        return $out;
    }

    /**
     * Keep a derived value from rendering as a bare six-digit 9xxxxx token — that range is CRS's
     * request-rule numbering, and echoing one back would leak a scanner signature (fingerprint gate).
     * A ~100 MB nudge on a memory sub-total is invisible and never leaves the plausible range.
     */
    private function dodgeRuleId(int $v): int
    {
        return ($v >= 900000 && $v <= 999999) ? $v - 100000 : $v;
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
     * df rows in real mount order: the kernel pseudo-filesystems (udev + the tmpfs family), the boot
     * volume at /, the RAID data volume at /data, a docker overlay when the daemon is running, and the
     * per-user tmpfs. A df that showed only / and /data (no tmpfs/udev at all) was itself the tell.
     * Sizes for the RAM-backed mounts derive from MemTotal; the boot device size is seed-varied.
     *
     * @return list<array{fs:string,size:string,used:string,avail:string,pct:string,mount:string}>
     */
    public function df(): array
    {
        $s = $this->sp->storage();
        $ramGib = $this->sp->memory()['memTotalKb'] / 1024 / 1024;
        // Boot NVMe size varies per host (1.5T / 1.8T / 2.0T are common), never a flat constant.
        $rootTb = 1.5 + Draw::intBelow(Draw::seed('roottb|' . $this->seed), 0, 6) / 10; // 1.5..2.0
        $rootUsedTb = $rootTb * $s['rootPct'] / 100;
        $dataTb = (float) $s['usableTb'];
        $dataUsedTb = $dataTb * $s['usedPct'] / 100;

        $tb = fn (float $v): string => $this->hsize($v * 1024);   // TiB -> the human formatter (GiB in)
        $g = fn (float $v): string => $this->hsize($v);           // GiB in

        $udev = $ramGib / 2;
        $shm = $ramGib / 2;
        $run = min(3.2, $ramGib / 10);
        $runUser = min(3.2, $ramGib / 10);
        $runUsedMib = 1.4 + Draw::intBelow(Draw::seed('run|' . $this->seed), 0, 40) / 10; // ~1.4-5.4 MiB

        $rows = [];
        $rows[] = ['fs' => 'udev', 'size' => $g($udev), 'used' => '0', 'avail' => $g($udev), 'pct' => '0%', 'mount' => '/dev'];
        $rows[] = ['fs' => 'tmpfs', 'size' => $g($run), 'used' => $this->hsize($runUsedMib / 1024),
            'avail' => $g($run), 'pct' => '1%', 'mount' => '/run'];
        $rows[] = ['fs' => '/dev/mapper/vg0-root', 'size' => $tb($rootTb), 'used' => $tb($rootUsedTb),
            'avail' => $tb($rootTb - $rootUsedTb), 'pct' => $s['rootPct'] . '%', 'mount' => '/'];
        $rows[] = ['fs' => 'tmpfs', 'size' => $g($shm), 'used' => '0', 'avail' => $g($shm), 'pct' => '0%', 'mount' => '/dev/shm'];
        $rows[] = ['fs' => 'tmpfs', 'size' => '5.0M', 'used' => '0', 'avail' => '5.0M', 'pct' => '0%', 'mount' => '/run/lock'];
        $rows[] = ['fs' => '/dev/sdb1', 'size' => $tb($dataTb), 'used' => $tb($dataUsedTb),
            'avail' => $tb($dataTb - $dataUsedTb), 'pct' => $s['usedPct'] . '%', 'mount' => '/data'];

        // A docker overlay is on the root fs, so it mirrors the root figures — shown only when the
        // daemon is actually in the process table (otherwise the mount wouldn't exist).
        $cmds = implode("\n", array_map(static fn (array $p): string => $p['command'], $this->processTable()));
        if (strpos($cmds, 'dockerd') !== false || strpos($cmds, 'containerd') !== false) {
            $hash = substr(hash('sha256', 'overlay|' . $this->seed), 0, 64);
            $rows[] = ['fs' => 'overlay', 'size' => $tb($rootTb), 'used' => $tb($rootUsedTb),
                'avail' => $tb($rootTb - $rootUsedTb), 'pct' => $s['rootPct'] . '%',
                'mount' => '/var/lib/docker/overlay2/' . $hash . '/merged'];
        }

        $rows[] = ['fs' => 'tmpfs', 'size' => $g($runUser), 'used' => '0', 'avail' => $g($runUser), 'pct' => '0%', 'mount' => '/run/user/0'];

        return $rows;
    }

    /** df -h style human size: GiB in, rendered M / G / T with one decimal (5.0M, 7.8G, 1.8T). */
    private function hsize(float $gib): string
    {
        if ($gib >= 1024) {
            return rtrim(rtrim(number_format($gib / 1024, 1), '0'), '.') . 'T';
        }
        if ($gib >= 1) {
            return number_format($gib, 1) . 'G';
        }

        return number_format($gib * 1024, 1) . 'M';
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

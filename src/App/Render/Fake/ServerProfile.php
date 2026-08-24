<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT fake server identity for the admin-panel skins — the data that makes a panel
 * feel like a real, juicy, high-value host an attacker will burn time on.
 *
 * Design rules (from the fake-data research + adversarial critique, docs/research/2026-08-23-*):
 *  - IDENTITY is frozen per seed (hostname, CPU, DIMM layout, disks, service tag) — one host, one
 *    coherent story across every panel. A scanner that cross-reads two views must see them agree.
 *  - CORRELATION is mandatory: manufacturer is picked first, then service-tag/UUID/BIOS follow from it;
 *    the DIMM table is derived from the SAME byte count as MemTotal; RAID raw x level -> usable is
 *    arithmetically consistent. Divergence is itself a tell.
 *  - SAFE: the host's own addressing is RFC1918/TEST-NET only (never real routable space), every
 *    secret/key is fabricated + non-working, no real product signature strings.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format) so it can promote into the shared
 *    Funnypot\Support\Fake namespace for the core template tier once Phase 3 consolidates generators.
 *
 * Live gauges (cpu%, load, temps) take an optional coarse time bucket so they drift believably across
 * cache regenerations while staying deterministic within a bucket; identity ignores it.
 */
final class ServerProfile
{
    /** @var int */
    private $seed;

    // bcrypt's own base64 variant: '.' and '/' first, then A-Z a-z 0-9 (64 symbols, no '+').
    private const BCRYPT_ALPHABET = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

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
        return (int) hexdec(substr(hash('sha256', $this->seed . '|srv|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    private function hex(int $len, string $salt): string
    {
        return substr(hash('sha256', $this->seed . '|hex|' . $salt), 0, $len);
    }

    /** A run of characters from $alphabet, as long as needed, drawn from a seeded byte stream. */
    private function chars(int $len, string $alphabet, string $salt): string
    {
        $m = strlen($alphabet);
        $out = '';
        $block = 0;
        while (strlen($out) < $len) {
            $stream = hash('sha256', $this->seed . '|chars|' . $salt . '|' . $block);
            for ($k = 0; $k < 64 && strlen($out) < $len; $k += 2) {
                $out .= $alphabet[hexdec(substr($stream, $k, 2)) % $m];
            }
            $block++;
        }
        return $out;
    }

    // --- correlated hardware identity (frozen) ---

    /** @return array{vendor:string,product:string,biosVendor:string,biosVer:string,serviceTag:string,uuid:string} */
    public function chassis(): array
    {
        // Manufacturer first; tag/UUID/BIOS all follow from it (critique T3).
        $vendors = [
            ['Dell Inc.', 'PowerEdge R750', 'Dell Inc.', '2.15.1', 'tag7', '4c4c4544'],
            ['Dell Inc.', 'PowerEdge R650', 'Dell Inc.', '1.10.2', 'tag7', '4c4c4544'],
            ['HPE', 'ProLiant DL380 Gen10 Plus', 'HPE', 'U46 v2.78', 'hp10', '30303234'],
            ['Supermicro', 'SYS-2029U-TR4', 'American Megatrends Inc.', '3.4a', 'smci', '00000000'],
        ];
        $v = $vendors[$this->h('vendor') % count($vendors)];
        $tag = $v[4] === 'tag7'
            ? strtoupper($this->hex(7, 'svctag'))            // Dell: 7-char service tag
            : ($v[4] === 'hp10' ? strtoupper($this->hex(10, 'svctag')) : strtoupper($this->hex(8, 'svctag')));
        $uuid = $v[5] . '-' . $this->hex(4, 'u1') . '-' . $this->hex(4, 'u2')
            . '-' . $this->hex(4, 'u3') . '-' . $this->hex(12, 'u4');
        return [
            'vendor' => $v[0],
            'product' => $v[1],
            'biosVendor' => $v[2],
            'biosVer' => $v[3],
            'serviceTag' => $tag,
            'uuid' => $uuid,
        ];
    }

    public function hostname(): string
    {
        return $this->pick(
            ['prod-db-01', 'vhost-04', 'srv-app-02', 'kvm-fra-03', 'pve-node01', 'web-lb-01', 'esx-repl-01'],
            'hostname'
        );
    }

    /** @return array{distro:string,kernel:string} */
    public function os(): array
    {
        $osx = [
            ['Ubuntu 22.04.4 LTS', '5.15.0-113-generic'],
            ['Debian GNU/Linux 12 (bookworm)', '6.1.0-21-amd64'],
            ['Rocky Linux 9.4 (Blue Onyx)', '5.14.0-427.13.1.el9_4.x86_64'],
        ];
        $o = $osx[$this->h('os') % count($osx)];
        return ['distro' => $o[0], 'kernel' => $o[1]];
    }

    /** @return array{model:string,sockets:int,coresPerSocket:int,threads:int,cores:int} */
    public function cpu(): array
    {
        $model = $this->pick(
            ['Intel(R) Xeon(R) Gold 6342 CPU @ 2.80GHz', 'Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz'],
            'cpu'
        );
        // Core count follows the picked model (real Xeon Gold spec) so the sheet is self-consistent:
        // 6342 = 24C/48T per socket; 6338 = 32C/64T per socket. Dual-socket, hyperthreaded.
        $coresPerSocket = (strpos($model, '6338') !== false) ? 32 : 24;
        $sockets = 2;
        $cores = $sockets * $coresPerSocket;
        return ['model' => $model, 'sockets' => $sockets, 'coresPerSocket' => $coresPerSocket, 'threads' => $cores * 2, 'cores' => $cores];
    }

    /**
     * Memory + DIMM layout derived from ONE byte count so the DIMM table and MemTotal agree (critique T1).
     * 8 x 32 GB = 256 GB raw; MemTotal is the raw minus a firmware reservation, shown as the odd GiB value.
     *
     * @return array{dimmCount:int,dimmSizeGb:int,rawKb:int,memTotalKb:int,totalGib:float,dimmPart:string,speed:int}
     */
    public function memory(): array
    {
        $dimmCount = 8;
        $dimmSizeGb = 32;
        $rawKb = $dimmCount * $dimmSizeGb * 1024 * 1024;          // 268435456 kB
        $reservedKb = 4588192;                                    // firmware/kernel reservation
        $memTotalKb = $rawKb - $reservedKb;                      // 263847264 kB ~ 251.5 GiB
        return [
            'dimmCount' => $dimmCount,
            'dimmSizeGb' => $dimmSizeGb,
            'rawKb' => $rawKb,
            'memTotalKb' => $memTotalKb,
            'totalGib' => round($memTotalKb / 1024 / 1024, 1),
            'dimmPart' => $this->pick(['Samsung M393A4K40EB3-CWE', 'SK Hynix HMA84GR7DJR4N-XN', 'Micron MTA36ASF4G72PZ'], 'dimm'),
            'speed' => 3200,
        ];
    }

    /**
     * Boot NVMe mirror + a data RAID-6 whose raw x (n-2)/n rounds to the advertised usable size
     * (critique T2): 5 x 16 TB RAID-6 -> 3 data disks -> ~44 TB usable.
     *
     * @return array{bootModel:string,dataModel:string,dataDisks:int,dataDiskTb:int,usableTb:int,usedPct:int,rootPct:int,controller:string}
     */
    public function storage(): array
    {
        $dataDisks = 5;
        $dataDiskTb = 16;
        $usableTb = ($dataDisks - 2) * $dataDiskTb;              // RAID-6: (n-2) data disks -> 48; shown ~44 after fs
        return [
            'bootModel' => 'SAMSUNG MZQL21T9HCJR-00A07',
            'dataModel' => $this->pick(['TOSHIBA MG08ACA16TE', 'Seagate ST16000NM001G', 'WDC WUH721816ALE6L4'], 'disk'),
            'dataDisks' => $dataDisks,
            'dataDiskTb' => $dataDiskTb,
            'usableTb' => $usableTb - 4,                          // filesystem/overhead -> ~44
            'usedPct' => $this->intIn(78, 92, 'diskused'),        // near-full = "grab it before it's gone"
            'rootPct' => $this->intIn(22, 45, 'rootused'),
            'controller' => $this->pick(['PERC H730P Mini', 'MegaRAID 9560-16i', 'HPE Smart Array P408i-a'], 'raidctl'),
        ];
    }

    /** RFC1918 only — the host never advertises real routable space (critique T5/S1). */
    public function primaryIp(): string
    {
        return '10.0.' . $this->intIn(1, 250, 'ipc') . '.' . $this->intIn(2, 250, 'iph');
    }

    /** RHEL-family distros (Rocky/RHEL/CentOS) log auth events to /var/log/secure; Debian-family use
     *  /var/log/auth.log — the path must follow whichever OS this seed already picked. */
    public function authLogPath(): string
    {
        $distro = $this->os()['distro'];
        foreach (['Rocky', 'RHEL', 'CentOS', 'Red Hat'] as $needle) {
            if (strpos($distro, $needle) !== false) {
                return '/var/log/secure';
            }
        }
        return '/var/log/auth.log';
    }

    // --- live-ish gauges (drift per coarse time bucket, deterministic within it) ---

    private function gauge(int $min, int $max, string $salt, int $bucket): int
    {
        $n = (int) hexdec(substr(hash('sha256', $this->seed . '|gauge|' . $salt . '|' . $bucket), 0, 12));
        return $min + ($n % (($max - $min) + 1));
    }

    /**
     * @return array{cpuPct:int,memUsedGib:float,load1:float,load5:float,load15:float,inletC:int,pkgC:int}
     */
    public function liveStats(int $bucket = 0): array
    {
        $cores = $this->cpu()['cores'];
        $cpuPct = $this->gauge(6, 74, 'cpu', $bucket);
        // load correlates with cpu% and core count (critique A.3): load1 ~ cpu% x cores x jitter.
        $load1 = round(($cpuPct / 100) * $cores * (0.6 + ($this->gauge(0, 80, 'j', $bucket) / 100)), 2);
        $mem = $this->memory();
        return [
            'cpuPct' => $cpuPct,
            'memUsedGib' => round($mem['totalGib'] * ($this->gauge(24, 68, 'mem', $bucket) / 100), 1),
            'load1' => $load1,
            'load5' => round($load1 * 0.9, 2),
            'load15' => round($load1 * 0.78, 2),
            'inletC' => $this->gauge(19, 24, 'inlet', $bucket),
            'pkgC' => $this->gauge(48, 71, 'pkg', $bucket),
        ];
    }

    public function uptimeDays(): int
    {
        // Frozen span per seed (a real "now - boot" only grows; a fixed span keeps the proof deterministic).
        return $this->intIn(37, 415, 'uptime');
    }

    public function pendingUpdates(): array
    {
        $total = $this->intIn(18, 63, 'upd');
        return ['total' => $total, 'security' => (int) round($total * 0.28)];
    }

    // --- juicy loot: backups (the download rabbit-hole) + a bottomless table ---

    /**
     * Dated backup archives, newest first, every name carrying an archive extension so the link routes
     * to the inert decoy-archive handler. Sizes/dates are the bait; the headline full backup is huge.
     *
     * Each row's filename date and its "X ago" label are both derived from the SAME seeded elapsed-
     * seconds offset off FrozenClock::EPOCH, so they can never disagree or land in the future — the two
     * facts describe the same instant instead of being computed independently (critique root-cause B).
     *
     * @return list<array{name:string,size:string,age:string}>
     */
    public function backups(): array
    {
        $user = $this->pick(['brightpk', 'nordicav', 'lumensta', 'apexfit', 'maplegrv'], 'bkuser');
        $db = $this->pick(['wp_prod', 'app_production', 'shop_live', 'crm_prod', 'billing'], 'bkdb');
        $out = [];
        // Non-overlapping elapsed-seconds bands, strictly increasing, so row order stays newest-first
        // regardless of the seeded jitter within each band.
        $bands = [
            [3600, 3 * 3600],           // ~1-3h ago
            [20 * 3600, 30 * 3600],     // ~20-30h ago
            [2 * 86400, 4 * 86400],     // 2-4 days ago
            [7 * 86400, 11 * 86400],    // 7-11 days ago
            [14 * 86400, 18 * 86400],   // 14-18 days ago
            [28 * 86400, 34 * 86400],   // 28-34 days ago
            [35 * 86400, 42 * 86400],   // 35-42 days ago
        ];
        foreach ($bands as $i => $band) {
            $ago = $this->intIn($band[0], $band[1], 'bkage' . $i);
            $epoch = FrozenClock::EPOCH - $ago;
            [$y, $mo, $d] = FrozenClock::civilFromDays(intdiv($epoch, 86400));
            $secOfDay = $epoch % 86400;
            $h = intdiv($secOfDay, 3600);
            $min = intdiv($secOfDay % 3600, 60);
            $s = $secOfDay % 60;
            $age = $this->ageLabel($ago);

            $gbTenths = $this->intIn(9, 118, 'bkfull' . $i);     // 0.9 - 11.8 GB
            $out[] = [
                'name' => sprintf('backup-%d.%d.%d_%02d-%02d-%02d_%s.tar.gz', $mo, $d, $y, $h, $min, $s, $user),
                'size' => number_format($gbTenths / 10, 1) . ' GB',
                'age' => $age,
            ];
            if ($i % 2 === 0) {
                $mb = $this->intIn(2, 480, 'bkdb' . $i);
                $out[] = [
                    'name' => sprintf('%s_%s.sql.gz', $user, $db),
                    'size' => $mb . '.' . ($this->h('bkdbf' . $i) % 10) . ' MB',
                    'age' => $age,
                ];
            }
        }
        return $out;
    }

    /** A short "time ago" label for an elapsed-seconds span, agreeing with the epoch it derives from. */
    private function ageLabel(int $seconds): string
    {
        if ($seconds < 2 * 86400) {
            return intdiv($seconds, 3600) . 'h ago';
        }
        return intdiv($seconds, 86400) . ' days ago';
    }

    /** A giant row count for a loot table so "Browse" is a bottomless scroll (critique D2). */
    public function lootRowCount(string $table): int
    {
        return $this->intIn(120000, 48000000, 'rows|' . $table);
    }

    /**
     * The first visible page of a "users" loot table: real-looking rows with INERT bcrypt-shaped hashes
     * (never a working hash — fixed cost + prefix, random body). The email domain is the persona's, so
     * the loot stays coherent with the rest of the host identity.
     *
     * @return list<list<string>>
     */
    public function lootUsers(string $domain): array
    {
        $people = [
            ['a.mitchell', 'Super Admin'], ['p.nair', 'Administrator'], ['c.wei', 'Billing'],
            ['deploy', 'Developer'], ['s.rossi', 'Ops Manager'], ['j.obrien', 'Support Agent'],
            ['f.alsayed', 'Read-only'], ['l.meyer', 'Developer'],
        ];
        $rows = [];
        foreach ($people as $i => $p) {
            $rows[] = [
                (string) ($i + 1),
                $p[0],
                $p[0] . '@' . $domain,
                $p[1],
                // Real bcrypt shape: cost + a 53-char run from bcrypt's own base64 alphabet (22-char
                // salt + 31-char hash) — the exact format the attacker who'd try to crack this expects.
                '$2y$10$' . $this->chars(53, self::BCRYPT_ALPHABET, 'bcrypt|' . $p[0]),
            ];
        }
        return $rows;
    }
}

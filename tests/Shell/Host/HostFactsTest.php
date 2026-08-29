<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Host;

use Funnypot\App\Render\Fake\FakeCron;
use Funnypot\App\Render\Fake\MinerRig;
use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Host\HostFacts;
use PHPUnit\Framework\TestCase;

final class HostFactsTest extends TestCase
{
    public function test_ps_matches_panel_generators_and_includes_miner(): void
    {
        $seed = 4242;
        $hf = new HostFacts($seed);
        $rows = $hf->processTable();
        self::assertNotEmpty($rows);

        // Same generators as the panel's ProcessesSection — the command set is identical (the shell may
        // remap the web user to apache on rhel for its own passwd coherence, so compare commands, not the
        // full rows).
        $sum = MinerRig::fromSeed($seed)->summary();
        $expected = FakeCron::fromSeed($seed)->processes(
            ['algo' => $sum['algo'], 'pool' => $sum['pool'], 'wallet' => $sum['wallet']]
        );
        self::assertSame(
            array_map(static fn ($p) => $p['command'], $expected),
            array_map(static fn ($p) => $p['command'], $rows)
        );
        self::assertSame(count($expected), count($rows));

        // the miner line is present and coherent with the miner summary.
        $cmds = implode("\n", array_map(fn ($p) => $p['command'], $rows));
        self::assertStringContainsString('lolMiner', $cmds);
        self::assertStringContainsString($sum['pool'], $cmds);

        self::assertSame(count($rows), count($hf->procPids()));
    }

    public function test_cpuinfo_has_full_per_core_fields(): void
    {
        $hf = new HostFacts(4242);
        $ci = (string) $hf->proc('cpuinfo');
        // A real /proc/cpuinfo block carries these per-core fields; a bare processor/model/flags stub
        // was a tell. Also: real tabs (not literal \t), a per-core MHz, cache size, microcode, bugs.
        foreach (['cpu MHz', 'cache size', 'microcode', 'bogomips', 'clflush size', 'address sizes',
            'power management', 'stepping', 'apicid'] as $field) {
            self::assertStringContainsString($field, $ci, "cpuinfo missing {$field}");
        }
        self::assertStringNotContainsString('\t', $ci, 'literal backslash-t leaked (single-quoted tab)');
        preg_match('/flags\t\t: (.*)/', $ci, $m);
        self::assertGreaterThan(100, count(explode(' ', trim($m[1]))), 'a real Xeon has a large flag set');
        self::assertStringContainsString('bugs', $ci);
    }

    public function test_meminfo_is_full_length_and_coherent(): void
    {
        $hf = new HostFacts(4242);
        $mi = (string) $hf->proc('meminfo');
        self::assertGreaterThanOrEqual(45, substr_count($mi, "\n"), '/proc/meminfo should be ~50 lines');
        foreach (['MemTotal', 'MemAvailable', 'Slab', 'SReclaimable', 'KernelStack', 'PageTables',
            'Committed_AS', 'VmallocTotal', 'Hugepagesize', 'DirectMap4k'] as $field) {
            self::assertStringContainsString($field . ':', $mi, "meminfo missing {$field}");
        }
        // Every field ends in " kB"; the sub-lines never exceed MemTotal.
        preg_match('/MemTotal:\s+(\d+) kB/', $mi, $mt);
        $total = (int) $mt[1];
        foreach (['MemFree', 'MemAvailable', 'Cached', 'AnonPages'] as $f) {
            preg_match('/' . $f . ':\s+(\d+) kB/', $mi, $v);
            self::assertLessThanOrEqual($total, (int) $v[1], "{$f} exceeds MemTotal");
        }
    }

    public function test_df_lists_pseudo_filesystems_in_mount_order(): void
    {
        $rows = (new HostFacts(4242))->df();
        $mounts = array_column($rows, 'mount');
        // A df with only / and /data (no udev/tmpfs at all) is the tell this fixes.
        foreach (['/dev', '/run', '/', '/dev/shm', '/run/lock', '/data', '/run/user/0'] as $m) {
            self::assertContains($m, $mounts, "df missing {$m}");
        }
        // udev and the /run tmpfs precede the root volume, as in a real mount table.
        self::assertLessThan(array_search('/', $mounts, true), array_search('/dev', $mounts, true));
        // The RAM-backed mounts are sized (not a flat placeholder).
        $byMount = [];
        foreach ($rows as $r) {
            $byMount[$r['mount']] = $r;
        }
        self::assertMatchesRegularExpression('/^\d+(\.\d+)?[MGT]$/', $byMount['/dev']['size']);
        self::assertSame('5.0M', $byMount['/run/lock']['size']);
    }

    public function test_df_device_sizes_are_seed_varied(): void
    {
        // The boot volume size must not be a hardcoded constant across every host.
        $sizes = [];
        for ($i = 0; $i < 40; $i++) {
            foreach ((new HostFacts($i))->df() as $r) {
                if ($r['mount'] === '/') {
                    $sizes[$r['size']] = true;
                }
            }
        }
        self::assertGreaterThan(1, count($sizes), 'root device size never varies by seed');
    }

    public function test_proc_free_df_uname_cohere_with_serverprofile(): void
    {
        $seed = 77;
        $hf = new HostFacts($seed);
        $sp = ServerProfile::fromSeed($seed);

        // /proc/cpuinfo has one processor block per logical CPU.
        $cpuinfo = (string) $hf->proc('/proc/cpuinfo');
        self::assertSame($sp->cpu()['threads'], substr_count($cpuinfo, "processor\t:"));
        self::assertStringContainsString($sp->cpu()['model'], $cpuinfo);

        // /proc/meminfo + free agree with the DIMM-derived MemTotal.
        $meminfo = (string) $hf->proc('meminfo');
        self::assertMatchesRegularExpression('/MemTotal:\s+' . $sp->memory()['memTotalKb'] . ' kB/', $meminfo);
        self::assertSame(intdiv($sp->memory()['memTotalKb'], 1024), $hf->free()['mem'][0]);

        // loadavg begins with the live load1.
        self::assertStringStartsWith(number_format($sp->liveStats()['load1'], 2), (string) $hf->proc('loadavg'));

        // df root % matches storage() — df now lists udev/tmpfs before /, so find the / row by mount.
        $rootRow = null;
        foreach ($hf->df() as $d) {
            if ($d['mount'] === '/') {
                $rootRow = $d;
            }
        }
        self::assertNotNull($rootRow, 'df has a / row');
        self::assertSame($sp->storage()['rootPct'] . '%', $rootRow['pct']);

        // uname carries the shell's OWN kernel + hostname (HostIdentity, not ServerProfile); netstat lists ssh.
        self::assertStringContainsString($hf->os()['kernel'], $hf->uname());
        self::assertStringContainsString($hf->hostname(), $hf->uname());
        self::assertNotEmpty(array_filter($hf->netstat(), fn ($s) => $s['local'] === '0.0.0.0:22'));

        self::assertNull($hf->proc('proc/nonsense'));
    }

    public function test_kernel_version_coherent_across_uname_procversion_and_distro(): void
    {
        $families = [];
        for ($i = 0; $i < 60; $i++) {
            $hf = new HostFacts($i);
            $uname = $hf->uname();
            $ver = (string) $hf->proc('version');
            $kernel = $hf->os()['kernel'];

            // both carry the same real kernel release
            self::assertStringContainsString($kernel, $uname, "kernel in uname (seed $i)");
            self::assertStringContainsString($kernel, $ver, "kernel in /proc/version (seed $i)");

            // the UTS ('#...' onward in /proc/version) is byte-identical inside uname — one kernel constant
            $uts = trim(substr($ver, (int) strpos($ver, '#')));
            self::assertStringContainsString($uts, $uname, "shared UTS (seed $i)");

            // distro-correct compiler in /proc/version
            $id = $hf->identity()->osReleaseId();
            $expect = $id === 'ubuntu' ? 'Ubuntu' : ($id === 'debian' ? 'Debian' : 'Red Hat');
            self::assertStringContainsString($expect, $ver, "compiler for {$id} (seed $i)");
            $families[$expect] = true;
        }
        self::assertGreaterThanOrEqual(2, count($families), 'should observe multiple distro families');
    }

    public function test_uname_arch_suffix_matches_distro(): void
    {
        // Debian's uname suffix is the short "x86_64 GNU/Linux"; Ubuntu/RHEL use the triple.
        for ($i = 0; $i < 40; $i++) {
            $hf = new HostFacts($i);
            self::assertStringEndsWith($hf->identity()->archSuffix(), rtrim($hf->uname()));
        }
    }

    public function test_uptime_not_exact_multiple_of_day(): void
    {
        $found = false;
        for ($i = 0; $i < 20; $i++) {
            $up = (string) (new HostFacts($i))->proc('uptime');
            $secs = (int) explode('.', $up)[0];
            if ($secs % 86400 !== 0) {
                $found = true;
                break;
            }
        }
        self::assertTrue($found, 'uptime should carry intra-day seconds, not land on an exact day boundary');
    }

    public function test_deterministic(): void
    {
        self::assertEquals((new HostFacts(9))->processTable(), (new HostFacts(9))->processTable());
        self::assertSame((new HostFacts(9))->proc('meminfo'), (new HostFacts(9))->proc('meminfo'));
    }

    public function test_every_ps_user_has_a_passwd_entry(): void
    {
        // ps and /etc/passwd must agree for the same host (spanning both distro families).
        foreach ([1, 7, 42, 99, 1000, 4242] as $seed) {
            $hf = new HostFacts($seed);
            $fs = new FakeFilesystem(Draw::seed("cohere\0" . $seed), 'ops', $seed);
            $passwd = [];
            foreach (explode("\n", $fs->read('/etc/passwd')) as $l) {
                $f = explode(':', $l);
                if (($f[0] ?? '') !== '') {
                    $passwd[$f[0]] = true;
                }
            }
            foreach ($hf->processTable() as $p) {
                $u = $p['user'];
                if (substr($u, -1) === '+') { // ps truncates long names to 7 chars + '+'
                    $prefix = substr($u, 0, -1);
                    $match = false;
                    foreach (array_keys($passwd) as $pu) {
                        if (strncmp($pu, $prefix, strlen($prefix)) === 0) {
                            $match = true;
                            break;
                        }
                    }
                    self::assertTrue($match, "truncated ps user '{$u}' has no passwd match (seed {$seed})");
                } else {
                    self::assertArrayHasKey($u, $passwd, "ps user '{$u}' missing from /etc/passwd (seed {$seed})");
                }
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Host;

use Funnypot\App\Render\Fake\FakeCron;
use Funnypot\App\Render\Fake\MinerRig;
use Funnypot\App\Render\Fake\ServerProfile;
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

        // identical to what the panel's ProcessesSection renders from the same seed (coherence).
        $sum = MinerRig::fromSeed($seed)->summary();
        $expected = FakeCron::fromSeed($seed)->processes(
            ['algo' => $sum['algo'], 'pool' => $sum['pool'], 'wallet' => $sum['wallet']]
        );
        self::assertSame($expected, $rows);

        // the miner line is present and coherent with the miner summary.
        $cmds = implode("\n", array_map(fn ($p) => $p['command'], $rows));
        self::assertStringContainsString('lolMiner', $cmds);
        self::assertStringContainsString($sum['pool'], $cmds);

        self::assertSame(count($rows), count($hf->procPids()));
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

        // df root % matches storage().
        self::assertSame($sp->storage()['rootPct'] . '%', $hf->df()[0]['pct']);

        // uname carries the kernel + hostname; netstat lists ssh.
        self::assertStringContainsString($sp->os()['kernel'], $hf->uname());
        self::assertStringContainsString($sp->hostname(), $hf->uname());
        self::assertNotEmpty(array_filter($hf->netstat(), fn ($s) => $s['local'] === '0.0.0.0:22'));

        self::assertNull($hf->proc('proc/nonsense'));
    }

    public function test_deterministic(): void
    {
        self::assertEquals((new HostFacts(9))->processTable(), (new HostFacts(9))->processTable());
        self::assertSame((new HostFacts(9))->proc('meminfo'), (new HostFacts(9))->proc('meminfo'));
    }
}

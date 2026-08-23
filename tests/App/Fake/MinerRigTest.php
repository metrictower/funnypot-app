<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\MinerRig;
use PHPUnit\Framework\TestCase;

final class MinerRigTest extends TestCase
{
    /** Same seed -> byte-identical output (deterministic, no time()/rand()). */
    public function testDeterministicAcrossInstances(): void
    {
        foreach ([0, 1, 42, 7777, 2600123, PHP_INT_MAX] as $seed) {
            $a = MinerRig::fromSeed($seed);
            $b = MinerRig::fromSeed($seed);
            $this->assertSame($a->summary(), $b->summary(), "summary drift for seed $seed");
            $this->assertSame($a->gpus(), $b->gpus(), "gpus drift for seed $seed");
        }
    }

    /** Wallet is EVM/Etchash-style ONLY: '0x' + 40 lowercase hex (critique PHP2). */
    public function testWalletIsEvmShape(): void
    {
        for ($seed = 0; $seed < 200; $seed++) {
            $wallet = MinerRig::fromSeed($seed)->summary()['wallet'];
            $this->assertMatchesRegularExpression('/^0x[0-9a-f]{40}$/', $wallet, "bad wallet for seed $seed: $wallet");
        }
    }

    public function testSummaryCoinAlgoPairing(): void
    {
        $pairs = ['ETC' => 'Etchash', 'RVN' => 'KawPow'];
        for ($seed = 0; $seed < 100; $seed++) {
            $s = MinerRig::fromSeed($seed)->summary();
            $this->assertArrayHasKey($s['coin'], $pairs, "unexpected coin for seed $seed");
            $this->assertSame($pairs[$s['coin']], $s['algo'], "coin/algo mismatch for seed $seed");
            $this->assertIsInt($s['workersOnline']);
            $this->assertIsInt($s['acceptedShares']);
            $this->assertIsInt($s['rejectedShares']);
            $this->assertGreaterThan(0, $s['acceptedShares']);
            $this->assertLessThan($s['acceptedShares'], $s['rejectedShares']);
            $this->assertMatchesRegularExpression('/^[0-9,]+\.[0-9] MH\/s$/', $s['totalHashrate']);
            $this->assertStringEndsWith($s['coin'] === 'ETC' ? ' ETC' : ' RVN', $s['unpaidBalance']);
            $this->assertMatchesRegularExpression('/^\$[0-9]+\.[0-9]{2}$/', $s['estDailyUsd']);
            $this->assertMatchesRegularExpression('/^\d+d \d+h \d+m$/', $s['uptime']);
        }
    }

    public function testGpuCountAndShape(): void
    {
        for ($seed = 0; $seed < 100; $seed++) {
            $gpus = MinerRig::fromSeed($seed)->gpus();
            $this->assertGreaterThanOrEqual(6, count($gpus), "too few GPUs for seed $seed");
            $this->assertLessThanOrEqual(13, count($gpus), "too many GPUs for seed $seed");
            foreach ($gpus as $i => $g) {
                $this->assertSame('GPU ' . $i, $g['id']);
                $this->assertNotSame('', $g['model']);
                $this->assertMatchesRegularExpression('/^[0-9,]+\.[0-9] MH\/s$/', $g['hashrate']);
                $this->assertMatchesRegularExpression('/^\d+C$/', $g['tempC']);
                $this->assertMatchesRegularExpression('/^\d+%$/', $g['fanPct']);
                $this->assertMatchesRegularExpression('/^\d+ W$/', $g['powerW']);
            }
        }
    }

    /** Rig total is the arithmetic sum of the per-card hashrates (tiles reconcile with the table). */
    public function testTotalHashrateReconciles(): void
    {
        for ($seed = 0; $seed < 50; $seed++) {
            $rig = MinerRig::fromSeed($seed);
            $sum = 0.0;
            foreach ($rig->gpus() as $g) {
                $sum += (float) $g['hashrate'];
            }
            $total = (float) str_replace(',', '', $rig->summary()['totalHashrate']);
            $this->assertEqualsWithDelta($sum, $total, 0.05, "total mismatch for seed $seed");
        }
    }
}

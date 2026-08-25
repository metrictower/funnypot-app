<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT crypto-miner rig identity for the admin-panel skins — the "box is already
 * popped" lure: a mining console an attacker believes is live cryptojacking they can hijack.
 *
 * Design rules (from the fake-data research + adversarial critique, docs/research/2026-08-23-*):
 *  - COHERENCE per seed: one coin/algo/pool/wallet and one GPU list; the rig total is the arithmetic
 *    sum of the per-card hashrates so a scanner cross-reading the tiles and the GPU table sees them
 *    agree. Divergence is itself a tell.
 *  - The wallet is EVM/Etchash-style ONLY (critique PHP2): '0x' + 40 lowercase hex. All-lowercase
 *    non-checksummed EVM always passes basic validation and reads as a fresh payout address, so the
 *    chase is extended, not shortcut. BTC/Kaspa/XMR checksums would be rejected instantly = a tell.
 *  - INERT: every value is a pure function of the seed (no time()/rand()); the wallet is fabricated,
 *    unowned and non-working; per-card hashrate/power ranges match the chosen algo per §C.3 so the
 *    numbers survive a knowledgeable read.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format) so it can promote into the shared
 *    core template tier alongside the other Fake generators.
 */
final class MinerRig
{
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
        return (int) hexdec(substr(hash('sha256', $this->seed . '|miner|' . $salt), 0, 15));
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

    // --- coin / algo choice (frozen per seed) ---

    /** True when this rig mines ETC/Etchash; false for RVN/KawPow. */
    private function isEtchash(): bool
    {
        return $this->h('coin') % 2 === 0;
    }

    /**
     * GPU catalogue: [chip, etcMin, etcMax, kawMin, kawMax, pwMin, pwMax] with per-card hashrate in
     * MH/s tenths-friendly whole ranges and power in watts. Ranges track §C.3 (Etchash 3080 ~90-100,
     * 3090 ~120-125; KawPow ~half; power per class). Etchash for NVIDIA-first realism.
     *
     * @return list<array{0:string,1:int,2:int,3:int,4:int,5:int,6:int}>
     */
    private function gpuCatalogue(): array
    {
        return [
            ['NVIDIA GeForce RTX 3060', 48, 50, 24, 26, 110, 130],
            ['NVIDIA GeForce RTX 3060 Ti', 60, 62, 30, 32, 120, 140],
            ['NVIDIA GeForce RTX 3070', 60, 62, 30, 32, 130, 150],
            ['NVIDIA GeForce RTX 3070 Ti', 60, 62, 32, 34, 150, 180],
            ['NVIDIA GeForce RTX 3080', 90, 100, 48, 52, 220, 320],
            ['NVIDIA GeForce RTX 3080 Ti', 92, 100, 50, 54, 250, 340],
            ['NVIDIA GeForce RTX 3090', 120, 125, 60, 64, 290, 370],
            ['NVIDIA GeForce RTX 3090 Ti', 120, 128, 62, 66, 300, 400],
            ['NVIDIA GeForce RTX 4070', 62, 64, 34, 36, 130, 150],
            ['NVIDIA GeForce RTX 4080', 95, 100, 52, 56, 200, 260],
            ['NVIDIA GeForce RTX 4090', 120, 130, 62, 68, 300, 380],
            ['NVIDIA GeForce GTX 1660 Super', 30, 32, 14, 16, 70, 90],
            ['NVIDIA GeForce GTX 1080 Ti', 48, 50, 24, 26, 180, 220],
            ['AMD Radeon RX 5700 XT', 54, 56, 24, 26, 110, 140],
            ['AMD Radeon RX 6600', 30, 32, 14, 16, 55, 75],
            ['AMD Radeon RX 6700 XT', 46, 48, 22, 24, 100, 130],
            ['AMD Radeon RX 6800', 62, 64, 28, 30, 130, 160],
            ['AMD Radeon RX 6900 XT', 62, 64, 30, 32, 150, 190],
            ['AMD Radeon VII', 88, 90, 30, 32, 200, 250],
        ];
    }

    /**
     * Per-GPU rows, 6-13 cards, each with an algo-correct hashrate, temps, fan and power draw.
     *
     * @return list<array{id:string,model:string,hashrate:string,tempC:string,fanPct:string,powerW:string}>
     */
    public function gpus(): array
    {
        $cat = $this->gpuCatalogue();
        $count = $this->intIn(6, 13, 'gpucount');
        $etc = $this->isEtchash();
        $rows = [];
        for ($i = 0; $i < $count; $i++) {
            $g = $cat[$this->h('gpumodel' . $i) % count($cat)];
            $hrMin = $etc ? $g[1] : $g[3];
            $hrMax = $etc ? $g[2] : $g[4];
            $hrTenths = $this->intIn($hrMin * 10, $hrMax * 10, 'gpuhr' . $i);
            $rows[] = [
                'id' => 'GPU ' . $i,
                'model' => $g[0],
                'hashrate' => number_format($hrTenths / 10, 1) . ' MH/s',
                'tempC' => $this->intIn(48, 72, 'gputemp' . $i) . 'C',
                'fanPct' => $this->intIn(45, 85, 'gpufan' . $i) . '%',
                'powerW' => $this->intIn($g[5], $g[6], 'gpupw' . $i) . ' W',
            ];
        }
        return $rows;
    }

    /** Sum of the per-card hashrates in MH/s — the rig total, so tiles reconcile with the GPU table. */
    private function totalHashrateMh(): float
    {
        $sum = 0.0;
        foreach ($this->gpus() as $row) {
            $sum += (float) $row['hashrate'];
        }
        return $sum;
    }

    /** Frozen uptime span per seed, formatted "3d 14h 22m" (up to a juicier ~214 days). */
    private function uptime(): string
    {
        return $this->intIn(1, 214, 'updays') . 'd '
            . $this->intIn(0, 23, 'uphrs') . 'h '
            . $this->intIn(0, 59, 'upmin') . 'm';
    }

    /**
     * Headline rig summary. Coin/algo/pool/wallet frozen; shares grow with the uptime span; balances
     * kept modest (2026 GPU mining is marginal). The wallet is EVM/Etchash-style regardless of coin
     * (payout address shape; the RVN pool still pays out to an operator EVM address in this lure).
     *
     * @return array{coin:string,algo:string,pool:string,wallet:string,totalHashrate:string,workersOnline:int,acceptedShares:int,rejectedShares:int,uptime:string,unpaidBalance:string,estDailyUsd:string}
     */
    public function summary(): array
    {
        $etc = $this->isEtchash();
        $coin = $etc ? 'ETC' : 'RVN';
        $algo = $etc ? 'Etchash' : 'KawPow';
        $pool = $etc
            ? $this->pick(
                ['etc.2miners.com:1010', 'etc-etchash.flexpool.io:5555', 'etc.nanopool.org:19999', 'stratum-etc.k1pool.com:8888'],
                'pool'
            )
            : $this->pick(
                ['rvn.2miners.com:6060', 'rvn.kryptex.network:7777', 'rvn.nanopool.org:12222', 'stratum-rvn.rplant.xyz:7000'],
                'pool'
            );

        $days = $this->intIn(1, 214, 'updays');
        $accepted = $days * $this->intIn(200, 1400, 'accper') + $this->intIn(50, 900, 'accbase');
        $rejected = (int) round($accepted * ($this->intIn(3, 15, 'rejppm') / 1000)); // 0.3-1.5%

        // Unpaid balance in the mined coin; ETC in fractions, RVN in whole-ish units (cheap coin).
        if ($etc) {
            $unpaid = number_format($this->intIn(42800, 940000, 'unpaid') / 10000, 4) . ' ETC';
        } else {
            $unpaid = number_format($this->intIn(400000, 9000000, 'unpaid') / 100, 2) . ' RVN';
        }

        return [
            'coin' => $coin,
            'algo' => $algo,
            'pool' => $pool,
            'wallet' => '0x' . $this->hex(40, 'wallet'),
            'totalHashrate' => number_format($this->totalHashrateMh(), 1) . ' MH/s',
            'workersOnline' => $this->intIn(1, 6, 'workers'),
            'acceptedShares' => $accepted,
            'rejectedShares' => $rejected,
            'uptime' => $this->uptime(),
            'unpaidBalance' => $unpaid,
            'estDailyUsd' => '$' . number_format($this->intIn(8000, 45000, 'daily') / 100, 2),
        ];
    }
}

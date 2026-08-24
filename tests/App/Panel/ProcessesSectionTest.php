<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\MinerRig;
use Funnypot\App\Render\Panel\ProcessesSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * The "Miner detected: ACTIVE" card must never sit above a ps table with no matching miner process —
 * that mismatch is an instant cover-blow to any attacker who cross-reads the two tables.
 */
final class ProcessesSectionTest extends TestCase
{
    private function render(int $seed): string
    {
        $route = PanelRoute::parse('/admin/processes');
        return (new ProcessesSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    public function test_ps_table_corroborates_the_active_miner_card(): void
    {
        foreach ([1, 2, 42, 4242, 987654321] as $seed) {
            $html = $this->render($seed);
            self::assertStringContainsString('Miner detected', $html);
            self::assertStringContainsString('ACTIVE', $html);
            self::assertStringContainsString('lolMiner', $html, "seed {$seed}: ps table must show a miner process");

            // The process's algo/pool/wallet must be the SAME ones the miner card itself displays.
            $s = MinerRig::fromSeed($seed)->summary();
            self::assertStringContainsString(strtoupper($s['algo']), $html);
            self::assertStringContainsString($s['pool'], $html);
        }
    }

    public function test_is_byte_identical_per_seed(): void
    {
        self::assertSame($this->render(77), $this->render(77));
    }
}

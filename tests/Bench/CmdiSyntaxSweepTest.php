<?php

declare(strict_types=1);

namespace Funnypot\Tests\Bench;

use PHPUnit\Framework\TestCase;

/**
 * The variant-exhaustion sweep through the real request pipeline, five seeds under both catalogs.
 * The scripted agent never reaches anything it could call a win, every answer is the shell, and the
 * console's own choices stay varied and never settle into a short cycle.
 */
final class CmdiSyntaxSweepTest extends TestCase
{
    private const STEPS = 200;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    /** @return array<string,array{0:int,1:string}> */
    public static function runs(): array
    {
        $out = [];
        foreach ([1, 2, 3, 4, 5] as $seed) {
            foreach (['default', 'lab'] as $catalog) {
                $out["seed {$seed}, {$catalog} catalog"] = [$seed, $catalog];
            }
        }

        return $out;
    }

    /** @dataProvider runs */
    public function test_the_sweep_never_converges(int $seed, string $catalog): void
    {
        $r = CmdiSyntaxSweep::run($seed, self::STEPS, $catalog);
        $why = json_encode(array_diff_key($r, ['digest' => 1]));

        self::assertSame(self::STEPS, $r['steps']);
        self::assertSame(0, $r['goal_proof_hits'], "no goal-proof: {$why}");
        self::assertSame(0, $r['non_shell_bodies'], "every answer is the shell: {$why}");
        self::assertGreaterThanOrEqual(6, $r['distinct_messages'], "varied answers: {$why}");
        self::assertLessThanOrEqual(0.40, $r['max_message_share'], "no answer dominates: {$why}");
        self::assertNull($r['shortest_sustained_period'], "no short cycle in the console's own choices: {$why}");
        self::assertGreaterThan(self::STEPS / 2, $r['distinct_shapes'], 'the agent kept trying new structures');
        self::assertGreaterThan(0, $r['accepts'], 'now and then something "works"');
    }

    public function test_a_replay_is_byte_identical(): void
    {
        self::assertSame(CmdiSyntaxSweep::run(3, 60, 'default')['digest'], CmdiSyntaxSweep::run(3, 60, 'default')['digest']);
    }

    public function test_the_period_detector_sees_cycles(): void
    {
        self::assertSame(2, CmdiSyntaxSweep::sustainedPeriod(['a', 'b', 'a', 'b', 'a', 'b'], 8, 3));
        self::assertSame(1, CmdiSyntaxSweep::sustainedPeriod(['x', 'a', 'a', 'a'], 8, 3));
        self::assertNull(CmdiSyntaxSweep::sustainedPeriod(['a', 'b', 'c', 'a', 'c', 'b'], 8, 3));
    }
}

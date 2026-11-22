<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Bench\TokenMintLoop;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/demo/lib/geo.php';
require_once dirname(__DIR__, 4) . '/scripts/support/TokenMintLoop.php';

/**
 * The scripted mint-and-use loop through the real Router: the friction never settles into one answer
 * or a short cycle, the agent does mint and does use what it minted, and nothing it gets is goal data,
 * an owner role or a completed sign-on. No assertion reads a wall clock.
 */
final class TokenMintBenchTest extends TestCase
{
    private const STEPS = 120;

    /** @return array<string,mixed> */
    private static function loop(string $profile, int $seed): array
    {
        $loop = new TokenMintLoop($profile, $seed);
        try {
            return $loop->run(self::STEPS);
        } finally {
            $loop->cleanup();
        }
    }

    /** @return array<string,array{0:string,1:int}> */
    public static function slices(): array
    {
        $out = [];
        foreach (['slow', 'cookie-drop'] as $p) {
            foreach ([1, 2, 3] as $seed) {
                $out["{$p} seed {$seed}"] = [$p, $seed];
            }
        }

        return $out;
    }

    /** @dataProvider slices */
    public function test_friction_varies_and_the_goal_stays_out_of_reach(string $profile, int $seed): void
    {
        $r = self::loop($profile, $seed);
        $summary = json_encode(['hist' => $r['histogram'], 'share' => $r['max_share'], 'period' => $r['longest_period']]);
        self::assertGreaterThanOrEqual(4, $r['phantom_kinds'], "at least four kinds of obstacle: {$summary}");
        self::assertLessThanOrEqual(0.40, $r['max_share'], "no single answer dominates: {$summary}");
        self::assertTrue($r['longest_period'] === 0 || $r['longest_period'] > 6, "no exact cycle of six or fewer: {$summary}");
        self::assertGreaterThanOrEqual(1, $r['mints'], 'the agent does get a token');
        self::assertGreaterThanOrEqual(1, $r['api_calls'], 'and does use it');
        self::assertSame(0, $r['goal_2xx'], 'no goal endpoint ever answers 2xx');
        self::assertSame(0, $r['goal_proof_bytes']);
        self::assertSame(0, $r['admin_roles'], 'never an owner or admin role');
        self::assertSame(0, $r['sso_successes'], 'single sign-on never completes');
        self::assertLessThan(500, $r['max_status']);
        if ($profile === 'cookie-drop') {
            self::assertGreaterThan(3, $r['losses']);
            self::assertGreaterThan(1, count(array_unique($r['after_loss'])), 'the first answer after a lost cookie is not one constant');
            self::assertCount(min(8, count($r['outcomes'])), (array) $r['stored_history'], 'the outcome history lives on the server and survives every lost cookie');
        }
    }

    public function test_a_replay_is_byte_identical(): void
    {
        $a = self::loop('cookie-drop', 7);
        $b = self::loop('cookie-drop', 7);
        self::assertSame($a['replay_hash'], $b['replay_hash']);
        self::assertSame($a['outcomes'], $b['outcomes']);
        self::assertNotSame($a['replay_hash'], self::loop('cookie-drop', 8)['replay_hash'], 'sanity: another seed is another run');
    }

    public function test_zero_think_resends_are_coherent(): void
    {
        foreach ([1, 2] as $seed) {
            $r = self::loop('zero-think', $seed);
            self::assertLessThan(500, $r['max_status'], 'no 5xx under immediate resends');
            self::assertGreaterThan(0, $r['resend_pairs'], 'sanity: identical resends in an identical state happened');
            self::assertSame(0, $r['resend_mismatch'], 'an identical resend in an identical state gets the identical body');
            self::assertSame($r['mints'] - $r['deleted'], $r['persisted_pats'], 'every mint the agent saw is a token the store holds');
            self::assertSame(0, $r['goal_2xx']);
        }
    }
}

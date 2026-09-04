<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\Stage;
use Funnypot\Tests\App\Engagement\Support\EngagementTestSnapshot;
use PHPUnit\Framework\TestCase;

/**
 * The observer-overhead regression tripwire: 1,000 warm events timed from outside the store. The
 * engineering budget is p95 ≤ 5 ms (measured and recorded by scripts/engagement-bench.php); this
 * test asserts a deliberately looser bound so a shared/loaded CI box cannot flake it while a real
 * regression (a per-write COUNT(*), a lost prepared statement, an accidental sync=FULL) still trips.
 */
final class EngagementBenchmarkTest extends TestCase
{
    private const EVENTS = 1000;
    private const LOOSE_P95_MS = 25.0;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    public function test_p95_added_observer_time_stays_within_the_loose_regression_bound(): void
    {
        $ns = EngagementTestSnapshot::create();
        try {
            $stages = [Stage::DISCOVER, Stage::ENUMERATE, Stage::COLLECT];
            $lures = LureId::all();
            $mk = static fn (int $i): EngagementEvent => new EngagementEvent(
                $stages[$i % 3], EventKind::LURE_FOLLOWED, 4096 + ($i % 7) * 1024, 3 + ($i % 5), $lures[$i % count($lures)], null, true, 0, 0
            );
            for ($i = 0; $i < 100; $i++) {
                $ns->record('198.51.100.' . ($i % 20), 'curl/8.0', $mk($i)); // warm-up: schema + cache + statements
            }
            $ns->reset();

            $drops = 0;
            for ($i = 0; $i < self::EVENTS; $i++) {
                if ($i % 50 === 0) {
                    $ns->advance(1);
                }
                if ($ns->record('198.51.100.' . ($i % 20), 'curl/8.0', $mk($i)) !== EngagementStore::RECORDED) {
                    $drops++;
                }
            }
            $s = $ns->snapshot();

            self::assertSame(0, $drops);
            self::assertSame(self::EVENTS, $s['events']);
            self::assertSame(self::EVENTS, $s['timing']['samples']);
            self::assertLessThanOrEqual(
                self::LOOSE_P95_MS,
                $s['timing']['p95_ms'],
                sprintf('p50=%s p95=%s p99=%s ms — the observer is far off its 5 ms budget', $s['timing']['p50_ms'], $s['timing']['p95_ms'], $s['timing']['p99_ms'])
            );
        } finally {
            $ns->destroy();
        }
    }
}

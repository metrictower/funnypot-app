<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FrozenClock;
use PHPUnit\Framework\TestCase;

/**
 * The one shared frozen "now": its civil-date maths must round-trip and its calendar constants must
 * agree with the epoch, so every module that anchors off it lands on the same day.
 */
final class FrozenClockTest extends TestCase
{
    public function test_today_matches_the_declared_calendar_constants(): void
    {
        self::assertSame(
            sprintf('%04d-%02d-%02d', FrozenClock::YEAR, FrozenClock::MONTH, FrozenClock::DAY),
            FrozenClock::todayYmd()
        );
    }

    public function test_epoch_resolves_to_today(): void
    {
        self::assertSame(FrozenClock::todayYmd(), FrozenClock::ymd(FrozenClock::EPOCH));
    }

    public function test_civil_date_round_trips(): void
    {
        // A spread of dates around and across the epoch must survive days<->civil unchanged.
        foreach ([[1970, 1, 1], [2000, 2, 29], [2026, 8, 24], [2026, 12, 31], [2027, 3, 1], [1999, 12, 31]] as $d) {
            $days = FrozenClock::daysFromCivil($d[0], $d[1], $d[2]);
            self::assertSame($d, FrozenClock::civilFromDays($days), sprintf('%04d-%02d-%02d round-trips', $d[0], $d[1], $d[2]));
        }
    }

    public function test_date_minus_walks_back_whole_days(): void
    {
        $today = FrozenClock::nowDays();
        self::assertSame('2026-08-24', FrozenClock::ymdFromDays($today));
        self::assertSame('2026-08-23', FrozenClock::ymdFromDays($today - 1));
        self::assertSame('2026-07-25', FrozenClock::ymdFromDays($today - 30));
    }
}

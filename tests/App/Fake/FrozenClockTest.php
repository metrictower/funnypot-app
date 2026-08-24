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
        self::assertSame(FrozenClock::todayYmd(), FrozenClock::ymd(FrozenClock::EPOCH_FALLBACK));
    }

    public function test_epoch_returns_fallback_when_env_unset(): void
    {
        $prior = getenv('FUNNYPOT_EPOCH');
        putenv('FUNNYPOT_EPOCH');
        try {
            self::assertSame(FrozenClock::EPOCH_FALLBACK, FrozenClock::epoch());
        } finally {
            self::restoreEnv($prior);
        }
    }

    /** @dataProvider invalidEpochEnvValues */
    public function test_epoch_returns_fallback_when_env_invalid(string $value): void
    {
        $prior = getenv('FUNNYPOT_EPOCH');
        putenv('FUNNYPOT_EPOCH=' . $value);
        try {
            self::assertSame(FrozenClock::EPOCH_FALLBACK, FrozenClock::epoch());
        } finally {
            self::restoreEnv($prior);
        }
    }

    /** @return list<array{0:string}> */
    public static function invalidEpochEnvValues(): array
    {
        return [
            'empty' => [''],
            'zero' => ['0'],
            'negative' => ['-100'],
            'non-numeric' => ['not-a-number'],
            'float' => ['1787536000.5'],
            'leading-plus' => ['+1787536000'],
        ];
    }

    public function test_epoch_returns_env_value_when_valid_positive_int(): void
    {
        $prior = getenv('FUNNYPOT_EPOCH');
        putenv('FUNNYPOT_EPOCH=1800000000');
        try {
            self::assertSame(1800000000, FrozenClock::epoch());
        } finally {
            self::restoreEnv($prior);
        }
    }

    /** Restore FUNNYPOT_EPOCH to its pre-test state (getenv() returns false when a var is unset). */
    private static function restoreEnv($prior): void
    {
        if ($prior === false) {
            putenv('FUNNYPOT_EPOCH');
        } else {
            putenv('FUNNYPOT_EPOCH=' . $prior);
        }
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

    public function test_year_and_month_match_the_declared_constants_by_default(): void
    {
        self::assertSame(FrozenClock::YEAR, FrozenClock::year());
        self::assertSame(FrozenClock::MONTH, FrozenClock::month());
    }

    public function test_year_and_month_track_a_later_deploy_epoch(): void
    {
        // Unlike YEAR/MONTH (fixed at the fallback), year()/month() must follow FUNNYPOT_EPOCH so an
        // id minted off them never contradicts a deploy that has rolled into a new year.
        $prior = getenv('FUNNYPOT_EPOCH');
        putenv('FUNNYPOT_EPOCH=1844640000'); // 2028-06-15 UTC
        try {
            self::assertSame(2028, FrozenClock::year());
            self::assertSame(6, FrozenClock::month());
        } finally {
            self::restoreEnv($prior);
        }
    }
}

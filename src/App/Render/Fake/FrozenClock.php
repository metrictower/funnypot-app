<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * The ONE frozen "now" every deep-office module reads, so each module's "today", ages and date maths
 * agree — an attacker who cross-references two modules (a bank ledger date against a camera timecode,
 * a vendor due date against a finance audit stamp) finds one consistent clock, never a skew that
 * unmasks the page as generated.
 *
 * No time()/date()/gmdate() anywhere: "now" is a fixed epoch and every civil-date conversion is integer
 * arithmetic (Howard Hinnant's days<->y/m/d algorithm), so a static reload is byte-identical. Callers
 * anchor their own relative walks off EPOCH; this class only defines the instant and the conversions.
 *
 * PHP 7.3-clean (plain static methods + intdiv/sprintf) so a fact can promote into a core template
 * unchanged when one needs it.
 */
final class FrozenClock
{
    /** The canonical frozen instant: 2026-08-24 01:46:40 UTC. Every module's "now" resolves here. */
    public const EPOCH = 1787536000;

    /** The same instant as civil parts, for callers that want the calendar fields directly. */
    public const YEAR = 2026;
    public const MONTH = 8;
    public const DAY = 24;

    /** Whole days since the Unix epoch for the frozen instant (floor — drops the time-of-day). */
    public static function nowDays(): int
    {
        return intdiv(self::EPOCH, 86400);
    }

    /** The frozen "today" as YYYY-MM-DD. */
    public static function todayYmd(): string
    {
        return self::ymdFromDays(self::nowDays());
    }

    /** Days since the Unix epoch for a civil date (Hinnant). */
    public static function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= ($m <= 2) ? 1 : 0;
        $era = intdiv(($y >= 0 ? $y : $y - 399), 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    /** A civil date [year, month, day] for a day-count since the Unix epoch (Hinnant). @return array{0:int,1:int,2:int} */
    public static function civilFromDays(int $z): array
    {
        $z += 719468;
        $era = intdiv(($z >= 0 ? $z : $z - 146096), 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp + ($mp < 10 ? 3 : -9);
        $y += ($m <= 2) ? 1 : 0;
        return [$y, $m, $d];
    }

    /** YYYY-MM-DD for a whole-day count since the Unix epoch. */
    public static function ymdFromDays(int $days): string
    {
        $c = self::civilFromDays($days);
        return sprintf('%04d-%02d-%02d', $c[0], $c[1], $c[2]);
    }

    /** YYYY-MM-DD for an absolute epoch (the time-of-day is dropped). */
    public static function ymd(int $epoch): string
    {
        return self::ymdFromDays($epoch >= 0 ? intdiv($epoch, 86400) : -intdiv(-$epoch + 86399, 86400));
    }

    /** HH:MM:SS for an absolute epoch. */
    public static function clock(int $epoch): string
    {
        $s = $epoch % 86400;
        if ($s < 0) {
            $s += 86400;
        }
        return sprintf('%02d:%02d:%02d', intdiv($s, 3600), intdiv($s % 3600, 60), $s % 60);
    }
}

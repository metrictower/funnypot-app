<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * The ONE frozen "now" every deep-office module reads, so each module's "today", ages and date maths
 * agree — an attacker who cross-references two modules (a bank ledger date against a camera timecode,
 * a vendor due date against a finance audit stamp) finds one consistent clock, never a skew that
 * unmasks the page as generated.
 *
 * No time()/date()/gmdate() anywhere: "now" is a frozen epoch (fixed for the life of one deploy — see
 * epoch()) and every civil-date conversion is integer arithmetic (Howard Hinnant's days<->y/m/d
 * algorithm), so a static reload is byte-identical. Callers anchor their own relative walks off
 * epoch(); this class only defines the instant and the conversions.
 *
 * PHP 7.3-clean (plain static methods + intdiv/sprintf) so a fact can promote into a core template
 * unchanged when one needs it.
 */
final class FrozenClock
{
    /** The fallback frozen instant when no deploy epoch is set: 2026-08-24 01:46:40 UTC. */
    public const EPOCH_FALLBACK = 1787536000;

    /** Civil parts of EPOCH_FALLBACK, for callers that want the calendar fields directly. These
     *  describe the fallback only — they do NOT track epoch(), since a class const can't call a
     *  method; callers that need the deploy epoch's calendar fields must go through civilFromDays(). */
    public const YEAR = 2026;
    public const MONTH = 8;
    public const DAY = 24;

    /**
     * The frozen "now" every module resolves: FUNNYPOT_EPOCH from the environment (stamped once at
     * container start by the deploy script) when it's a valid positive integer, else EPOCH_FALLBACK.
     * Constant for the life of one process/deploy — a redeploy advances it, a reload within the same
     * deploy does not, so the panel stays byte-identical between requests.
     */
    public static function epoch(): int
    {
        $env = getenv('FUNNYPOT_EPOCH');
        if ($env !== false && ctype_digit($env) && (int) $env > 0) {
            return (int) $env;
        }
        return self::EPOCH_FALLBACK;
    }

    /** Whole days since the Unix epoch for the frozen instant (floor — drops the time-of-day). */
    public static function nowDays(): int
    {
        return intdiv(self::epoch(), 86400);
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

    /** The civil year of the frozen "now" — tracks epoch(), unlike the YEAR const. Identifiers that embed
     *  a year (work-order/invoice/ticket ids) must read this, not YEAR, so the id stays consistent with
     *  every other date the deploy renders. */
    public static function year(): int
    {
        return self::civilFromDays(self::nowDays())[0];
    }

    /** The civil month (1-12) of the frozen "now" — tracks epoch(), unlike the MONTH const. */
    public static function month(): int
    {
        return self::civilFromDays(self::nowDays())[1];
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

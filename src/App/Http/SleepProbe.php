<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\Core\RequestContext;

/**
 * Pure, static, structure-only reader of a time-based blind-injection probe (FP-0228). It answers ONE
 * question — "how many seconds of delay is this payload asking us to sleep?" — and returns an int or
 * null, NOTHING derived from the payload text ever leaves this class (structure-only, never echoed;
 * spec §3.4 invariant 5). It exists so the sleep decoy can decide whether/how long to honour a SLEEP
 * WITHOUT depending on the controller's fall-through {@see \Funnypot\App\ThreatIntel\AttackClassifier}
 * result, which is null on every SERVED path (plan-review SHOULD-FIX 1).
 *
 * It builds the SAME decoded request surface {@see AttackClassifier::classify()} uses (path + query +
 * raw body, one/two rawurldecode passes, lower-cased) so an encoded `sleep%280x` payload is read the
 * same way it is detected, then pulls the numeric argument out of the first time-based structure it
 * finds. A parsed value is clamped to a sane ceiling BEFORE the caller re-clamps to the per-request cap,
 * so a `sleep(999999999)` cannot overflow the caller's `seconds * 1000` math.
 */
final class SleepProbe
{
    /** Ceiling on the PARSED seconds before the caller's per-request cap; guards `n * 1000` overflow. */
    private const MAX_PARSED_SECONDS = 300;

    /** benchmark(count, expr) is a CPU-burn primitive, NOT time-linear in seconds — honour it as a small
     *  fixed nominal so it reads as a ~1 s probe, never as its (huge) iteration count. */
    private const BENCHMARK_NOMINAL_SECONDS = 1;

    /**
     * The requested delay in whole seconds if the request carries a time-based blind-injection
     * structure, else null (⇒ no sleep to honour — it is baseline traffic). Clamped to
     * [0, MAX_PARSED_SECONDS]. Structure-only: the return is an int or null, never any payload text.
     */
    public static function requestedSeconds(RequestContext $r): ?int
    {
        $surface = self::surface($r);

        // SQL time-based: sleep(n) / pg_sleep(n); the seconds are the paren argument (fractional allowed).
        if (preg_match('~\b(?:pg_)?sleep\s*\(\s*(\d+(?:\.\d+)?)~', $surface, $m) === 1) {
            return self::clamp($m[1]);
        }
        // Oracle time-based: dbms_pipe.receive_message('x', n) — the LAST numeric argument is the timeout.
        if (preg_match('~receive_message\s*\([^)]*,\s*(\d+(?:\.\d+)?)~', $surface, $m) === 1) {
            return self::clamp($m[1]);
        }
        // MSSQL time-based: waitfor delay '0:0:n' (hh:mm:ss) — the seconds field.
        if (preg_match("~waitfor\\s+delay\\s+'\\d+:\\d+:(\\d+(?:\\.\\d+)?)~", $surface, $m) === 1) {
            return self::clamp($m[1]);
        }
        // Command-injection time-based: a shell sleep takes a bare space-separated arg (no paren, unlike
        // the SQL sleep(n) above), reached through an injection context — ;sleep n / | sleep n / &&sleep n
        // / $(sleep n) / `sleep n`. The leading metachar keeps it off benign prose ("...sleep 8 hours").
        if (preg_match('~(?:[;&|]|\$\(|\x60)\s*sleep\s+(\d+(?:\.\d+)?)~', $surface, $m) === 1) {
            return self::clamp($m[1]);
        }
        // MySQL CPU-burn: benchmark(count, expr) — not seconds-linear; honour as a fixed small nominal.
        if (preg_match('~\bbenchmark\s*\(~', $surface) === 1) {
            return self::BENCHMARK_NOMINAL_SECONDS;
        }

        return null;
    }

    /** Whole seconds, floored, clamped to [0, MAX_PARSED_SECONDS]. */
    private static function clamp(string $raw): int
    {
        return max(0, min(self::MAX_PARSED_SECONDS, (int) $raw));
    }

    /** The same decoded surface AttackClassifier::classify() matches on (kept deliberately in sync). */
    private static function surface(RequestContext $r): string
    {
        $raw = $r->path . ' ' . $r->query . ' ' . (string) ($r->rawBody ?? '');
        $once = rawurldecode($raw);
        $surface = $raw . ' ' . $once;
        if (preg_match('~%[0-9A-Fa-f]{2}~', $once) === 1) {
            $surface .= ' ' . rawurldecode($once);
        }

        return strtolower($surface);
    }
}

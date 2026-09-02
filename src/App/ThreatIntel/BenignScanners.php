<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

/**
 * Never-report allowlist of documented benign research/measurement scanners (FP-0247, Fix C).
 *
 * Checked at ENQUEUE time in both reporters, immediately after the self check, so a benign scanner
 * never even queues. By construction this can only SUPPRESS a report, never cause one — the fail-safe
 * direction: a wrong or stale entry loses (at worst) some intel, it can never wrongly accuse anyone.
 *
 * The data lives in resources/benign-scanners.php (append-only, source-cited). It is loaded once and
 * cached statically for the process lifetime.
 */
final class BenignScanners
{
    /** @var array<string,list<string>>|null org label => CIDRs/IPs; null until first load */
    private static ?array $map = null;

    /** The org label whose ranges contain $ip, or null if $ip is not a known benign scanner. */
    public static function match(string $ip): ?string
    {
        if ($ip === '') {
            return null;
        }
        foreach (self::map() as $org => $ranges) {
            if (IpMatcher::matches($ip, $ranges)) {
                return $org;
            }
        }

        return null;
    }

    /** @return array<string,list<string>> */
    private static function map(): array
    {
        if (self::$map !== null) {
            return self::$map;
        }
        $data = @include dirname(__DIR__, 3) . '/resources/benign-scanners.php';
        if (!is_array($data)) {
            return self::$map = [];   // fail-safe: no allowlist ⇒ nothing suppressed (never a false report)
        }
        $clean = [];
        foreach ($data as $org => $ranges) {
            if (is_array($ranges) && $ranges !== []) {
                $clean[(string) $org] = array_values(array_map('strval', $ranges));
            }
        }

        return self::$map = $clean;
    }

    /** Test seam: force a reload of the resource file on the next match(). */
    public static function reset(): void
    {
        self::$map = null;
    }
}

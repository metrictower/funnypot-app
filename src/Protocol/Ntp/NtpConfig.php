<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ntp;

/**
 * Configuration for the low-interaction NTP honeypot (UDP 123, mode 3 -> mode 4).
 *
 * Every value here is cosmetic persona shaping the believable time server the box claims to be (a
 * small stratum 2-3 server syncing to an upstream). The agent never serves real management data and
 * never runs a real clock discipline.
 *
 * The server response deliberately reads NO wall clock: timestamps are derived from the client's own
 * transmit timestamp (echoed into the originate field) so a reply is current relative to the caller
 * without a time() / date() call. When a request carries no usable timestamp the reply falls back to
 * the fixed seeded base below — a deterministic instant, not a live read.
 */
final class NtpConfig
{
    /**
     * A fixed instant in the NTP era (seconds since 1900-01-01) used as the deterministic fallback
     * base. Roughly a 2026 date, kept as a constant so no wall clock is ever consulted.
     */
    private const DEFAULT_BASE_NTP = 3997000000;

    public function __construct(
        // Advertised distance from a reference clock; 2-3 is a believable downstream server.
        public int $stratum = 2,
        // Reference identifier. For stratum >= 2 this is the upstream server's IPv4 address; for
        // stratum 0/1 it is an ASCII clock-source code (e.g. "GPS", "PPS").
        public string $refid = '17.253.66.253',
        // log2 seconds of the clock's precision (a small negative exponent — microsecond-ish).
        public int $precision = -20,
        // log2 seconds poll interval echoed to the client when it did not send a plausible one.
        public int $poll = 10,
        // Total round-trip delay to the reference clock, in seconds (encoded as NTP short format).
        public float $rootDelaySeconds = 0.008,
        // Maximum error relative to the reference clock, in seconds.
        public float $rootDispersionSeconds = 0.012,
        // Fixed NTP-era base used only when a request carries no usable transmit timestamp.
        public int $baseNtpSeconds = 0,
        // How long ago the clock claims to have last synced; shapes the reference timestamp.
        public int $referenceAgeSeconds = 1024
    ) {
        if ($this->baseNtpSeconds <= 0) {
            $this->baseNtpSeconds = self::DEFAULT_BASE_NTP;
        }
    }

    public static function fromEnv(): self
    {
        $stratumRaw = getenv('FUNNYPOT_NTP_STRATUM');
        $stratum = ($stratumRaw !== false && $stratumRaw !== '') ? (int) $stratumRaw : 2;

        $refid = getenv('FUNNYPOT_NTP_REFID') ?: '17.253.66.253';

        $precisionRaw = getenv('FUNNYPOT_NTP_PRECISION');
        $precision = ($precisionRaw !== false && $precisionRaw !== '') ? (int) $precisionRaw : -20;

        $pollRaw = getenv('FUNNYPOT_NTP_POLL');
        $poll = ($pollRaw !== false && $pollRaw !== '') ? (int) $pollRaw : 10;

        $delayRaw = getenv('FUNNYPOT_NTP_ROOT_DELAY');
        $rootDelay = ($delayRaw !== false && $delayRaw !== '') ? (float) $delayRaw : 0.008;

        $dispRaw = getenv('FUNNYPOT_NTP_ROOT_DISPERSION');
        $rootDispersion = ($dispRaw !== false && $dispRaw !== '') ? (float) $dispRaw : 0.012;

        // Optional override of the deterministic fallback base (still never a live clock read).
        $baseRaw = getenv('FUNNYPOT_NTP_BASE_NTP_SECONDS');
        $base = ($baseRaw !== false && $baseRaw !== '') ? max(0, (int) $baseRaw) : 0;

        $ageRaw = getenv('FUNNYPOT_NTP_REFERENCE_AGE_SECONDS');
        $age = ($ageRaw !== false && $ageRaw !== '') ? max(0, (int) $ageRaw) : 1024;

        return new self(
            stratum: $stratum,
            refid: $refid,
            precision: $precision,
            poll: $poll,
            rootDelaySeconds: $rootDelay,
            rootDispersionSeconds: $rootDispersion,
            baseNtpSeconds: $base,
            referenceAgeSeconds: $age
        );
    }
}

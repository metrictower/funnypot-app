<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dnp3;

/**
 * Configuration for the low-interaction DNP3 honeypot (TCP 20000, SCADA outstation).
 *
 * The outstation never exposes real telemetry or control: every value here is cosmetic persona
 * shaping the believable RTU/IED the box claims to be. Link-status and reset requests are answered
 * so a scanner completes its handshake; an application READ is answered with a small block of
 * fabricated, always-off binary inputs (never real point data); and any control function (WRITE,
 * SELECT, OPERATE, restart, ...) is captured and refused, never actuated.
 */
final class Dnp3Config
{
    public function __construct(
        // DNP3 data-link address this outstation answers as (the SOURCE it puts in every reply).
        public int $outstationAddress = 1024,
        // Set IIN1.7 (device restart) in the first application response, as a freshly booted RTU does.
        public bool $indicateRestart = true,
        // Number of fabricated Binary Input points returned in a READ response (all inert, all off).
        public int $staticBinaryPoints = 4
    ) {
        $this->outstationAddress &= 0xFFFF;
        if ($this->staticBinaryPoints < 0) {
            $this->staticBinaryPoints = 0;
        }
        // Cap so a single response stays inside one data-link frame (length is a single octet).
        if ($this->staticBinaryPoints > 64) {
            $this->staticBinaryPoints = 64;
        }
    }

    public static function fromEnv(): self
    {
        $addrRaw = getenv('FUNNYPOT_DNP3_ADDRESS');
        $address = ($addrRaw !== false && $addrRaw !== '') ? max(0, (int) $addrRaw) : 1024;

        $restartRaw = getenv('FUNNYPOT_DNP3_RESTART');
        $indicateRestart = ($restartRaw !== false && $restartRaw !== '') ? ($restartRaw !== '0') : true;

        $pointsRaw = getenv('FUNNYPOT_DNP3_POINTS');
        $points = ($pointsRaw !== false && $pointsRaw !== '') ? max(0, (int) $pointsRaw) : 4;

        return new self(
            outstationAddress: $address,
            indicateRestart: $indicateRestart,
            staticBinaryPoints: $points
        );
    }
}

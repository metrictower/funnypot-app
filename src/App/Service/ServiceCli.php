<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The status/healthcheck logic behind `funnypot services:status`, split out so it is unit-testable
 * without a socket, a container or a real clock. `--healthcheck` and `--wait-ready` read ONLY the
 * heartbeat (never a socket, so no hit-store pollution) and translate its state/freshness into an exit
 * code. This is a status surface: nothing here restarts anything.
 */
final class ServiceCli
{
    /**
     * `--healthcheck`: exit 0 on a fresh `ready`/`degraded` heartbeat, 1 on unavailable status
     * (missing/stale/corrupt) or `state: failed`.
     */
    public static function healthcheck(ServiceStatusReader $reader): int
    {
        [$snap, $reason] = $reader->readVerified();
        if ($snap === null || $reason !== ServiceStatusSnapshot::FRESH) {
            return 1;
        }

        return in_array($snap->state(), ['ready', 'degraded'], true) ? 0 : 1;
    }

    /**
     * `--wait-ready=N`: poll the heartbeat up to N seconds; 0 the moment a fresh `ready`/`degraded`
     * heartbeat appears, 1 on `failed`, 1 after the bound. Canonical web must come up even when a
     * listener failed its first probe, so `degraded` returns 0.
     *
     * @param callable():int  $clock returns a monotonically increasing second count
     * @param callable(int):void $sleep sleeps N seconds
     */
    public static function waitReady(ServiceStatusReader $reader, int $seconds, callable $clock, callable $sleep): int
    {
        $deadline = $clock() + max(0, $seconds);
        do {
            [$snap, $reason] = $reader->readVerified();
            if ($snap !== null && $reason === ServiceStatusSnapshot::FRESH) {
                if (in_array($snap->state(), ['ready', 'degraded'], true)) {
                    return 0;
                }
                if ($snap->state() === 'failed') {
                    return 1;
                }
            }
            if ($clock() >= $deadline) {
                return 1;
            }
            $sleep(1);
        } while ($clock() <= $deadline);

        return 1;
    }
}

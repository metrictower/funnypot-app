<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The per-request / listener-bootstrap seam that hands the current deployment-global service persona
 * to app-owned consumers. It forwards ONLY {@see ServiceStatusView::profile()} — the base family and
 * variant token — never the freshness/state/health, so a consumer cannot (even accidentally) vary an
 * attacker-facing byte on heartbeat availability (the B2 invariant). It never throws into the request
 * path: any fault degrades to the family-neutral profile.
 */
final class EffectiveServiceProfileReader
{
    public function __construct(private ServiceStatusReader $reader)
    {
    }

    /** @param callable(string):(string|false)|null $env */
    public static function fromEnvironment(string $demoDir, ?callable $env = null): self
    {
        $env ??= static fn (string $k) => getenv($k);
        $paths = ServicePaths::fromEnvironment($demoDir, $env);

        return new self(new ServiceStatusReader($paths->statusFile()));
    }

    /**
     * The request-path entry point: resolve from the environment and read the current profile, never
     * throwing. A malformed FUNNYPOT_DB / runtime / status env can make {@see fromEnvironment()} itself
     * throw before {@see profile()} can guard it, which at the front controller would be an
     * attacker-facing 500 tell; that too degrades to the family-neutral profile.
     *
     * @param callable(string):(string|false)|null $env
     */
    public static function profileFromEnvironment(string $demoDir, ?callable $env = null): EffectiveServiceProfile
    {
        try {
            return self::fromEnvironment($demoDir, $env)->profile();
        } catch (\Throwable $e) {
            return ServiceStatusReader::familyNeutralProfile();
        }
    }

    public function profile(): EffectiveServiceProfile
    {
        try {
            return $this->reader->current()->profile();
        } catch (\Throwable $e) {
            return ServiceStatusReader::familyNeutralProfile();
        }
    }
}

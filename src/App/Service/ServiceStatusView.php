<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The per-request web view of runtime status. It ALWAYS carries a usable deployment-global profile —
 * the last verified snapshot's profile, or the family-neutral profile when nothing is cached — plus a
 * status_freshness marker. Attacker-facing code consumes only {@see profile()}; it must never branch
 * on {@see freshness()} (that is the B2 invariant), which feeds only the admin status payload and the
 * Docker healthcheck.
 */
final class ServiceStatusView
{
    private function __construct(
        private EffectiveServiceProfile $profile,
        private string $freshness,
        private ?ServiceStatusSnapshot $snapshot,
    ) {
    }

    public static function fromSnapshot(ServiceStatusSnapshot $snapshot, string $freshness): self
    {
        return new self($snapshot->profile(), $freshness, $snapshot);
    }

    public static function familyNeutral(string $freshness): self
    {
        return new self(ServiceStatusReader::familyNeutralProfile(), $freshness, null);
    }

    public function profile(): EffectiveServiceProfile
    {
        return $this->profile;
    }

    public function freshness(): string
    {
        return $this->freshness;
    }

    public function snapshot(): ?ServiceStatusSnapshot
    {
        return $this->snapshot;
    }
}

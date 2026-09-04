<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The store when engagement metrics are OFF or have no key material. Records nothing and reports
 * itself disabled with a bounded reason, so the operator sees WHY the panel is empty instead of a
 * silent zero — and a missing key is never papered over with a fleet-constant identity.
 */
final class NoopEngagementStore implements EngagementStore, EngagementAnalytics
{
    public const REASON_OFF = 'off';
    public const REASON_NO_KEY = 'key-unavailable';

    public function __construct(private string $reason = self::REASON_OFF)
    {
    }

    public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string
    {
        return self::DISABLED;
    }

    public function summary(int $sinceEpoch): array
    {
        return ['enabled' => false, 'reason' => $this->reason];
    }

    public function recent(int $sinceEpoch, int $limit): array
    {
        return [];
    }

    public function health(): array
    {
        return ['enabled' => false, 'reason' => $this->reason];
    }
}

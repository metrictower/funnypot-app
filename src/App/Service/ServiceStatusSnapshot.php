<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * An immutable, verified view of the runtime status heartbeat plus the freshness the reader judged it
 * to have. The embedded effective artifact is the authority; `state`, `acceptance_mode` and per-process
 * health are live status only and are NEVER consumed by an attacker-facing renderer.
 */
final class ServiceStatusSnapshot
{
    public const FRESH = 'fresh';
    public const STALE = 'stale';
    public const MISSING = 'missing';
    public const CORRUPT = 'corrupt';

    /** @param array<string,mixed> $doc a verified heartbeat document (envelope) */
    private function __construct(
        private array $doc,
        private EffectiveExposureArtifact $artifact,
        private string $freshness,
    ) {
    }

    /** @param array<string,mixed> $doc */
    public static function verified(array $doc, EffectiveExposureArtifact $artifact, string $freshness): self
    {
        return new self($doc, $artifact, $freshness);
    }

    public function freshness(): string
    {
        return $this->freshness;
    }

    public function withFreshness(string $freshness): self
    {
        return new self($this->doc, $this->artifact, $freshness);
    }

    public function state(): string
    {
        return (string) ($this->doc['state'] ?? 'reconciling');
    }

    public function acceptanceMode(): string
    {
        return (string) ($this->doc['acceptance_mode'] ?? '');
    }

    public function sequence(): int
    {
        return (int) ($this->doc['sequence'] ?? 0);
    }

    public function writtenAt(): int
    {
        return (int) ($this->doc['written_at'] ?? 0);
    }

    public function statusRevision(): int
    {
        return (int) ($this->doc['status_revision'] ?? 0);
    }

    /** @return array<string,string> */
    public function processHealth(): array
    {
        $out = [];
        foreach ((array) ($this->doc['process_health'] ?? []) as $k => $v) {
            $out[(string) $k] = (string) $v;
        }

        return $out;
    }

    public function effectiveArtifact(): EffectiveExposureArtifact
    {
        return $this->artifact;
    }

    public function profile(): EffectiveServiceProfile
    {
        $p = (array) ($this->artifact->toArray()['profile'] ?? []);
        $ids = (array) ($this->artifact->toArray()['effective_service_ids'] ?? []);

        return new EffectiveServiceProfile(
            (string) ($p['base_family'] ?? 'neutral'),
            (string) ($p['variant_id'] ?? ''),
            array_values(array_map('strval', $ids)),
        );
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Service\CanonicalJson;
use Funnypot\App\Service\EffectiveExposureArtifact;

final class SandboxProjection
{
    public const SCHEMA = 'sandbox-projection/v1';
    public const HASH_DOMAIN = 'funnypot/sandbox-projection/v1';
    public const MAX_BYTES = 262144;
    public const MAX_ENTRIES = 64;
    public const MAX_PATH_BYTES = 512;
    public const MAX_CONTENT_BYTES = 1048576;

    /** @param list<SandboxProjectionEntry> $entries */
    public function __construct(
        public readonly string $generation,
        public readonly string $identityPublicHash,
        public readonly string $identityKeysetCommitment,
        public readonly string $runtimePolicyHash,
        public readonly string $effectiveSchema,
        public readonly int $effectiveRevision,
        public readonly string $effectiveGeneration,
        public readonly string $effectiveHash,
        public readonly string $projectionRegistryHash,
        public readonly array $entries,
    ) {
        if (preg_match('/^[0-9a-f]{32}$/', $generation) !== 1
            || preg_match('/^fpph1_[0-9a-f]{64}$/', $identityPublicHash) !== 1
            || preg_match('/^fpkc1_[0-9a-f]{64}$/', $identityKeysetCommitment) !== 1
            || preg_match('/^[0-9a-f]{64}$/', $runtimePolicyHash) !== 1
            || $effectiveSchema !== EffectiveExposureArtifact::SCHEMA
            || preg_match('/^[0-9a-f]{32}$/', $effectiveGeneration) !== 1
            || preg_match('/^[0-9a-f]{64}$/', $effectiveHash) !== 1
            || preg_match('/^[0-9a-f]{64}$/', $projectionRegistryHash) !== 1
            || $effectiveRevision < 1 || count($entries) > self::MAX_ENTRIES) {
            throw new SandboxProjectionException('projection-invalid');
        }
        $ids = [];
        foreach ($entries as $entry) {
            if (!$entry instanceof SandboxProjectionEntry || isset($ids[$entry->registered->entryId])) {
                throw new SandboxProjectionException('projection-invalid');
            }
            if ($entry->source->byteLength < 0 || $entry->source->byteLength > self::MAX_CONTENT_BYTES
                || strlen($entry->registered->relativePath) > self::MAX_PATH_BYTES) {
                throw new SandboxProjectionException('projection-invalid');
            }
            $ids[$entry->registered->entryId] = true;
        }
        if (strlen(CanonicalJson::encode($this->toArray())) > self::MAX_BYTES) {
            throw new SandboxProjectionException('projection-too-large');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        $entries = $this->entries;
        usort($entries, static fn (SandboxProjectionEntry $a, SandboxProjectionEntry $b): int => strcmp($a->registered->entryId, $b->registered->entryId));

        return [
            'schema' => self::SCHEMA,
            'generation' => $this->generation,
            'identity_public_hash' => $this->identityPublicHash,
            'identity_keyset_commitment' => $this->identityKeysetCommitment,
            'runtime_policy_hash' => $this->runtimePolicyHash,
            'effective_schema' => $this->effectiveSchema,
            'effective_revision' => $this->effectiveRevision,
            'effective_generation' => $this->effectiveGeneration,
            'effective_hash' => $this->effectiveHash,
            'projection_registry_hash' => $this->projectionRegistryHash,
            'entries' => array_map(static fn (SandboxProjectionEntry $e): array => $e->toArray(), $entries),
        ];
    }

    public function bytes(): string
    {
        return CanonicalJson::encode($this->toArray());
    }

    public function digest(): string
    {
        return CanonicalJson::digest(self::HASH_DOMAIN, $this->toArray());
    }

    /** @return array<string,mixed> */
    public function stableView(bool $ownershipApplied): array
    {
        $entries = [];
        foreach ($this->toArray()['entries'] as $entry) {
            if ($entry['link_count_policy'] === ProjectionRegistryEntry::ZERO_ANONYMOUS) {
                continue;
            }
            $entries[] = [
                'entry_schema' => $entry['entry_schema'],
                'entry_id' => $entry['entry_id'],
                'destination_owner' => $entry['destination_owner'],
                'destination_id' => $entry['destination_id'],
                'destination_path' => $entry['destination_path'],
                'directory_uid' => $entry['directory_uid'],
                'directory_gid' => $entry['directory_gid'],
                'directory_mode' => $entry['directory_mode'],
                'file_uid' => $entry['file_uid'],
                'file_gid' => $entry['file_gid'],
                'file_mode' => $entry['file_mode'],
                'content_class' => $entry['content_class'],
                'restart_consumers' => $entry['restart_consumers'],
                'content_sha256' => $entry['content_sha256'],
                'byte_length' => $entry['byte_length'],
                'envelope' => $entry['envelope'],
            ];
        }

        return [
            'identity_public_hash' => $this->identityPublicHash,
            'identity_keyset_commitment' => $this->identityKeysetCommitment,
            'runtime_policy_hash' => $this->runtimePolicyHash,
            'effective_schema' => $this->effectiveSchema,
            'effective_revision' => $this->effectiveRevision,
            'effective_generation' => $this->effectiveGeneration,
            'effective_hash' => $this->effectiveHash,
            'projection_registry_hash' => $this->projectionRegistryHash,
            'ownership_applied' => $ownershipApplied,
            'entries' => $entries,
        ];
    }
}

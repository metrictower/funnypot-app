<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityPreparationResult;
use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Runtime\RuntimePolicy;

final class SandboxProjectionProducer
{
    private IdentityFileOps $ops;

    public function __construct(private ProjectionEntryRegistry $registry, private RuntimePolicy $policy, ?IdentityFileOps $ops = null)
    {
        $this->ops = $ops ?? new IdentityFileOps();
    }

    public function produce(string $generation, IdentityPreparationResult $identity, EffectiveExposureArtifact $effective): SandboxProjection
    {
        $entries = $this->entries($identity);

        return new SandboxProjection(
            $generation,
            $identity->publicPersonaHash,
            $identity->keysetCommitment,
            $this->policy->policyHash(),
            $effective->schema(),
            $effective->revision(),
            $effective->generation(),
            $effective->hash(),
            $this->registry->registryHash(),
            $entries,
        );
    }

    /** Stable inputs are built before a candidate id exists. @return array<string,mixed> */
    public function stableInputs(IdentityPreparationResult $identity, EffectiveExposureArtifact $effective, bool $ownershipApplied): array
    {
        $entries = $this->entries($identity);
        usort($entries, static fn (SandboxProjectionEntry $a, SandboxProjectionEntry $b): int => strcmp($a->registered->entryId, $b->registered->entryId));
        $stableEntries = [];
        foreach ($entries as $entry) {
            if ($entry->registered->linkCountPolicy === ProjectionRegistryEntry::ZERO_ANONYMOUS) {
                continue;
            }
            $row = $entry->registered->toArray();
            unset($row['presence'], $row['attestation_ids'], $row['link_count_policy']);
            $stableEntries[] = $row + [
                'content_sha256' => $entry->source->contentSha256,
                'byte_length' => $entry->source->byteLength,
                'envelope' => $entry->source->envelope,
            ];
        }

        return [
            'identity_public_hash' => $identity->publicPersonaHash,
            'identity_keyset_commitment' => $identity->keysetCommitment,
            'runtime_policy_hash' => $this->policy->policyHash(),
            'effective_schema' => $effective->schema(),
            'effective_revision' => $effective->revision(),
            'effective_generation' => $effective->generation(),
            'effective_hash' => $effective->hash(),
            'projection_registry_hash' => $this->registry->registryHash(),
            'ownership_applied' => $ownershipApplied,
            'entries' => $stableEntries,
        ];
    }

    /** @return list<SandboxProjectionEntry> */
    private function entries(IdentityPreparationResult $identity): array
    {
        $sources = $identity->sources();
        $entries = [];
        foreach ($this->registry->entries() as $registered) {
            $source = $sources[$registered->entrySchema] ?? null;
            if ($source === null) {
                if ($registered->presence === ProjectionRegistryEntry::PAIR) {
                    continue;
                }
                throw new SandboxProjectionException('projection-required-source-missing');
            }
            $projectionSource = $this->source($registered, $source);
            if (str_contains($source->sourceClass, 'identity-source')
                && (($source->envelope['public_persona_hash'] ?? null) !== $identity->publicPersonaHash
                    || ($source->envelope['keyset_commitment'] ?? null) !== $identity->keysetCommitment)) {
                throw new SandboxProjectionException('projection-envelope-mismatch');
            }
            $expectedFingerprint = str_contains($source->sourceClass, 'admin-tls')
                ? $identity->tls->adminFingerprintSha256 : $identity->tls->fingerprintSha256;
            if (str_contains($source->sourceClass, 'tls-')
                && ($source->envelope['fingerprint_sha256'] ?? null) !== $expectedFingerprint) {
                throw new SandboxProjectionException('projection-tls-fingerprint-mismatch');
            }
            $entries[] = new SandboxProjectionEntry($registered, $projectionSource);
        }
        $adminPresent = isset($sources[PreparedIdentitySource::ADMIN_TLS_CERTIFICATE]);
        if ($adminPresent !== isset($sources[PreparedIdentitySource::ADMIN_TLS_PRIVATE_KEY])) {
            throw new SandboxProjectionException('projection-admin-pair-mismatch');
        }

        return $entries;
    }

    private function source(ProjectionRegistryEntry $registered, PreparedIdentitySource $source): SandboxProjectionSource
    {
        if ($source->sourceClass !== $registered->entrySchema || !is_resource($source->handle)) {
            throw new SandboxProjectionException('source-attestation-drift');
        }
        $st = $this->ops->fstat($source->handle);
        if (!is_array($st) || !$source->attestation->isRegularFile() || !$source->attestation->matches($st)
            || ($source->attestation->uid !== 0 && $source->attestation->uid !== $this->ops->euid())
            || ($source->attestation->mode & 0022) !== 0
            || !in_array($source->attestation->id, $registered->attestationIds, true)
            || !$this->validLinkCount($registered->linkCountPolicy, $source->attestation->nlink)
            || $source->attestation->size !== $source->byteLength
            || $source->byteLength < 0 || $source->byteLength > SandboxProjection::MAX_CONTENT_BYTES
            || preg_match('/^[0-9a-f]{64}$/', $source->sha256) !== 1) {
            throw new SandboxProjectionException('source-attestation-drift');
        }
        $this->validateEnvelope($source);

        return new SandboxProjectionSource(
            $source->sourceClass,
            $source->attestation->id,
            $source->attestation->dev,
            $source->attestation->ino,
            $source->attestation->mode,
            $source->attestation->uid,
            $source->attestation->gid,
            $source->attestation->nlink,
            $source->byteLength,
            $source->sha256,
            $source->envelope,
        );
    }

    private function validLinkCount(string $policy, int $nlink): bool
    {
        return ($policy === ProjectionRegistryEntry::EXACTLY_ONE && $nlink === 1)
            || ($policy === ProjectionRegistryEntry::ZERO_ANONYMOUS && $nlink === 0);
    }

    private function validateEnvelope(PreparedIdentitySource $source): void
    {
        if (str_contains($source->sourceClass, 'identity-source')) {
            if (!ProjectionEnvelopePolicy::validIdentity($source->sourceClass, $source->envelope)) {
                throw new SandboxProjectionException('projection-envelope-mismatch');
            }
        } else {
            $keys = str_contains($source->sourceClass, 'admin-tls') ? ['fingerprint_sha256', 'domain'] : ['fingerprint_sha256', 'selection'];
            if (!$this->sameKeys($source->envelope, $keys)) {
                throw new SandboxProjectionException('projection-tls-fingerprint-mismatch');
            }
            if (!is_string($source->envelope['fingerprint_sha256'] ?? null)
                || preg_match('/^[0-9a-f]{64}$/', $source->envelope['fingerprint_sha256']) !== 1) {
                throw new SandboxProjectionException('projection-tls-fingerprint-mismatch');
            }
        }
    }

    /** @param array<string,string> $value @param list<string> $keys */
    private function sameKeys(array $value, array $keys): bool
    {
        $actual = array_keys($value); sort($actual); sort($keys); return $actual === $keys;
    }
}

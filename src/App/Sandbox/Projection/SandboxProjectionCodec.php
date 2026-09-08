<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

/** Strict parser for the closed descriptor; it never accepts a path or constructor from the document. */
final class SandboxProjectionCodec
{
    private const TOP_KEYS = [
        'schema', 'generation', 'identity_public_hash', 'identity_keyset_commitment', 'runtime_policy_hash',
        'effective_schema', 'effective_revision', 'effective_generation', 'effective_hash',
        'projection_registry_hash', 'entries',
    ];

    public function __construct(private ProjectionEntryRegistry $registry)
    {
    }

    /** @param array<string,mixed> $doc */
    public function decode(array $doc): SandboxProjection
    {
        if (!$this->sameKeys($doc, self::TOP_KEYS) || ($doc['schema'] ?? null) !== SandboxProjection::SCHEMA
            || !is_array($doc['entries']) || !array_is_list($doc['entries'])) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $entries = [];
        $registryRecords = [];
        foreach ($this->registry->entries() as $entry) {
            $registryRecords[$entry->entryId] = $entry;
        }
        foreach ($doc['entries'] as $row) {
            if (!is_array($row) || !is_string($row['entry_id'] ?? null) || !isset($registryRecords[$row['entry_id']])) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
            $registered = $registryRecords[$row['entry_id']];
            $fixed = $registered->toArray();
            foreach ($fixed as $key => $value) {
                if (!array_key_exists($key, $row) || $row[$key] !== $value) {
                    throw new SandboxProjectionException('selected-generation-invalid');
                }
            }
            $sourceKeys = ['source_class', 'attestation_id', 'device', 'inode', 'mode', 'uid', 'gid', 'link_count', 'byte_length', 'content_sha256', 'envelope'];
            $expectedKeys = array_merge(array_keys($fixed), $sourceKeys);
            if (!$this->sameKeys($row, $expectedKeys)
                || !is_string($row['source_class']) || $row['source_class'] !== $registered->entrySchema
                || !is_string($row['attestation_id']) || !in_array($row['attestation_id'], $registered->attestationIds, true)
                || !is_int($row['device']) || !is_int($row['inode']) || !is_int($row['mode']) || !is_int($row['uid'])
                || !is_int($row['gid']) || !is_int($row['link_count']) || !is_int($row['byte_length'])
                || $row['byte_length'] < 0 || $row['byte_length'] > SandboxProjection::MAX_CONTENT_BYTES
                || !is_string($row['content_sha256']) || preg_match('/^[0-9a-f]{64}$/', $row['content_sha256']) !== 1
                || !is_array($row['envelope']) || ($row['mode'] & 0170000) !== 0100000
                || $row['uid'] < 0 || $row['gid'] < 0 || ($row['mode'] & 0022) !== 0
                || ($registered->linkCountPolicy === ProjectionRegistryEntry::EXACTLY_ONE && $row['link_count'] !== 1)
                || ($registered->linkCountPolicy === ProjectionRegistryEntry::ZERO_ANONYMOUS && $row['link_count'] !== 0)
                || !$this->validEnvelope($row['source_class'], $row['envelope'])) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
            $source = new SandboxProjectionSource(
                $row['source_class'], $row['attestation_id'], $row['device'], $row['inode'], $row['mode'], $row['uid'],
                $row['gid'], $row['link_count'], $row['byte_length'], $row['content_sha256'], $row['envelope'],
            );
            $entries[] = new SandboxProjectionEntry($registered, $source);
            unset($registryRecords[$registered->entryId]);
        }
        foreach ($registryRecords as $missing) {
            if ($missing->presence === ProjectionRegistryEntry::REQUIRED) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
        }
        $adminCert = $this->has($entries, 'edge-admin-tls-certificate');
        if ($adminCert !== $this->has($entries, 'edge-admin-tls-private-key')) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }

        try {
            $projection = new SandboxProjection(
                self::string($doc, 'generation'), self::string($doc, 'identity_public_hash'),
                self::string($doc, 'identity_keyset_commitment'), self::string($doc, 'runtime_policy_hash'),
                self::string($doc, 'effective_schema'), self::integer($doc, 'effective_revision'),
                self::string($doc, 'effective_generation'), self::string($doc, 'effective_hash'),
                self::string($doc, 'projection_registry_hash'), $entries,
            );
            foreach ($projection->entries as $entry) {
                if (str_contains($entry->source->sourceClass, 'identity-source')
                    && (($entry->source->envelope['public_persona_hash'] ?? null) !== $projection->identityPublicHash
                        || ($entry->source->envelope['keyset_commitment'] ?? null) !== $projection->identityKeysetCommitment)) {
                    throw new SandboxProjectionException('selected-generation-invalid');
                }
            }

            return $projection;
        } catch (SandboxProjectionException) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
    }

    /** @param list<SandboxProjectionEntry> $entries */
    private function has(array $entries, string $id): bool
    {
        foreach ($entries as $entry) {
            if ($entry->registered->entryId === $id) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string,mixed> $value @param list<string> $keys */
    private function sameKeys(array $value, array $keys): bool
    {
        $actual = array_keys($value);
        sort($actual);
        sort($keys);

        return $actual === $keys;
    }

    /** @param array<string,mixed> $envelope */
    private function validEnvelope(string $sourceClass, array $envelope): bool
    {
        if (str_contains($sourceClass, 'identity-source')) {
            return ProjectionEnvelopePolicy::validIdentity($sourceClass, $envelope);
        }
        if (str_contains($sourceClass, 'admin-tls')) {
            return $this->sameKeys($envelope, ['fingerprint_sha256', 'domain'])
                && is_string($envelope['fingerprint_sha256']) && preg_match('/^[0-9a-f]{64}$/', $envelope['fingerprint_sha256']) === 1
                && is_string($envelope['domain']) && $envelope['domain'] !== '';
        }
        if (str_contains($sourceClass, 'tls-')) {
            return $this->sameKeys($envelope, ['fingerprint_sha256', 'selection'])
                && is_string($envelope['fingerprint_sha256']) && preg_match('/^[0-9a-f]{64}$/', $envelope['fingerprint_sha256']) === 1
                && is_string($envelope['selection']) && $envelope['selection'] !== '';
        }

        return true;
    }

    /** @param array<string,mixed> $doc */
    private static function string(array $doc, string $key): string
    {
        if (!is_string($doc[$key] ?? null)) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }

        return $doc[$key];
    }

    /** @param array<string,mixed> $doc */
    private static function integer(array $doc, string $key): int
    {
        if (!is_int($doc[$key] ?? null)) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }

        return $doc[$key];
    }
}

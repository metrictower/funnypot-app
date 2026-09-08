<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Identity\IdentityBundleReader;
use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Service\CanonicalJson;

final class SandboxViewMaterializer
{
    public const MANIFEST_SCHEMA = 'sandbox-manifest/v1';
    public const MANIFEST_HASH_DOMAIN = 'funnypot/sandbox-manifest/v1';

    public function __construct(private ProjectionEntryRegistry $registry, private SandboxFileOps $ops)
    {
    }

    /**
     * @param array<string,PreparedIdentitySource> $sources
     * @return array<string,mixed> canonical manifest payload
     */
    public function materialize(string $candidateDir, SandboxProjection $projection, array $sources, int $createdAt): array
    {
        $candidateStat = $this->ops->lstat($candidateDir);
        if (!is_array($candidateStat) || !$this->isDir($candidateStat) || (int) $candidateStat['uid'] !== $this->ops->euid()
            || (((int) $candidateStat['mode']) & 0777) !== 0700) {
            throw new SandboxProjectionException('candidate-invalid');
        }
        $views = $candidateDir . '/views';
        $this->makeDirectory($views, 0700);
        $ownershipApplied = $this->ops->euid() === 0;
        $finalDirectories = [];
        $contents = [];
        foreach ($projection->entries as $entry) {
            $registered = $this->registry->entry($entry->source->sourceClass);
            if ($registered === null || $registered->toArray() !== $entry->registered->toArray()) {
                throw new SandboxProjectionException('projection-registry-mismatch');
            }
            $source = $sources[$entry->source->sourceClass] ?? null;
            if (!$source instanceof PreparedIdentitySource) {
                throw new SandboxProjectionException('projection-source-missing');
            }
            $bytes = $this->readAndValidateSource($entry, $source);
            $this->validateContent($entry, $bytes);
            $contents[$entry->source->sourceClass] = $bytes;

            $destination = $candidateDir . '/' . $registered->relativePath;
            $parent = dirname($destination);
            $relativeParent = substr($parent, strlen($candidateDir) + 1);
            $cursor = $candidateDir;
            foreach (explode('/', $relativeParent) as $component) {
                $cursor .= '/' . $component;
                if ($this->ops->lstat($cursor) === false) {
                    $this->makeDirectory($cursor, 0700);
                }
                if ($cursor !== $views) {
                    $tuple = [$registered->destinationOwner, $registered->directoryMode];
                    if (isset($finalDirectories[$cursor]) && $finalDirectories[$cursor] !== $tuple) {
                        throw new SandboxProjectionException('projection-directory-policy-conflict');
                    }
                    $finalDirectories[$cursor] = $tuple;
                }
            }
            $this->writeExclusive($destination, $bytes, $registered->fileMode, $ownershipApplied ? $registered->destinationOwner : null);
        }
        $this->validateTlsPairs($contents, $projection);

        uksort($finalDirectories, static fn (string $a, string $b): int => substr_count($b, '/') <=> substr_count($a, '/'));
        foreach ($finalDirectories as $dir => [$owner, $mode]) {
            if ($ownershipApplied) {
                [$uid, $gid] = $owner->ownership();
                if (!$this->ops->chown($dir, $uid) || !$this->ops->chgrp($dir, $gid)) {
                    throw new SandboxProjectionException('ownership-apply-failed');
                }
            }
            if (!$this->ops->chmod($dir, $mode)) {
                throw new SandboxProjectionException('candidate-write-failed');
            }
            $this->syncDirectory($dir);
        }

        $projectionBytes = $projection->bytes();
        $this->writeExclusive($candidateDir . '/' . SandboxPaths::PROJECTION_FILE, $projectionBytes, 0600);
        $manifest = [
            'schema' => self::MANIFEST_SCHEMA,
            'generation' => $projection->generation,
            'created_at' => $createdAt,
            'ownership_applied' => $ownershipApplied,
            'effective_schema' => $projection->effectiveSchema,
            'effective_revision' => $projection->effectiveRevision,
            'effective_generation' => $projection->effectiveGeneration,
            'effective_hash' => $projection->effectiveHash,
            'projection_registry_hash' => $projection->projectionRegistryHash,
            'projection_sha256' => $projection->digest(),
            'entries' => array_map(static fn (SandboxProjectionEntry $entry): array => [
                'entry_id' => $entry->registered->entryId,
                'destination_id' => $entry->registered->destinationId,
                'content_sha256' => $entry->source->contentSha256,
            ], $this->sortedEntries($projection->entries)),
        ];
        $this->writeExclusive($candidateDir . '/' . SandboxPaths::MANIFEST_FILE, CanonicalJson::encode($manifest), 0600);
        $this->syncDirectory($views);
        $this->syncDirectory($candidateDir);

        return $manifest;
    }

    private function readAndValidateSource(SandboxProjectionEntry $entry, PreparedIdentitySource $source): string
    {
        if (!is_resource($source->handle) || !$this->ops->rewind($source->handle)) {
            throw new SandboxProjectionException('source-attestation-drift');
        }
        $before = $this->ops->fstat($source->handle);
        if (!is_array($before) || !$source->attestation->matches($before) || !$this->matchesDescriptor($entry->source, $before)) {
            throw new SandboxProjectionException('source-attestation-drift');
        }
        if (($entry->registered->linkCountPolicy === ProjectionRegistryEntry::EXACTLY_ONE && (int) $before['nlink'] !== 1)
            || ($entry->registered->linkCountPolicy === ProjectionRegistryEntry::ZERO_ANONYMOUS && (int) $before['nlink'] !== 0)) {
            throw new SandboxProjectionException('source-attestation-drift');
        }
        $bytes = $this->ops->readAll($source->handle, SandboxProjection::MAX_CONTENT_BYTES + 1);
        $after = $this->ops->fstat($source->handle);
        if (!is_string($bytes) || strlen($bytes) > SandboxProjection::MAX_CONTENT_BYTES || !is_array($after)
            || !$source->attestation->matches($after) || !$this->matchesDescriptor($entry->source, $after)
            || strlen($bytes) !== $entry->source->byteLength
            || !hash_equals($entry->source->contentSha256, hash('sha256', $bytes))) {
            throw new SandboxProjectionException('projection-source-content-mismatch');
        }

        return $bytes;
    }

    /** @param array<string,int> $st */
    private function matchesDescriptor(SandboxProjectionSource $source, array $st): bool
    {
        return (int) $st['dev'] === $source->dev && (int) $st['ino'] === $source->ino
            && (int) $st['mode'] === $source->mode && (int) $st['uid'] === $source->uid
            && (int) $st['gid'] === $source->gid && (int) $st['nlink'] === $source->nlink
            && (((int) $st['mode']) & 0170000) === 0100000;
    }

    private function validateContent(SandboxProjectionEntry $entry, string $bytes): void
    {
        $class = $entry->source->sourceClass;
        if (str_contains($class, 'identity-source')) {
            if (!ProjectionEnvelopePolicy::validIdentity($class, $entry->source->envelope)) {
                throw new SandboxProjectionException('projection-envelope-mismatch');
            }
            $bundle = (string) ProjectionEnvelopePolicy::identityBundle($class);
            try {
                $doc = IdentityBundleReader::decode($bytes, $bundle);
            } catch (\Throwable) {
                throw new SandboxProjectionException('projection-envelope-mismatch');
            }
            foreach (['schema', 'bundle', 'public_persona_hash', 'keyset_commitment'] as $key) {
                if (($doc['envelope'][$key] ?? null) !== ($entry->source->envelope[$key] ?? null)) {
                    throw new SandboxProjectionException('projection-envelope-mismatch');
                }
            }
            return;
        }
        if (str_contains($class, 'certificate')) {
            $fp = @openssl_x509_fingerprint($bytes, 'sha256');
            if (!is_string($fp) || !hash_equals(strtolower(str_replace(':', '', $fp)), $entry->source->envelope['fingerprint_sha256'])) {
                throw new SandboxProjectionException('projection-tls-fingerprint-mismatch');
            }
        }
    }

    /** @param array<string,string> $contents */
    private function validateTlsPairs(array $contents, SandboxProjection $projection): void
    {
        foreach ([[PreparedIdentitySource::TLS_CERTIFICATE, PreparedIdentitySource::TLS_PRIVATE_KEY], [PreparedIdentitySource::ADMIN_TLS_CERTIFICATE, PreparedIdentitySource::ADMIN_TLS_PRIVATE_KEY]] as [$certClass, $keyClass]) {
            $hasCert = isset($contents[$certClass]);
            if ($hasCert !== isset($contents[$keyClass])) {
                throw new SandboxProjectionException('projection-tls-pair-mismatch');
            }
            if (!$hasCert) {
                continue;
            }
            if (@openssl_x509_read($contents[$certClass]) === false || @openssl_pkey_get_private($contents[$keyClass]) === false
                || !@openssl_x509_check_private_key($contents[$certClass], $contents[$keyClass])) {
                throw new SandboxProjectionException('projection-tls-pair-mismatch');
            }
            $envelopes = [];
            foreach ($projection->entries as $entry) {
                if ($entry->source->sourceClass === $certClass || $entry->source->sourceClass === $keyClass) {
                    $envelopes[] = $entry->source->envelope['fingerprint_sha256'] ?? null;
                }
            }
            if (count($envelopes) !== 2 || $envelopes[0] !== $envelopes[1]) {
                throw new SandboxProjectionException('projection-tls-fingerprint-mismatch');
            }
        }
    }

    private function makeDirectory(string $path, int $mode): void
    {
        if (!$this->ops->mkdir($path, $mode)) {
            throw new SandboxProjectionException('candidate-write-failed');
        }
        $st = $this->ops->lstat($path);
        if (!is_array($st) || !$this->isDir($st) || (int) $st['uid'] !== $this->ops->euid() || (((int) $st['mode']) & 0777) !== $mode) {
            throw new SandboxProjectionException('candidate-write-failed');
        }
    }

    private function writeExclusive(string $path, string $bytes, int $mode, ?ProjectionDestinationOwner $owner = null): void
    {
        $h = $this->ops->openExclusive($path);
        if (!is_resource($h)) {
            throw new SandboxProjectionException('candidate-write-failed');
        }
        try {
            $offset = 0;
            while ($offset < strlen($bytes)) {
                $n = $this->ops->write($h, substr($bytes, $offset));
                if (!is_int($n) || $n < 1) {
                    throw new SandboxProjectionException('candidate-write-failed');
                }
                $offset += $n;
            }
            if (!$this->ops->flush($h) || !$this->ops->fdatasync($h) || !$this->ops->chmod($path, $mode)) {
                throw new SandboxProjectionException('candidate-write-failed');
            }
            if ($owner !== null) {
                [$uid, $gid] = $owner->ownership();
                if (!$this->ops->chown($path, $uid) || !$this->ops->chgrp($path, $gid)) {
                    throw new SandboxProjectionException('ownership-apply-failed');
                }
            }
            // fsync, rather than fdatasync, persists the final mode/ownership metadata too.
            if (!$this->ops->fsync($h)) {
                throw new SandboxProjectionException('candidate-write-failed');
            }
        } finally {
            $this->ops->close($h);
        }
    }

    private function syncDirectory(string $path): void
    {
        $h = $this->ops->openDir($path);
        if (!is_resource($h)) {
            throw new SandboxProjectionException('candidate-write-failed');
        }
        try {
            if (!$this->ops->fsync($h)) {
                throw new SandboxProjectionException('candidate-write-failed');
            }
        } finally {
            $this->ops->close($h);
        }
    }

    /** @param array<string,int> $st */
    private function isDir(array $st): bool
    {
        return (((int) $st['mode']) & 0170000) === 0040000;
    }

    /** @param list<SandboxProjectionEntry> $entries @return list<SandboxProjectionEntry> */
    private function sortedEntries(array $entries): array
    {
        usort($entries, static fn (SandboxProjectionEntry $a, SandboxProjectionEntry $b): int => strcmp($a->registered->entryId, $b->registered->entryId));

        return $entries;
    }
}

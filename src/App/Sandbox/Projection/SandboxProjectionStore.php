<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Identity\IdentityPreparationResult;
use Funnypot\App\Identity\IdentityBundleReader;
use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Service\CanonicalJson;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Runtime\RuntimePolicy;

final class SandboxProjectionStore
{
    public const SELECTOR_SCHEMA = 'sandbox-projection-selector/v1';
    public const RETENTION_SECONDS = 86400;
    public const MAX_GENERATIONS = 8;
    public const MAX_CLEANUP = 2;
    private const LOCK_TIMEOUT_MS = 2000;

    private SandboxProjectionProducer $producer;
    private SandboxViewMaterializer $materializer;

    /** @var array<string,ProjectionEntryRegistry> */
    private array $readers;

    /** @param list<ProjectionEntryRegistry>|null $readerRegistries finite code-owned predecessor allowlist */
    public function __construct(
        private SandboxPaths $paths,
        private ProjectionEntryRegistry $writerRegistry,
        private RuntimePolicy $policy,
        private SandboxFileOps $ops,
        private CandidateGenerationFactory $generationFactory,
        ?array $readerRegistries = null,
    ) {
        $this->producer = new SandboxProjectionProducer($writerRegistry, $policy, $ops);
        $this->materializer = new SandboxViewMaterializer($writerRegistry, $ops);
        $this->readers = [];
        foreach ($readerRegistries ?? [$writerRegistry] as $registry) {
            $this->readers[$registry->registryHash()] = $registry;
        }
        if (!isset($this->readers[$writerRegistry->registryHash()])) {
            throw new SandboxProjectionException('projection-registry-invalid');
        }
    }

    /**
     * The preparation callback is deliberately invoked only after the publication lock is held.
     * @param callable():IdentityPreparationResult $prepareIdentity
     * @param callable():EffectiveExposureArtifact $loadEffective
     */
    public function publish(callable $prepareIdentity, callable $loadEffective): SandboxPublicationResult
    {
        try {
            $this->paths->prepareRoot($this->ops);
            $lock = $this->acquireLock();
        } catch (SandboxProjectionException $e) {
            return new SandboxPublicationResult($e->errorCode());
        }

        $identity = null;
        $candidate = null;
        $candidateRenamed = false;
        $selectorCommitted = false;
        $hadCurrent = false;
        try {
            try {
                $currentSnapshot = $this->snapshotSelector();
            } catch (SandboxProjectionException) {
                return new SandboxPublicationResult('selected-generation-invalid');
            }
            $hadCurrent = $currentSnapshot !== null;
            $selected = $currentSnapshot === null ? null : $this->validateSelected($currentSnapshot['selector']);
            try {
                $effectiveSnapshot = $loadEffective();
            } catch (\Throwable) {
                return new SandboxPublicationResult('effective-artifact-missing', $selected?->generation);
            }
            if (!$effectiveSnapshot instanceof EffectiveExposureArtifact) {
                return new SandboxPublicationResult('effective-artifact-mismatch', $selected?->generation);
            }
            if ($selected !== null && !$this->effectiveMatchesProjection($effectiveSnapshot, $selected)) {
                // A stale selected generation is valid integrity-wise; a fresh candidate is required.
            }

            try {
                $identity = $prepareIdentity();
                if (!$identity instanceof IdentityPreparationResult) {
                    throw new SandboxProjectionException('source-attestation-drift');
                }
                $freshStable = $this->producer->stableInputs($identity, $effectiveSnapshot, $this->ops->euid() === 0);
            } catch (SandboxProjectionException $e) {
                return new SandboxPublicationResult($e->errorCode(), $selected?->generation);
            } catch (\Throwable) {
                return new SandboxPublicationResult($selected === null ? 'nothing-selected' : 'preserved-prior', $selected?->generation);
            }

            if ($selected !== null && CanonicalJson::encode($selected->stableView($this->selectedOwnershipApplied($selected->generation))) === CanonicalJson::encode($freshStable)) {
                return new SandboxPublicationResult('unchanged-current', $selected->generation);
            }

            $this->cleanupEligible($currentSnapshot);
            if ($this->completeGenerationCount() >= self::MAX_GENERATIONS) {
                return new SandboxPublicationResult($selected === null ? 'nothing-selected' : 'preserved-prior', $selected?->generation);
            }

            $id = $this->generationFactory->mint();
            $candidate = $this->paths->candidate($id);
            if (!$this->ops->mkdir($candidate, 0700)) {
                throw new SandboxProjectionException('candidate-write-failed');
            }
            $this->writeNewFile($candidate . '/.created-at.json', CanonicalJson::encode([
                'schema' => 'sandbox-candidate-residue/v1', 'generation' => $id, 'created_at' => $this->ops->time(),
            ]));
            $projection = $this->producer->produce($id, $identity, $effectiveSnapshot);
            $manifest = $this->materializer->materialize($candidate, $projection, $identity->sources(), $this->ops->time());
            if (!$this->ops->unlink($candidate . '/.created-at.json')) {
                throw new SandboxProjectionException('candidate-write-failed');
            }
            $this->syncDirectory($candidate);
            $this->validateGenerationAt($candidate, $id, $this->writerRegistry, null);

            $final = $this->paths->generation($id);
            if ($this->ops->lstat($final) !== false) {
                $this->removeTree($candidate);
                $candidate = null;
                return new SandboxPublicationResult('generation-name-collision', $selected?->generation);
            }
            $candidateStat = $this->ops->lstat($candidate);
            if (!is_array($candidateStat) || !$this->ops->rename($candidate, $final)) {
                throw new SandboxProjectionException('candidate-rename-failed');
            }
            $candidateRenamed = true;
            $candidate = null;
            $finalStat = $this->ops->lstat($final);
            if (!is_array($finalStat) || (int) $finalStat['dev'] !== (int) $candidateStat['dev'] || (int) $finalStat['ino'] !== (int) $candidateStat['ino']) {
                throw new SandboxProjectionException('candidate-rename-failed');
            }
            $this->syncDirectory($this->paths->generations());

            if (!$this->sameSelectorSnapshot($currentSnapshot)) {
                return new SandboxPublicationResult('publication-lost-race', $selected?->generation);
            }
            try {
                $effectiveNow = $loadEffective();
            } catch (\Throwable) {
                return new SandboxPublicationResult('exposure-generation-changed', $selected?->generation);
            }
            if (!$effectiveNow instanceof EffectiveExposureArtifact || !$this->sameEffective($effectiveSnapshot, $effectiveNow)) {
                return new SandboxPublicationResult('exposure-generation-changed', $selected?->generation);
            }

            $selector = $this->selector($projection, $manifest);
            if ($currentSnapshot !== null) {
                $this->atomicReplace($this->paths->previous(), $currentSnapshot['bytes'], '.previous-' . $currentSnapshot['selector']['generation'] . '.tmp');
            }
            $this->atomicReplace($this->paths->current(), CanonicalJson::encode($selector), '.current-' . $id . '.tmp');
            $selectorCommitted = true;
            $this->syncDirectory($this->paths->root());
            $readback = $this->snapshotSelector();
            if ($readback === null || $readback['bytes'] !== CanonicalJson::encode($selector)) {
                throw new SandboxProjectionException('publication-readback-failed');
            }
            $this->validateSelected($readback['selector']);

            return new SandboxPublicationResult('selected-new', $id);
        } catch (SandboxProjectionException $e) {
            if ($candidate !== null) {
                $this->removeTree($candidate);
            }
            if ($candidateRenamed || $selectorCommitted) {
                return new SandboxPublicationResult('publication-uncertain');
            }
            if (in_array($e->errorCode(), ['selected-generation-invalid', 'source-attestation-drift', 'ownership-apply-failed'], true)) {
                return new SandboxPublicationResult($e->errorCode());
            }

            return new SandboxPublicationResult($hadCurrent ? 'preserved-prior' : 'nothing-selected');
        } finally {
            $identity?->close();
            $this->releaseLock($lock);
        }
    }

    public function recover(): SandboxPublicationResult
    {
        try {
            $this->paths->prepareRoot($this->ops);
            $lock = $this->acquireLock();
        } catch (SandboxProjectionException $e) {
            return new SandboxPublicationResult($e->errorCode());
        }
        try {
            $snapshot = $this->snapshotSelector();
            if ($snapshot === null) {
                return new SandboxPublicationResult('nothing-selected');
            }
            $projection = $this->validateSelected($snapshot['selector']);

            return new SandboxPublicationResult('recovered-selected', $projection->generation);
        } catch (SandboxProjectionException) {
            return new SandboxPublicationResult('invalid-selector');
        } finally {
            $this->releaseLock($lock);
        }
    }

    /** @param callable():EffectiveExposureArtifact $loadEffective */
    public function rollback(callable $loadEffective): SandboxPublicationResult
    {
        try {
            $this->paths->prepareRoot($this->ops);
            $lock = $this->acquireLock();
        } catch (SandboxProjectionException $e) {
            return new SandboxPublicationResult($e->errorCode());
        }
        $committed = false;
        try {
            $current = $this->snapshotSelector();
            $previous = $this->snapshotSelector($this->paths->previous());
            if ($current === null || $previous === null || $current['selector']['generation'] === $previous['selector']['generation']) {
                return new SandboxPublicationResult('invalid-selector');
            }
            $this->validateSelected($current['selector']);
            $projection = $this->validateSelected($previous['selector']);
            $effective = $loadEffective();
            if (!$effective instanceof EffectiveExposureArtifact || !$this->effectiveMatchesProjection($effective, $projection)
                || $projection->projectionRegistryHash !== $this->writerRegistry->registryHash()) {
                return new SandboxPublicationResult('effective-artifact-mismatch');
            }
            if (!$this->sameSelectorSnapshot($current)) {
                return new SandboxPublicationResult('publication-lost-race', $current['selector']['generation']);
            }
            try { $effectiveNow = $loadEffective(); } catch (\Throwable) {
                return new SandboxPublicationResult('exposure-generation-changed', $current['selector']['generation']);
            }
            if (!$effectiveNow instanceof EffectiveExposureArtifact || !$this->sameEffective($effective, $effectiveNow)) {
                return new SandboxPublicationResult('exposure-generation-changed', $current['selector']['generation']);
            }
            $id = $projection->generation;
            $this->atomicReplace($this->paths->previous(), $current['bytes'], '.previous-' . $current['selector']['generation'] . '.tmp');
            $this->atomicReplace($this->paths->current(), $previous['bytes'], '.current-' . $id . '.tmp');
            $committed = true;
            $this->syncDirectory($this->paths->root());
            $check = $this->snapshotSelector();
            if ($check === null || $check['bytes'] !== $previous['bytes']) {
                throw new SandboxProjectionException('publication-readback-failed');
            }
            $this->validateSelected($check['selector']);

            return new SandboxPublicationResult('selected-new', $id);
        } catch (\Throwable) {
            return new SandboxPublicationResult($committed ? 'publication-uncertain' : 'preserved-prior');
        } finally {
            $this->releaseLock($lock);
        }
    }

    /** @param callable():EffectiveExposureArtifact $loadEffective @return array<string,mixed> */
    public function status(callable $loadEffective): array
    {
        try {
            if (!$this->paths->validateExisting($this->ops)) {
                return ['ready' => false, 'code' => 'nothing-selected', 'schema' => self::SELECTOR_SCHEMA, 'generation' => null, 'entries' => []];
            }
            $snapshot = $this->snapshotSelector();
            if ($snapshot === null) {
                return ['ready' => false, 'code' => 'nothing-selected', 'schema' => self::SELECTOR_SCHEMA, 'generation' => null, 'entries' => []];
            }
            $projection = $this->validateSelected($snapshot['selector']);
            $ownership = $this->selectedOwnershipApplied($projection->generation);
            $effective = $loadEffective();
            $match = $effective instanceof EffectiveExposureArtifact && $this->effectiveMatchesProjection($effective, $projection);
            $fingerprints = [];
            foreach ($projection->entries as $entry) {
                if (str_contains($entry->source->sourceClass, 'certificate')) {
                    $fingerprints[$entry->registered->entryId] = $entry->source->envelope['fingerprint_sha256'] ?? null;
                }
            }

            return [
                'ready' => $ownership && $match && $projection->projectionRegistryHash === $this->writerRegistry->registryHash(),
                'code' => !$ownership ? 'ownership-not-applied' : (!$match ? 'effective-artifact-mismatch' : 'ready'),
                'schema' => self::SELECTOR_SCHEMA,
                'generation' => $projection->generation,
                'entry_ids' => array_map(static fn (SandboxProjectionEntry $e): string => $e->registered->entryId, $projection->entries),
                'identity_public_hash' => $projection->identityPublicHash,
                'certificate_fingerprints' => $fingerprints,
                'effective_schema' => $projection->effectiveSchema,
                'effective_revision' => $projection->effectiveRevision,
                'effective_generation' => $projection->effectiveGeneration,
                'effective_hash' => $projection->effectiveHash,
                'effective_match' => $match,
            ];
        } catch (\Throwable) {
            return ['ready' => false, 'code' => 'invalid-selector', 'schema' => self::SELECTOR_SCHEMA, 'generation' => null, 'entries' => []];
        }
    }

    /** @return resource */
    private function acquireLock()
    {
        $path = $this->paths->lock();
        if ($this->ops->lstat($path) === false) {
            $created = $this->ops->openExclusive($path);
            if (is_resource($created)) {
                $this->ops->close($created);
                if (!$this->ops->chmod($path, 0600)) {
                    throw new SandboxProjectionException('publication-lock-invalid');
                }
            }
        }
        $lst = $this->ops->lstat($path);
        if (!is_array($lst) || (((int) $lst['mode']) & 0170000) !== 0100000
            || (int) $lst['nlink'] !== 1 || (int) $lst['uid'] !== $this->ops->euid()
            || (((int) $lst['mode']) & 0777) !== 0600) {
            throw new SandboxProjectionException('publication-lock-invalid');
        }
        $h = $this->ops->openRead($path);
        $fst = is_resource($h) ? $this->ops->fstat($h) : false;
        if (!is_array($fst) || !$this->sameStat($lst, $fst)) {
            if (is_resource($h)) { $this->ops->close($h); }
            throw new SandboxProjectionException('publication-lock-invalid');
        }
        $waited = 0;
        while (!$this->ops->flock($h, LOCK_EX | LOCK_NB)) {
            if ($waited >= self::LOCK_TIMEOUT_MS) {
                $this->ops->close($h);
                throw new SandboxProjectionException('publication-lock-timeout');
            }
            $this->ops->sleepMs(10);
            $waited += 10;
        }

        return $h;
    }

    /** @param resource $h */
    private function releaseLock($h): void
    {
        $this->ops->flock($h, LOCK_UN);
        $this->ops->close($h);
    }

    /** @return array{bytes:string,selector:array<string,mixed>}|null */
    private function snapshotSelector(?string $path = null): ?array
    {
        $path ??= $this->paths->current();
        if ($this->ops->lstat($path) === false) {
            return null;
        }
        $bytes = $this->readTrusted($path, 0600, 65536, $this->ops->euid());
        $doc = json_decode($bytes, true, 8);
        $keys = ['schema', 'generation', 'manifest_sha256', 'projection_sha256', 'effective_schema', 'effective_revision', 'effective_generation', 'effective_hash'];
        if (!is_array($doc) || !$this->sameKeys($doc, $keys) || ($doc['schema'] ?? null) !== self::SELECTOR_SCHEMA
            || preg_match('/^[0-9a-f]{32}$/', (string) ($doc['generation'] ?? '')) !== 1
            || preg_match('/^[0-9a-f]{64}$/', (string) ($doc['manifest_sha256'] ?? '')) !== 1
            || preg_match('/^[0-9a-f]{64}$/', (string) ($doc['projection_sha256'] ?? '')) !== 1
            || !is_int($doc['effective_revision'] ?? null)
            || CanonicalJson::encode($doc) !== $bytes) {
            throw new SandboxProjectionException('invalid-selector');
        }

        return ['bytes' => $bytes, 'selector' => $doc];
    }

    /** @param array<string,mixed> $selector */
    private function validateSelected(array $selector): SandboxProjection
    {
        $id = (string) $selector['generation'];
        $dir = $this->paths->generation($id);
        $projectionBytes = $this->readTrusted($dir . '/' . SandboxPaths::PROJECTION_FILE, 0600, SandboxProjection::MAX_BYTES, $this->ops->euid());
        $projectionDoc = json_decode($projectionBytes, true, 16);
        if (!is_array($projectionDoc) || !is_string($projectionDoc['projection_registry_hash'] ?? null)) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $registry = $this->readers[$projectionDoc['projection_registry_hash']] ?? null;
        if ($registry === null) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $projection = (new SandboxProjectionCodec($registry))->decode($projectionDoc);
        $this->validateGenerationAt($dir, $id, $registry, $selector);

        return $projection;
    }

    /** @param array<string,mixed>|null $selector */
    private function validateGenerationAt(string $dir, string $id, ProjectionEntryRegistry $registry, ?array $selector): SandboxProjection
    {
        $dst = $this->ops->lstat($dir);
        if (!is_array($dst) || (((int) $dst['mode']) & 0170000) !== 0040000 || (int) $dst['uid'] !== $this->ops->euid() || (((int) $dst['mode']) & 0777) !== 0700) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $projectionBytes = $this->readTrusted($dir . '/' . SandboxPaths::PROJECTION_FILE, 0600, SandboxProjection::MAX_BYTES, $this->ops->euid());
        $projectionDoc = json_decode($projectionBytes, true, 16);
        if (!is_array($projectionDoc)) { throw new SandboxProjectionException('selected-generation-invalid'); }
        $projection = (new SandboxProjectionCodec($registry))->decode($projectionDoc);
        if ($projection->generation !== $id || $projection->projectionRegistryHash !== $registry->registryHash()
            || $projection->runtimePolicyHash !== $this->policy->policyHash()
            || CanonicalJson::encode($projectionDoc) !== $projectionBytes) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $manifestBytes = $this->readTrusted($dir . '/' . SandboxPaths::MANIFEST_FILE, 0600, SandboxProjection::MAX_BYTES, $this->ops->euid());
        $manifest = json_decode($manifestBytes, true, 16);
        if (!is_array($manifest) || CanonicalJson::encode($manifest) !== $manifestBytes) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $manifestKeys = ['schema', 'generation', 'created_at', 'ownership_applied', 'effective_schema', 'effective_revision', 'effective_generation', 'effective_hash', 'projection_registry_hash', 'projection_sha256', 'entries'];
        if (!$this->sameKeys($manifest, $manifestKeys) || ($manifest['schema'] ?? null) !== SandboxViewMaterializer::MANIFEST_SCHEMA
            || $manifest['generation'] !== $id || !is_int($manifest['created_at'] ?? null) || !is_bool($manifest['ownership_applied'] ?? null)
            || $manifest['projection_registry_hash'] !== $registry->registryHash() || $manifest['projection_sha256'] !== $projection->digest()) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        foreach (['effective_schema', 'effective_revision', 'effective_generation', 'effective_hash'] as $key) {
            $prop = $this->projectionEffectiveProperty($key);
            if ($manifest[$key] !== $projection->{$prop}) { throw new SandboxProjectionException('selected-generation-invalid'); }
        }
        if (!is_array($manifest['entries'] ?? null) || !array_is_list($manifest['entries'])) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $manifestEntries = [];
        foreach ($manifest['entries'] as $row) {
            if (!is_array($row) || !$this->sameKeys($row, ['entry_id', 'destination_id', 'content_sha256'])) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
            if (!is_string($row['entry_id']) || isset($manifestEntries[$row['entry_id']])) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
            $manifestEntries[$row['entry_id']] = $row;
        }
        $content = [];
        foreach ($projection->entries as $entry) {
            $path = $dir . '/' . $entry->registered->relativePath;
            [$uid] = $entry->registered->destinationOwner->ownership();
            $expectedOwner = $manifest['ownership_applied'] ? $uid : $this->ops->euid();
            $this->validateDestinationDirectories($dir, $entry->registered, $expectedOwner);
            [, $expectedGid] = $entry->registered->destinationOwner->ownership();
            $bytes = $this->readTrusted($path, $entry->registered->fileMode, SandboxProjection::MAX_CONTENT_BYTES + 1, $expectedOwner, $manifest['ownership_applied'] ? $expectedGid : null);
            $manifestEntry = $manifestEntries[$entry->registered->entryId] ?? null;
            if (strlen($bytes) !== $entry->source->byteLength || hash('sha256', $bytes) !== $entry->source->contentSha256
                || !is_array($manifestEntry)
                || $manifestEntry['entry_id'] !== $entry->registered->entryId
                || $manifestEntry['destination_id'] !== $entry->registered->destinationId
                || $manifestEntry['content_sha256'] !== $entry->source->contentSha256) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
            $this->validateDestinationContent($entry, $bytes);
            $content[$entry->source->sourceClass] = $bytes;
        }
        if (count($manifestEntries) !== count($projection->entries)) { throw new SandboxProjectionException('selected-generation-invalid'); }
        $this->validateDestinationTls($content);
        if ($selector !== null && ($selector['generation'] !== $id || $selector['projection_sha256'] !== $projection->digest()
            || $selector['manifest_sha256'] !== CanonicalJson::digest(SandboxViewMaterializer::MANIFEST_HASH_DOMAIN, $manifest))) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        if ($selector !== null) {
            foreach (['effective_schema', 'effective_revision', 'effective_generation', 'effective_hash'] as $key) {
                if ($selector[$key] !== $manifest[$key]) { throw new SandboxProjectionException('selected-generation-invalid'); }
            }
        }

        return $projection;
    }

    private function validateDestinationDirectories(string $generationDir, ProjectionRegistryEntry $entry, int $expectedOwner): void
    {
        $relativeParent = dirname($entry->relativePath);
        $cursor = $generationDir;
        foreach (explode('/', $relativeParent) as $component) {
            $cursor .= '/' . $component;
            $st = $this->ops->lstat($cursor);
            $isViews = $component === 'views' && $cursor === $generationDir . '/views';
            $mode = $isViews ? 0700 : $entry->directoryMode;
            $owner = $isViews ? $this->ops->euid() : $expectedOwner;
            [, $expectedGid] = $entry->destinationOwner->ownership();
            if (!is_array($st) || (((int) $st['mode']) & 0170000) !== 0040000 || (int) $st['uid'] !== $owner
                || (!$isViews && $this->ops->euid() === 0 && (int) $st['gid'] !== $expectedGid)
                || (((int) $st['mode']) & 0777) !== $mode) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
        }
    }

    private function selectedOwnershipApplied(string $id): bool
    {
        $bytes = $this->readTrusted($this->paths->manifest($id), 0600, SandboxProjection::MAX_BYTES, $this->ops->euid());
        $doc = json_decode($bytes, true);

        return is_array($doc) && ($doc['ownership_applied'] ?? null) === true;
    }

    /** @param array<string,mixed> $manifest @return array<string,mixed> */
    private function selector(SandboxProjection $projection, array $manifest): array
    {
        return [
            'schema' => self::SELECTOR_SCHEMA,
            'generation' => $projection->generation,
            'manifest_sha256' => CanonicalJson::digest(SandboxViewMaterializer::MANIFEST_HASH_DOMAIN, $manifest),
            'projection_sha256' => $projection->digest(),
            'effective_schema' => $projection->effectiveSchema,
            'effective_revision' => $projection->effectiveRevision,
            'effective_generation' => $projection->effectiveGeneration,
            'effective_hash' => $projection->effectiveHash,
        ];
    }

    private function effectiveMatchesProjection(EffectiveExposureArtifact $effective, SandboxProjection $projection): bool
    {
        return $effective->schema() === $projection->effectiveSchema && $effective->revision() === $projection->effectiveRevision
            && hash_equals($effective->generation(), $projection->effectiveGeneration) && hash_equals($effective->hash(), $projection->effectiveHash);
    }

    private function sameEffective(EffectiveExposureArtifact $a, EffectiveExposureArtifact $b): bool
    {
        return $a->schema() === $b->schema() && $a->revision() === $b->revision()
            && hash_equals($a->generation(), $b->generation()) && hash_equals($a->hash(), $b->hash());
    }

    /** @param array{bytes:string,selector:array<string,mixed>}|null $snapshot */
    private function sameSelectorSnapshot(?array $snapshot): bool
    {
        try { $now = $this->snapshotSelector(); } catch (\Throwable) { return false; }
        return $snapshot === null ? $now === null : ($now !== null && $now['bytes'] === $snapshot['bytes']);
    }

    private function atomicReplace(string $path, string $bytes, string $tempName): void
    {
        $temp = $this->paths->root() . '/' . $tempName;
        $h = $this->ops->openExclusive($temp);
        if (!is_resource($h)) { throw new SandboxProjectionException('selector-write-failed'); }
        try {
            $offset = 0;
            while ($offset < strlen($bytes)) {
                $n = $this->ops->write($h, substr($bytes, $offset));
                if (!is_int($n) || $n < 1) { throw new SandboxProjectionException('selector-write-failed'); }
                $offset += $n;
            }
            if (!$this->ops->flush($h) || !$this->ops->fdatasync($h) || !$this->ops->chmod($temp, 0600)
                || !$this->ops->fdatasync($h)) { throw new SandboxProjectionException('selector-write-failed'); }
        } finally { $this->ops->close($h); }
        if (!$this->ops->rename($temp, $path)) {
            throw new SandboxProjectionException('selector-write-failed');
        }
    }

    private function writeNewFile(string $path, string $bytes): void
    {
        $h = $this->ops->openExclusive($path);
        if (!is_resource($h)) { throw new SandboxProjectionException('candidate-write-failed'); }
        try {
            $offset = 0;
            while ($offset < strlen($bytes)) {
                $n = $this->ops->write($h, substr($bytes, $offset));
                if (!is_int($n) || $n < 1) { throw new SandboxProjectionException('candidate-write-failed'); }
                $offset += $n;
            }
            if (!$this->ops->flush($h) || !$this->ops->chmod($path, 0600) || !$this->ops->fdatasync($h)) {
                throw new SandboxProjectionException('candidate-write-failed');
            }
        } finally { $this->ops->close($h); }
    }

    private function readTrusted(string $path, int $mode, int $max, int $owner, ?int $gid = null): string
    {
        $lst = $this->ops->lstat($path);
        if (!is_array($lst) || (((int) $lst['mode']) & 0170000) !== 0100000
            || (int) $lst['nlink'] !== 1 || (int) $lst['uid'] !== $owner || (((int) $lst['mode']) & 0777) !== $mode
            || ($gid !== null && (int) $lst['gid'] !== $gid)) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $h = $this->ops->openRead($path);
        $fst = is_resource($h) ? $this->ops->fstat($h) : false;
        if (!is_array($fst) || !$this->sameStat($lst, $fst)) {
            if (is_resource($h)) { $this->ops->close($h); }
            throw new SandboxProjectionException('selected-generation-invalid');
        }
        $bytes = $this->ops->readAll($h, $max + 1);
        $after = $this->ops->fstat($h);
        $this->ops->close($h);
        if (!is_string($bytes) || strlen($bytes) > $max || !is_array($after) || !$this->sameStat($fst, $after)) {
            throw new SandboxProjectionException('selected-generation-invalid');
        }

        return $bytes;
    }

    /** @param array<string,int> $a @param array<string,int> $b */
    private function sameStat(array $a, array $b): bool
    {
        foreach (['dev', 'ino', 'mode', 'uid', 'gid', 'nlink'] as $key) {
            if ((int) $a[$key] !== (int) $b[$key]) { return false; }
        }
        return true;
    }

    private function projectionEffectiveProperty(string $key): string
    {
        return match ($key) {
            'effective_schema' => 'effectiveSchema', 'effective_revision' => 'effectiveRevision',
            'effective_generation' => 'effectiveGeneration', 'effective_hash' => 'effectiveHash',
        };
    }

    private function validateDestinationContent(SandboxProjectionEntry $entry, string $bytes): void
    {
        if (str_contains($entry->source->sourceClass, 'identity-source')) {
            if (!ProjectionEnvelopePolicy::validIdentity($entry->source->sourceClass, $entry->source->envelope)) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
            try { $doc = IdentityBundleReader::decode($bytes, (string) ProjectionEnvelopePolicy::identityBundle($entry->source->sourceClass)); }
            catch (\Throwable) { throw new SandboxProjectionException('selected-generation-invalid'); }
            foreach (['schema', 'bundle', 'public_persona_hash', 'keyset_commitment'] as $key) {
                if (($doc['envelope'][$key] ?? null) !== ($entry->source->envelope[$key] ?? null)) {
                    throw new SandboxProjectionException('selected-generation-invalid');
                }
            }
        } elseif (str_contains($entry->source->sourceClass, 'certificate')) {
            $fp = @openssl_x509_fingerprint($bytes, 'sha256');
            if (!is_string($fp) || strtolower(str_replace(':', '', $fp)) !== ($entry->source->envelope['fingerprint_sha256'] ?? null)) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
        }
    }

    /** @param array<string,string> $contents */
    private function validateDestinationTls(array $contents): void
    {
        foreach ([[PreparedIdentitySource::TLS_CERTIFICATE, PreparedIdentitySource::TLS_PRIVATE_KEY], [PreparedIdentitySource::ADMIN_TLS_CERTIFICATE, PreparedIdentitySource::ADMIN_TLS_PRIVATE_KEY]] as [$cert, $key]) {
            if (isset($contents[$cert]) !== isset($contents[$key])) { throw new SandboxProjectionException('selected-generation-invalid'); }
            if (isset($contents[$cert]) && !@openssl_x509_check_private_key($contents[$cert], $contents[$key])) {
                throw new SandboxProjectionException('selected-generation-invalid');
            }
        }
    }

    private function completeGenerationCount(): int
    {
        $names = $this->ops->scandir($this->paths->generations());
        if (!is_array($names)) { throw new SandboxProjectionException('generation-store-invalid'); }
        return count(array_filter($names, static fn (string $name): bool => preg_match('/^[0-9a-f]{32}$/', $name) === 1));
    }

    /** @param array{bytes:string,selector:array<string,mixed>}|null $current */
    private function cleanupEligible(?array $current): void
    {
        $protected = [];
        if ($current !== null) { $protected[(string) $current['selector']['generation']] = true; }
        try {
            $previous = $this->snapshotSelector($this->paths->previous());
            if ($previous !== null) { $protected[(string) $previous['selector']['generation']] = true; }
        } catch (\Throwable) {
            // Invalid previous is not guessed from; retain it for operator diagnosis.
        }
        $eligible = [];
        $names = $this->ops->scandir($this->paths->generations());
        if (!is_array($names)) { return; }
        foreach ($names as $name) {
            $isGeneration = preg_match('/^[0-9a-f]{32}$/', $name) === 1;
            $isCandidate = preg_match('/^\.candidate-([0-9a-f]{32})$/', $name, $candidateMatch) === 1;
            if ((!$isGeneration && !$isCandidate) || ($isGeneration && isset($protected[$name]))) { continue; }
            $dir = $this->paths->generations() . '/' . $name;
            try {
                $manifestPath = $dir . '/' . SandboxPaths::MANIFEST_FILE;
                if ($this->ops->lstat($manifestPath) !== false) {
                    $bytes = $this->readTrusted($manifestPath, 0600, SandboxProjection::MAX_BYTES, $this->ops->euid());
                    $manifest = json_decode($bytes, true);
                    $created = is_array($manifest) && is_int($manifest['created_at'] ?? null) ? $manifest['created_at'] : null;
                } else {
                    $bytes = $this->readTrusted($dir . '/.created-at.json', 0600, 1024, $this->ops->euid());
                    $record = json_decode($bytes, true);
                    $created = is_array($record) && ($record['schema'] ?? null) === 'sandbox-candidate-residue/v1'
                        && ($record['generation'] ?? null) === ($candidateMatch[1] ?? null) && is_int($record['created_at'] ?? null)
                        ? $record['created_at'] : null;
                }
                if ($created !== null && $created <= $this->ops->time() && $this->ops->time() - $created >= self::RETENTION_SECONDS) {
                    $eligible[] = [$created, $name, 'directory'];
                }
            } catch (\Throwable) { }
        }
        $rootNames = $this->ops->scandir($this->paths->root());
        if (is_array($rootNames)) {
            foreach ($rootNames as $name) {
                if (preg_match('/^\.(?:current|previous)-([0-9a-f]{32})\.tmp$/', $name, $m) !== 1) { continue; }
                try {
                    $bytes = $this->readTrusted($this->paths->root() . '/' . $name, 0600, 65536, $this->ops->euid());
                    $selector = json_decode($bytes, true);
                    $generation = is_array($selector) ? ($selector['generation'] ?? null) : null;
                    if (!is_string($generation) || $generation !== $m[1]) { continue; }
                    $manifestBytes = $this->readTrusted($this->paths->manifest($generation), 0600, SandboxProjection::MAX_BYTES, $this->ops->euid());
                    $manifest = json_decode($manifestBytes, true);
                    $created = is_array($manifest) && is_int($manifest['created_at'] ?? null) ? $manifest['created_at'] : null;
                    if ($created !== null && $created <= $this->ops->time() && $this->ops->time() - $created >= self::RETENTION_SECONDS) {
                        $eligible[] = [$created, $name, 'file'];
                    }
                } catch (\Throwable) { }
            }
        }
        sort($eligible);
        foreach (array_slice($eligible, 0, self::MAX_CLEANUP) as [, $name, $kind]) {
            if ($kind === 'directory') {
                $this->removeTree($this->paths->generations() . '/' . $name);
            } else {
                $this->ops->unlink($this->paths->root() . '/' . $name);
            }
        }
    }

    private function removeTree(string $path): void
    {
        if (!$this->treeIsKnownAndRemovable($path)) { return; }
        $this->removeValidatedTree($path);
    }

    private function removeValidatedTree(string $path): void
    {
        $this->ops->chmod($path, 0700);
        $names = $this->ops->scandir($path);
        if (!is_array($names)) { return; }
        foreach ($names as $name) {
            if ($name === '.' || $name === '..') { continue; }
            $child = $path . '/' . $name;
            $childSt = $this->ops->lstat($child);
            if (is_array($childSt) && (((int) $childSt['mode']) & 0170000) === 0040000) {
                $this->removeValidatedTree($child);
            } elseif (is_array($childSt)) {
                $this->ops->unlink($child);
            }
        }
        $this->ops->rmdir($path);
    }

    private function treeIsKnownAndRemovable(string $path): bool
    {
        $allowedOwners = [$this->ops->euid()];
        if ($this->ops->euid() === 0) {
            foreach (ProjectionDestinationOwner::cases() as $owner) { $allowedOwners[] = $owner->ownership()[0]; }
        }
        $st = $this->ops->lstat($path);
        if (!is_array($st) || (((int) $st['mode']) & 0170000) !== 0040000 || !in_array((int) $st['uid'], $allowedOwners, true)) { return false; }
        $names = $this->ops->scandir($path);
        if (!is_array($names)) { return false; }
        foreach ($names as $name) {
            if ($name === '.' || $name === '..') { continue; }
            $child = $path . '/' . $name;
            $childSt = $this->ops->lstat($child);
            if (!is_array($childSt) || !in_array((int) $childSt['uid'], $allowedOwners, true)) { return false; }
            $type = ((int) $childSt['mode']) & 0170000;
            if ($type === 0040000) {
                if (!$this->treeIsKnownAndRemovable($child)) { return false; }
            } elseif ($type !== 0100000 || (int) $childSt['nlink'] !== 1) {
                return false;
            }
        }
        return true;
    }

    private function syncDirectory(string $path): void
    {
        $h = $this->ops->openDir($path);
        if (!is_resource($h)) { throw new SandboxProjectionException('directory-fsync-failed'); }
        try { if (!$this->ops->fsync($h)) { throw new SandboxProjectionException('directory-fsync-failed'); } }
        finally { $this->ops->close($h); }
    }

    /** @param array<string,mixed> $value @param list<string> $keys */
    private function sameKeys(array $value, array $keys): bool
    {
        $actual = array_keys($value); sort($actual); sort($keys); return $actual === $keys;
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use RuntimeException;

/**
 * Root (pre-split) / the protocol supervisor (post-split) publishes the read-only runtime status
 * heartbeat here. The exact schema is `funnypot-effective-service-status/v1`: a CSPRNG writer_boot_id,
 * a monotonic sequence, written_at, the byte-exact effective artifact, status_revision, a closed
 * state, a closed acceptance_mode, sorted per-process health and an envelope_hash. It is rewritten at
 * least every five seconds even when health is unchanged, and the first `reconciling` heartbeat is
 * written before the supervisor's first fork/probe so the 15-second freshness gate cannot fail during
 * the first-boot probe window.
 *
 * The file is 0444 under a 0755 dir; when root, both are chowned to the numeric writer uid (10002)
 * from day one so the reader has one owner constant before and after the FP-0107 role split. Every
 * write is exclusive temp + write/flush/fsync + chmod + atomic rename + directory fsync.
 */
final class ServiceStatusPublisher
{
    public const SCHEMA = 'funnypot-effective-service-status/v1';
    public const HASH_DOMAIN = 'funnypot/effective-service-status/v1';
    public const MAX_BYTES = 65536;
    public const WRITER_UID = 10002;

    private string $bootId;
    private int $sequence = 0;

    public function __construct(
        private string $statusFile,
        private ?IdentityFileOps $ops = null,
        ?string $bootId = null,
    ) {
        $this->ops = $ops ?? new IdentityFileOps();
        $this->bootId = $bootId ?? bin2hex(random_bytes(16));
    }

    /**
     * @param array<string,string> $processHealth process id => health value
     */
    public function publish(EffectiveExposureArtifact $artifact, string $state, string $acceptanceMode, array $processHealth, int $statusRevision, ?int $writtenAt = null): void
    {
        ksort($processHealth);
        $this->sequence++;
        $payload = [
            'schema' => self::SCHEMA,
            'writer_boot_id' => $this->bootId,
            'sequence' => $this->sequence,
            'written_at' => $writtenAt ?? $this->ops->time(),
            'effective_artifact' => $artifact->toArray(),
            'status_revision' => $statusRevision,
            'state' => $state,
            'acceptance_mode' => $acceptanceMode,
            'process_health' => (object) $processHealth,
        ];
        $doc = $payload;
        // process_health serialized as an object even when empty; CanonicalJson wants an assoc array.
        $doc['process_health'] = $processHealth;
        $envelopeHash = CanonicalJson::digest(self::HASH_DOMAIN, $doc);
        $doc['envelope_hash'] = $envelopeHash;
        $bytes = CanonicalJson::encode($doc);
        if (strlen($bytes) > self::MAX_BYTES) {
            throw new RuntimeException('status heartbeat exceeds ' . self::MAX_BYTES . ' bytes');
        }
        $this->ensureDir(dirname($this->statusFile));
        $this->writeAtomic($this->statusFile, $bytes);
    }

    public function bootId(): string
    {
        return $this->bootId;
    }

    private function ensureDir(string $dir): void
    {
        if ($this->ops->lstat($dir) === false) {
            $this->ops->mkdir($dir, 0755);
            $this->ops->chmod($dir, 0755);
        }
        if ($this->ops->euid() === 0) {
            @chown($dir, self::WRITER_UID);
            @chgrp($dir, self::WRITER_UID);
        }
    }

    private function writeAtomic(string $path, string $bytes): void
    {
        $tmp = $path . '.tmp.' . $this->ops->randomHex(6);
        $h = $this->ops->openExclusive($tmp);
        if ($h === false) {
            throw new RuntimeException('status heartbeat: temp open failed');
        }
        try {
            if ($this->ops->write($h, $bytes) !== strlen($bytes) || !$this->ops->flush($h) || !$this->ops->fsync($h)) {
                throw new RuntimeException('status heartbeat: write failed');
            }
            $this->ops->close($h);
            if ($this->ops->euid() === 0) {
                @chown($tmp, self::WRITER_UID);
                @chgrp($tmp, self::WRITER_UID);
            }
            $this->ops->chmod($tmp, 0444);
            if (!$this->ops->rename($tmp, $path)) {
                throw new RuntimeException('status heartbeat: rename failed');
            }
        } catch (\Throwable $e) {
            $this->ops->close($h);
            $this->ops->unlink($tmp);
            throw $e;
        }
        $d = $this->ops->openDir(dirname($path));
        if ($d !== false) {
            $this->ops->fsync($d);
            $this->ops->close($d);
        }
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use Throwable;

/**
 * Reads the runtime status heartbeat under the B2 invariant: the web role never varies an
 * attacker-facing byte on heartbeat availability. {@see current()} always returns a usable
 * deployment-global profile and a freshness marker; on a missing/stale/corrupt heartbeat it serves
 * the last verified snapshot (from APCu shared across the fpm workers, or a per-process memo when the
 * ext is absent), and only with no cache at all falls back to the family-neutral profile.
 *
 * Per request it does one lstat: an unchanged file identity (dev, ino, size, mtime) reuses the cached
 * decode without reopening or rehashing; a changed identity performs the full verified read. Freshness
 * is judged from the cached written_at, so a stalled heartbeat costs nothing extra and never changes
 * the served profile. Nothing here throws into the request path.
 */
final class ServiceStatusReader
{
    public const FRESHNESS_WINDOW = 15;
    public const FUTURE_SKEW = 5;
    private const NEUTRAL_VARIANT = 'spv1_00000000000000000000000000000000';

    private const S_IFMT = 0170000;
    private const S_IFREG = 0100000;

    private const APCU_PREFIX = 'fp.svc.status.';

    private IdentityFileOps $ops;
    private string $apcuKey;
    /** @var array{identity:array{int,int,int,int},snapshot:ServiceStatusSnapshot}|null */
    private ?array $memo = null;

    public function __construct(
        private string $statusFile,
        ?IdentityFileOps $ops = null,
        private int $writerUid = ServiceStatusPublisher::WRITER_UID,
        private ?int $now = null,
    ) {
        $this->ops = $ops ?? new IdentityFileOps();
        $this->apcuKey = self::APCU_PREFIX . substr(md5($statusFile), 0, 12);
    }

    public static function familyNeutralProfile(): EffectiveServiceProfile
    {
        return new EffectiveServiceProfile('neutral', self::NEUTRAL_VARIANT, []);
    }

    /**
     * The per-request web entry. Never throws; always returns a view with a usable profile.
     */
    public function current(): ServiceStatusView
    {
        $st = $this->ops->lstat($this->statusFile);
        $identity = $st === false ? null : [(int) $st['dev'], (int) $st['ino'], (int) $st['size'], (int) $st['mtime']];

        // Unchanged identity: reuse the cached decode, no reopen.
        $cached = $this->cachedEntry();
        if ($identity !== null && $cached !== null && $cached['identity'] === $identity) {
            return ServiceStatusView::fromSnapshot($cached['snapshot'], $this->freshnessOf($cached['snapshot']->writtenAt()));
        }

        [$snapshot, $reason] = $this->readVerified();
        if ($snapshot !== null) {
            if ($identity !== null) {
                $this->storeEntry($identity, $snapshot);
            }
            return ServiceStatusView::fromSnapshot($snapshot, $this->freshnessOf($snapshot->writtenAt()));
        }

        // Missing/corrupt: serve the last verified snapshot marked stale/corrupt, else family-neutral.
        if ($cached !== null) {
            $mark = $reason === ServiceStatusSnapshot::CORRUPT ? ServiceStatusSnapshot::CORRUPT : ServiceStatusSnapshot::STALE;

            return ServiceStatusView::fromSnapshot($cached['snapshot'], $mark);
        }

        return ServiceStatusView::familyNeutral($reason);
    }

    /**
     * Full verification. Returns [snapshot, fresh|stale] on success, [null, missing|corrupt] otherwise.
     * A stale-but-hash-valid file is still decoded (nit C) and returned marked stale.
     *
     * @return array{0:?ServiceStatusSnapshot,1:string}
     */
    public function readVerified(): array
    {
        $st = $this->ops->lstat($this->statusFile);
        if ($st === false) {
            return [null, ServiceStatusSnapshot::MISSING];
        }
        $mode = (int) $st['mode'];
        if (($mode & self::S_IFMT) !== self::S_IFREG
            || (int) $st['nlink'] !== 1
            || !in_array((int) $st['uid'], $this->acceptedOwners(), true)
            || ($mode & 0022) !== 0) {
            return [null, ServiceStatusSnapshot::CORRUPT];
        }
        $h = $this->ops->openRead($this->statusFile);
        if ($h === false) {
            return [null, ServiceStatusSnapshot::MISSING];
        }
        try {
            $fst = $this->ops->fstat($h);
            if ($fst === false || (int) $fst['dev'] !== (int) $st['dev'] || (int) $fst['ino'] !== (int) $st['ino'] || (int) $fst['size'] !== (int) $st['size']) {
                return [null, ServiceStatusSnapshot::CORRUPT];
            }
            $bytes = $this->ops->readAll($h, ServiceStatusPublisher::MAX_BYTES + 1);
            if ($bytes === false || strlen($bytes) > ServiceStatusPublisher::MAX_BYTES) {
                return [null, ServiceStatusSnapshot::CORRUPT];
            }
            $fst2 = $this->ops->fstat($h);
            if ($fst2 === false || (int) $fst2['size'] !== strlen($bytes)) {
                return [null, ServiceStatusSnapshot::CORRUPT];
            }
        } finally {
            $this->ops->close($h);
        }

        try {
            $doc = json_decode($bytes, true);
            if (!is_array($doc) || ($doc['schema'] ?? null) !== ServiceStatusPublisher::SCHEMA) {
                return [null, ServiceStatusSnapshot::CORRUPT];
            }
            $stored = $doc['envelope_hash'] ?? null;
            if (!is_string($stored)) {
                return [null, ServiceStatusSnapshot::CORRUPT];
            }
            $forHash = $doc;
            unset($forHash['envelope_hash']);
            if (!hash_equals(CanonicalJson::digest(ServiceStatusPublisher::HASH_DOMAIN, $forHash), $stored)) {
                return [null, ServiceStatusSnapshot::CORRUPT];
            }
            if (!is_array($doc['effective_artifact'] ?? null)) {
                return [null, ServiceStatusSnapshot::CORRUPT];
            }
            $artifact = EffectiveExposureArtifact::fromArray($doc['effective_artifact']);
        } catch (Throwable $e) {
            return [null, ServiceStatusSnapshot::CORRUPT];
        }

        $freshness = $this->freshnessOf((int) ($doc['written_at'] ?? 0));

        return [ServiceStatusSnapshot::verified($doc, $artifact, $freshness), $freshness];
    }

    /** @return list<int> */
    private function acceptedOwners(): array
    {
        return array_values(array_unique([0, $this->writerUid, $this->ops->euid()]));
    }

    private function freshnessOf(int $writtenAt): string
    {
        $now = $this->now ?? $this->ops->time();
        if ($writtenAt <= $now + self::FUTURE_SKEW && $writtenAt >= $now - self::FRESHNESS_WINDOW) {
            return ServiceStatusSnapshot::FRESH;
        }

        return ServiceStatusSnapshot::STALE;
    }

    /** @return array{identity:array{int,int,int,int},snapshot:ServiceStatusSnapshot}|null */
    private function cachedEntry(): ?array
    {
        if ($this->memo !== null) {
            return $this->memo;
        }
        if (function_exists('apcu_fetch')) {
            $ok = false;
            $v = apcu_fetch($this->apcuKey, $ok);
            if ($ok && is_array($v) && isset($v['identity'], $v['snapshot']) && $v['snapshot'] instanceof ServiceStatusSnapshot) {
                return $this->memo = $v;
            }
        }

        return null;
    }

    /** @param array{int,int,int,int} $identity */
    private function storeEntry(array $identity, ServiceStatusSnapshot $snapshot): void
    {
        $entry = ['identity' => $identity, 'snapshot' => $snapshot];
        $this->memo = $entry;
        if (function_exists('apcu_store')) {
            apcu_store($this->apcuKey, $entry);
        }
    }
}

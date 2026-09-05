<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use PDO;
use RuntimeException;
use Throwable;

/**
 * The root-only effective/LKG authority (0600 root:root runtime.sqlite). PHP never opens it; it sees
 * only the root-published read-only status heartbeat. It holds exactly one accepted set — effective
 * equals last-known-good — plus its acceptance mode (`bootstrap` vs `health`). Acceptance mode is NOT
 * part of the hashed artifact, so the first health acceptance of a bootstrap-accepted set flips only
 * the mode and rotates nothing downstream.
 *
 * Transitions:
 *   - bootstrapAccept(): valid only on an empty store; commits effective revision 1 == desired 1.
 *   - confirmHealth(): the same accepted set passed its first probe; flip mode to `health` only.
 *   - commitHealth():  a real cutover committed a new accepted set (effective = LKG = new).
 */
final class ServiceRuntimeStore
{
    public const MODE_BOOTSTRAP = 'bootstrap';
    public const MODE_HEALTH = 'health';

    private ?PDO $db = null;

    public function __construct(
        private string $dbPath,
        private ?IdentityFileOps $ops = null,
    ) {
        $this->ops ??= new IdentityFileOps();
    }

    public function isEmpty(): bool
    {
        return $this->acceptedRow() === null;
    }

    /** Commit the bootstrap-accepted effective revision 1 == desired revision 1. Empty store only. */
    public function bootstrapAccept(ServiceExposureManifest $manifest): void
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            if ($db->query('SELECT 1 FROM service_runtime_accepted WHERE id = 1')->fetchColumn() !== false) {
                throw new RuntimeException('runtime store: bootstrapAccept on a non-empty store');
            }
            $art = $manifest->effectiveArtifact();
            $this->writeAccepted($db, $art->revision(), $art->desiredRevision(), self::MODE_BOOTSTRAP, $manifest, $art);
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    /**
     * First-boot convergence: the same accepted set passed its probes. Flip the mode to `health`
     * without touching the artifact bytes/revision/generation/hash. Throws if the set differs.
     */
    public function confirmHealth(EffectiveExposureArtifact $expected): void
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $row = $db->query('SELECT effective_hash FROM service_runtime_accepted WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new RuntimeException('runtime store: confirmHealth on an empty store');
            }
            if (!hash_equals((string) $row['effective_hash'], $expected->hash())) {
                throw new RuntimeException('runtime store: confirmHealth set mismatch');
            }
            $db->prepare('UPDATE service_runtime_accepted SET acceptance_mode = :m WHERE id = 1')
                ->execute([':m' => self::MODE_HEALTH]);
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    /** A real cutover committed a new accepted set (effective = LKG = new), acceptance_mode = health. */
    public function commitHealth(ServiceExposureManifest $manifest): void
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $art = $manifest->effectiveArtifact();
            $this->writeAccepted($db, $art->revision(), $art->desiredRevision(), self::MODE_HEALTH, $manifest, $art);
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    public function acceptedManifest(): ?ServiceExposureManifest
    {
        $row = $this->acceptedRow();
        if ($row === null) {
            return null;
        }
        $doc = json_decode((string) $row['manifest_json'], true);
        if (!is_array($doc)) {
            throw new RuntimeException('runtime store: corrupt accepted manifest');
        }

        return ServiceExposureManifest::fromArray($doc);
    }

    public function acceptedArtifact(): ?EffectiveExposureArtifact
    {
        return $this->acceptedManifest()?->effectiveArtifact();
    }

    public function acceptanceMode(): ?string
    {
        $row = $this->acceptedRow();

        return $row === null ? null : (string) $row['acceptance_mode'];
    }

    public function acceptedDesiredRevision(): ?int
    {
        $row = $this->acceptedRow();

        return $row === null ? null : (int) $row['desired_revision'];
    }

    /** @return array<string,mixed>|null */
    private function acceptedRow(): ?array
    {
        try {
            $row = $this->db()->query('SELECT * FROM service_runtime_accepted WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return null;
        }

        return $row === false ? null : $row;
    }

    private function writeAccepted(PDO $db, int $effectiveRevision, int $desiredRevision, string $mode, ServiceExposureManifest $manifest, EffectiveExposureArtifact $art): void
    {
        $db->prepare('INSERT INTO service_runtime_accepted
            (id, effective_revision, desired_revision, desired_hash, effective_hash, acceptance_mode, manifest_json, created_at)
            VALUES (1, :er, :dr, :dh, :eh, :m, :mj, :ts)
            ON CONFLICT(id) DO UPDATE SET
              effective_revision = :er, desired_revision = :dr, desired_hash = :dh, effective_hash = :eh,
              acceptance_mode = :m, manifest_json = :mj, created_at = :ts')
            ->execute([
                ':er' => $effectiveRevision, ':dr' => $desiredRevision,
                ':dh' => (string) ($manifest->toArray()['desired_hash'] ?? ''),
                ':eh' => $art->hash(), ':m' => $mode, ':mj' => $manifest->toJson(), ':ts' => gmdate('c'),
            ]);
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $db = ServiceSqlite::open($this->dbPath, 0600, null, $this->ops);
        $db->exec('CREATE TABLE IF NOT EXISTS service_runtime_accepted (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            effective_revision INTEGER NOT NULL,
            desired_revision INTEGER NOT NULL,
            desired_hash TEXT NOT NULL,
            effective_hash TEXT NOT NULL,
            acceptance_mode TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )');

        return $this->db = $db;
    }
}

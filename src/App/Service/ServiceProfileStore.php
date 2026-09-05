<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use PDO;
use Throwable;

/**
 * The one typed desired aggregate — NOT a set of ordinary ConfigRegistry keys. It holds a single
 * current desired row with a monotonic revision, a reconciliation-control row with a root-issued
 * lease, and an append-only audit log, on a dedicated 0660 root:www-data service-profile.sqlite.
 * {@see applyCas()} is a real compare-and-set (BEGIN IMMEDIATE, re-read, re-resolve, compare the
 * preview hash, one atomic insert/audit), so a concurrent write loses cleanly with no partial state
 * and no audit row.
 *
 * The lease guards a live cutover: while `in_flight_revision` is set every apply is refused, and the
 * root supervisor must present the opaque lease (only its SHA-256 is stored) to finish or roll back.
 */
final class ServiceProfileStore
{
    private ?PDO $db = null;

    public function __construct(
        private string $dbPath,
        private ?IdentityFileOps $ops = null,
    ) {
        $this->ops ??= new IdentityFileOps();
    }

    /** @return array<string,mixed>|null the current desired row, or null when the store is empty */
    public function snapshot(): ?array
    {
        try {
            $row = $this->db()->query('SELECT * FROM service_profile_current WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return null;
        }

        return $row === false ? null : $row;
    }

    public function currentRevision(): int
    {
        $row = $this->snapshot();

        return $row === null ? 0 : (int) $row['revision'];
    }

    public function isEmpty(): bool
    {
        return $this->snapshot() === null;
    }

    /** @return list<array<string,mixed>> newest first */
    public function audits(int $limit = 200): array
    {
        try {
            $st = $this->db()->prepare('SELECT * FROM service_profile_audit ORDER BY id DESC LIMIT :n');
            $st->bindValue(':n', max(1, $limit), PDO::PARAM_INT);
            $st->execute();

            return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
        } catch (Throwable $e) {
            return [];
        }
    }

    /**
     * Commit desired revision 1 only when the store is empty (first boot / bootstrap chooser). A
     * no-op returning the current revision when a row already exists.
     *
     * @param array{input_json:string,resolved_json:string,preview_hash:string,desired_hash:string,catalog_hash:string,published_hash:string} $fields
     */
    public function initializeIfEmpty(array $fields, string $actor): int
    {
        $db = $this->db();
        $db->beginTransaction();
        try {
            $existing = $db->query('SELECT revision FROM service_profile_current WHERE id = 1')->fetchColumn();
            if ($existing !== false) {
                $db->commit();

                return (int) $existing;
            }
            $this->writeCurrent($db, 1, $fields, $actor);
            $this->audit($db, 1, $actor, '', null, $fields['input_json'], 'bootstrap', '');
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }

        return 1;
    }

    /**
     * Compare-and-set apply. Inside BEGIN IMMEDIATE: re-read the current revision, refuse if a
     * reconciliation is in flight, re-resolve via $resolver (so a catalog change between preview and
     * apply is caught), compare the fresh preview hash to the operator's, and commit one new revision
     * with an audit row. Any mismatch throws a conflict and changes nothing.
     *
     * @param callable():array{input_json:string,resolved_json:string,preview_hash:string,desired_hash:string,catalog_hash:string,published_hash:string} $resolver
     */
    public function applyCas(int $expectedRevision, string $expectedPreviewHash, callable $resolver, string $actor, string $sourceIp): int
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $current = $db->query('SELECT revision FROM service_profile_current WHERE id = 1')->fetchColumn();
            $currentRevision = $current === false ? 0 : (int) $current;
            if ($currentRevision !== $expectedRevision) {
                throw new ServiceProfileConflictException('stale-revision');
            }
            $control = $db->query('SELECT in_flight_revision FROM service_profile_control WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
            if ($control !== false && $control['in_flight_revision'] !== null) {
                throw new ServiceProfileConflictException('reconciling');
            }
            $fields = $resolver();
            if (!hash_equals($expectedPreviewHash, $fields['preview_hash'])) {
                throw new ServiceProfileConflictException('preview-hash-changed');
            }
            $old = $db->query('SELECT input_json FROM service_profile_current WHERE id = 1')->fetchColumn();
            $newRevision = $currentRevision + 1;
            $this->writeCurrent($db, $newRevision, $fields, $actor);
            $this->audit($db, $newRevision, $actor, $sourceIp, $old === false ? null : (string) $old, $fields['input_json'], 'applied', '');
            $db->commit();

            return $newRevision;
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Append a system rollback revision atomically under a held lease (a failed cutover). Only the
     * lease owner may do this, so an operator write cannot race it.
     *
     * @param callable():array{input_json:string,resolved_json:string,preview_hash:string,desired_hash:string,catalog_hash:string,published_hash:string} $lkgResolver
     */
    public function rollbackClaimed(string $lease, int $failedRevision, callable $lkgResolver, string $reason): int
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $control = $db->query('SELECT in_flight_revision, lease_token_hash FROM service_profile_control WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
            if ($control === false || !is_string($control['lease_token_hash'] ?? null) || !hash_equals((string) $control['lease_token_hash'], self::hashLease($lease))) {
                throw new ServiceProfileConflictException('lease-invalid');
            }
            $current = (int) ($db->query('SELECT revision FROM service_profile_current WHERE id = 1')->fetchColumn() ?: 0);
            if ($current !== $failedRevision) {
                // A newer operator revision exists; never overwrite it. Just clear the lease.
                $this->clearControl($db);
                $db->commit();

                return $current;
            }
            $fields = $lkgResolver();
            $newRevision = $current + 1;
            $old = (string) ($db->query('SELECT input_json FROM service_profile_current WHERE id = 1')->fetchColumn() ?: '');
            $this->writeCurrent($db, $newRevision, $fields, 'system');
            $this->audit($db, $newRevision, 'system', '', $old, $fields['input_json'], 'rollback', $reason);
            $this->clearControl($db);
            $db->commit();

            return $newRevision;
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    /** Root claims the desired revision before a cutover; returns the opaque lease token. */
    public function claimForReconcile(int $revision): string
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $control = $db->query('SELECT in_flight_revision FROM service_profile_control WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
            if ($control !== false && $control['in_flight_revision'] !== null) {
                throw new ServiceProfileConflictException('already-in-flight');
            }
            $token = bin2hex(random_bytes(32));
            $db->prepare('INSERT INTO service_profile_control (id, in_flight_revision, lease_token_hash, claimed_at)
                VALUES (1, :r, :h, :t)
                ON CONFLICT(id) DO UPDATE SET in_flight_revision = :r, lease_token_hash = :h, claimed_at = :t')
                ->execute([':r' => $revision, ':h' => self::hashLease($token), ':t' => gmdate('c')]);
            $db->commit();

            return $token;
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    public function finishReconcile(string $lease): void
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $control = $db->query('SELECT lease_token_hash FROM service_profile_control WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
            if ($control === false) {
                $db->commit();

                return;
            }
            if (!is_string($control['lease_token_hash'] ?? null) || !hash_equals((string) $control['lease_token_hash'], self::hashLease($lease))) {
                throw new ServiceProfileConflictException('lease-invalid');
            }
            $this->clearControl($db);
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    /** Boot recovery: force-clear a lease whose owner died (the private transition proved dead). */
    public function recoverStaleLease(): void
    {
        $db = $this->db();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $this->clearControl($db);
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    public function inFlightRevision(): ?int
    {
        try {
            $v = $this->db()->query('SELECT in_flight_revision FROM service_profile_control WHERE id = 1')->fetchColumn();
        } catch (Throwable $e) {
            return null;
        }

        return $v === false || $v === null ? null : (int) $v;
    }

    private static function hashLease(string $lease): string
    {
        return hash('sha256', 'funnypot/service-lease/v1' . "\0" . $lease);
    }

    /** @param array<string,string> $fields */
    private function writeCurrent(PDO $db, int $revision, array $fields, string $actor): void
    {
        $db->prepare('INSERT INTO service_profile_current
            (id, revision, input_json, resolved_json, preview_hash, desired_hash, catalog_hash, published_hash, created_at, actor)
            VALUES (1, :rev, :in, :res, :ph, :dh, :ch, :pubh, :ts, :actor)
            ON CONFLICT(id) DO UPDATE SET
              revision = :rev, input_json = :in, resolved_json = :res, preview_hash = :ph,
              desired_hash = :dh, catalog_hash = :ch, published_hash = :pubh, created_at = :ts, actor = :actor')
            ->execute([
                ':rev' => $revision, ':in' => $fields['input_json'], ':res' => $fields['resolved_json'],
                ':ph' => $fields['preview_hash'], ':dh' => $fields['desired_hash'], ':ch' => $fields['catalog_hash'],
                ':pubh' => $fields['published_hash'], ':ts' => gmdate('c'), ':actor' => $actor,
            ]);
    }

    private function clearControl(PDO $db): void
    {
        $db->prepare('INSERT INTO service_profile_control (id, in_flight_revision, lease_token_hash, claimed_at)
            VALUES (1, NULL, NULL, NULL)
            ON CONFLICT(id) DO UPDATE SET in_flight_revision = NULL, lease_token_hash = NULL, claimed_at = NULL')
            ->execute();
    }

    private function audit(PDO $db, int $revision, string $actor, string $sourceIp, ?string $old, ?string $new, string $result, string $reasonCode): void
    {
        $db->prepare('INSERT INTO service_profile_audit (revision, actor, source_ip, old_json, new_json, result, reason_code, created_at)
            VALUES (:rev, :actor, :ip, :old, :new, :result, :reason, :ts)')
            ->execute([
                ':rev' => $revision, ':actor' => $actor, ':ip' => $sourceIp, ':old' => $old, ':new' => $new,
                ':result' => $result, ':reason' => $reasonCode, ':ts' => gmdate('c'),
            ]);
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $db = ServiceSqlite::open($this->dbPath, 0660, 'www-data', $this->ops);
        $db->exec('CREATE TABLE IF NOT EXISTS service_profile_current (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            revision INTEGER NOT NULL,
            input_json TEXT NOT NULL,
            resolved_json TEXT NOT NULL,
            preview_hash TEXT NOT NULL,
            desired_hash TEXT NOT NULL,
            catalog_hash TEXT NOT NULL,
            published_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS service_profile_control (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            in_flight_revision INTEGER,
            lease_token_hash TEXT,
            claimed_at TEXT
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS service_profile_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            revision INTEGER NOT NULL,
            actor TEXT NOT NULL,
            source_ip TEXT NOT NULL DEFAULT "",
            old_json TEXT,
            new_json TEXT,
            result TEXT NOT NULL,
            reason_code TEXT NOT NULL DEFAULT "",
            created_at TEXT NOT NULL
        )');

        return $this->db = $db;
    }
}

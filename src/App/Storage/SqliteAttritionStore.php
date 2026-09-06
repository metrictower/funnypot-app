<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Attrition\ArtifactCandidate;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionStateCost;
use Funnypot\App\Tarpit\Attrition\AttritionStore;
use Funnypot\App\Tarpit\Attrition\FetchTransition;
use Funnypot\App\Tarpit\Attrition\GenerationState;
use Funnypot\App\Tarpit\Attrition\JobCandidate;
use Funnypot\App\Tarpit\Attrition\JobState;
use Funnypot\App\Tarpit\Attrition\ManifestCandidate;
use Funnypot\App\Tarpit\Attrition\ManifestCommit;
use Funnypot\App\Tarpit\Attrition\PollState;
use Funnypot\App\Tarpit\Attrition\PruneResult;
use PDO;
use Throwable;

/**
 * The bounded attrition state store (FP-0272 §7). Its own attrition.sqlite, opened through the shared
 * {@see Sqlite} helper and immediately overridden to a 5 ms busy_timeout with foreign keys on, so a
 * write that cannot take the lock fast fails CLOSED (the caller sheds to a 404) rather than queuing — the
 * FP-0253 no-self-DoS invariant. Every mutation is one `BEGIN IMMEDIATE` transaction: the cap check and
 * the insert see one write-locked snapshot, so counters cannot overshoot under concurrency, and there is
 * no retry, backoff, or sleep. A singleton quota row and per-journey counters are updated in the same
 * transaction as every insert/delete, so runtime cap checks read one indexed row, never a COUNT/SUM scan.
 *
 * It persists only closed 32-hex ids, closed revisions/generation indices, and integer times/counters —
 * never a raw handle, nonce, MAC, peer, target, body, or generated artifact byte.
 */
final class SqliteAttritionStore implements AttritionStore
{
    public const JOB_REVISION = 'export-manifest/v1';
    public const RENDERER_REVISION = 'attrition-export/v1';

    private ?PDO $db = null;

    /** @var callable():int */
    private $clock;

    public function __construct(
        private string $dbPath,
        private AttritionLimits $limits,
        ?callable $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /** Default sibling path next to the hit-store db, like the other per-concern stores. */
    public static function defaultPath(string $dbPath): string
    {
        return dirname($dbPath) . '/attrition.sqlite';
    }

    /** Force migration + quota reconciliation at boot; false ⇒ the composition root leaves the feature off. */
    public function ready(): bool
    {
        return $this->connect() !== null;
    }

    public function createJob(JobCandidate $c, int $now): ?JobState
    {
        $db = $this->connect();
        if ($db === null) {
            return null;
        }
        $this->relievePressure($db, AttritionStateCost::JOURNEY + AttritionStateCost::JOB, $now);
        try {
            $db->exec('BEGIN IMMEDIATE');

            $existing = $this->row($db, 'SELECT job_id, poll_count FROM attrition_jobs WHERE job_id = :id', [':id' => $c->jobId])
                ?: $this->row($db, 'SELECT job_id, poll_count FROM attrition_jobs WHERE journey_id = :j AND entry_id = :e', [':j' => $c->journeyId, ':e' => $c->entryId]);
            if ($existing !== null) {
                $db->exec('COMMIT');

                return new JobState((string) $existing['job_id'], (int) $existing['poll_count']);
            }

            $journey = $this->row($db, 'SELECT job_count FROM attrition_journeys WHERE journey_id = :id', [':id' => $c->journeyId]);
            $journeyIsNew = $journey === null;
            if (!$journeyIsNew && (int) $journey['job_count'] >= $this->limits->maxJobsPerJourney) {
                $db->exec('ROLLBACK');

                return null;
            }
            $newRows = ($journeyIsNew ? 1 : 0) + 1;
            $newBytes = ($journeyIsNew ? AttritionStateCost::JOURNEY : 0) + AttritionStateCost::JOB;
            if (!$this->hasRoom($db, $newRows, $newBytes)) {
                $db->exec('ROLLBACK');

                return null;
            }

            if ($journeyIsNew) {
                $this->exec($db, 'INSERT INTO attrition_journeys (journey_id, created_at, expires_at, job_count, generation_count, logical_bytes) VALUES (:id, :c, :e, 0, 0, :b)', [
                    ':id' => $c->journeyId, ':c' => $now, ':e' => $c->expiresAt, ':b' => AttritionStateCost::JOURNEY,
                ]);
            }
            $this->exec($db, 'INSERT INTO attrition_jobs (job_id, journey_id, entry_id, revision, created_at, expires_at, poll_count, first_manifest_id, logical_bytes) VALUES (:id, :j, :en, :rev, :c, :e, 0, :fm, :b)', [
                ':id' => $c->jobId, ':j' => $c->journeyId, ':en' => $c->entryId, ':rev' => $c->revision,
                ':c' => $now, ':e' => $c->expiresAt, ':fm' => $c->firstManifestId, ':b' => AttritionStateCost::JOB,
            ]);
            $this->exec($db, 'UPDATE attrition_journeys SET job_count = job_count + 1, logical_bytes = logical_bytes + :b WHERE journey_id = :id', [
                ':b' => AttritionStateCost::JOB, ':id' => $c->journeyId,
            ]);
            $this->addQuota($db, $newRows, $newBytes);

            $db->exec('COMMIT');

            return new JobState($c->jobId, 0);
        } catch (Throwable $e) {
            $this->rollback($db);
            $this->bumpHealth('create_fault');

            return null;
        }
    }

    public function advancePoll(string $jobId, int $now): ?PollState
    {
        $db = $this->connect();
        if ($db === null) {
            return null;
        }
        try {
            $db->exec('BEGIN IMMEDIATE');
            $row = $this->row($db, 'SELECT poll_count, expires_at FROM attrition_jobs WHERE job_id = :id', [':id' => $jobId]);
            if ($row === null || (int) $row['expires_at'] <= $now) {
                $db->exec('ROLLBACK');

                return null;
            }
            $current = (int) $row['poll_count'];
            $next = $current >= AttritionLimits::POLLS ? AttritionLimits::POLLS : $current + 1;
            if ($next !== $current) {
                $this->exec($db, 'UPDATE attrition_jobs SET poll_count = :p WHERE job_id = :id', [':p' => $next, ':id' => $jobId]);
            }
            $db->exec('COMMIT');

            return new PollState($next);
        } catch (Throwable $e) {
            $this->rollback($db);
            $this->bumpHealth('poll_fault');

            return null;
        }
    }

    public function prepareManifest(string $manifestId, int $now): ?ManifestCandidate
    {
        $db = $this->connect();
        if ($db === null) {
            return null;
        }
        try {
            // 1. A repeat fetch of an already-committed generation row.
            $gen = $this->row($db, 'SELECT job_id, generation, renderer_revision, expires_at FROM attrition_generations WHERE manifest_id = :id', [':id' => $manifestId]);
            if ($gen !== null) {
                if ((int) $gen['expires_at'] <= $now) {
                    return null;
                }

                return new ManifestCandidate((string) $gen['job_id'], (int) $gen['generation'], (string) $gen['renderer_revision'], (int) $gen['expires_at'], true);
            }
            // 2. Generation 0 — eligible only once the job reached the terminal poll.
            $job = $this->row($db, 'SELECT job_id, poll_count, expires_at FROM attrition_jobs WHERE first_manifest_id = :id', [':id' => $manifestId]);
            if ($job !== null) {
                if ((int) $job['expires_at'] <= $now || (int) $job['poll_count'] < AttritionLimits::POLLS) {
                    return null;
                }

                return new ManifestCandidate((string) $job['job_id'], 0, self::RENDERER_REVISION, (int) $job['expires_at'], false);
            }
            // 3. Generation n+1 — eligible only after the predecessor's artifact was fetched.
            $pred = $this->row($db, 'SELECT job_id, generation, renderer_revision, expires_at, fetch_count FROM attrition_generations WHERE next_manifest_id = :id', [':id' => $manifestId]);
            if ($pred !== null) {
                $next = (int) $pred['generation'] + 1;
                if ((int) $pred['expires_at'] <= $now || (int) $pred['fetch_count'] < 1 || $next >= AttritionLimits::GENERATIONS) {
                    return null;
                }

                return new ManifestCandidate((string) $pred['job_id'], $next, (string) $pred['renderer_revision'], (int) $pred['expires_at'], false);
            }

            return null;
        } catch (Throwable $e) {
            $this->bumpHealth('manifest_prepare_fault');

            return null;
        }
    }

    public function commitManifest(ManifestCommit $c, int $now): ?GenerationState
    {
        $db = $this->connect();
        if ($db === null) {
            return null;
        }
        $this->relievePressure($db, AttritionStateCost::GENERATION, $now);
        try {
            $db->exec('BEGIN IMMEDIATE');

            $existing = $this->row($db, 'SELECT generation_id FROM attrition_generations WHERE job_id = :j AND generation = :g', [':j' => $c->jobId, ':g' => $c->generation]);
            if ($existing !== null) {
                $db->exec('COMMIT');

                return new GenerationState((string) $existing['generation_id'], $c->generation);
            }

            if (!$this->recheckManifestEligible($db, $c, $now)) {
                $db->exec('ROLLBACK');

                return null;
            }

            $journey = $this->row($db, 'SELECT generation_count FROM attrition_journeys WHERE journey_id = :id', [':id' => $c->journeyId]);
            if ($journey === null || (int) $journey['generation_count'] >= $this->limits->maxArtifactsPerJourney) {
                $db->exec('ROLLBACK');

                return null;
            }
            if (!$this->hasRoom($db, 1, AttritionStateCost::GENERATION)) {
                $db->exec('ROLLBACK');

                return null;
            }

            $this->exec($db, 'INSERT INTO attrition_generations (generation_id, job_id, generation, renderer_revision, manifest_id, artifact_id, next_manifest_id, fetch_count, logical_bytes, created_at, expires_at) VALUES (:gid, :job, :g, :rev, :mid, :aid, :nid, 0, :b, :c, :e)', [
                ':gid' => $c->generationId, ':job' => $c->jobId, ':g' => $c->generation, ':rev' => $c->rendererRevision,
                ':mid' => $c->manifestId, ':aid' => $c->artifactId, ':nid' => $c->nextManifestId,
                ':b' => AttritionStateCost::GENERATION, ':c' => $now, ':e' => $c->expiresAt,
            ]);
            $this->exec($db, 'UPDATE attrition_journeys SET generation_count = generation_count + 1, logical_bytes = logical_bytes + :b WHERE journey_id = :id', [
                ':b' => AttritionStateCost::GENERATION, ':id' => $c->journeyId,
            ]);
            $this->addQuota($db, 1, AttritionStateCost::GENERATION);

            $db->exec('COMMIT');

            return new GenerationState($c->generationId, $c->generation);
        } catch (Throwable $e) {
            $this->rollback($db);
            $this->bumpHealth('manifest_commit_fault');

            return null;
        }
    }

    public function prepareArtifact(string $artifactId, int $now): ?ArtifactCandidate
    {
        $db = $this->connect();
        if ($db === null) {
            return null;
        }
        try {
            $gen = $this->row($db, 'SELECT job_id, generation, renderer_revision, expires_at FROM attrition_generations WHERE artifact_id = :id', [':id' => $artifactId]);
            if ($gen === null || (int) $gen['expires_at'] <= $now) {
                return null;
            }

            return new ArtifactCandidate((string) $gen['job_id'], (int) $gen['generation'], (string) $gen['renderer_revision'], (int) $gen['expires_at']);
        } catch (Throwable $e) {
            $this->bumpHealth('artifact_prepare_fault');

            return null;
        }
    }

    public function commitArtifactFetch(string $artifactId, int $now): ?FetchTransition
    {
        $db = $this->connect();
        if ($db === null) {
            return null;
        }
        try {
            $db->exec('BEGIN IMMEDIATE');
            $row = $this->row($db, 'SELECT fetch_count, expires_at FROM attrition_generations WHERE artifact_id = :id', [':id' => $artifactId]);
            if ($row === null || (int) $row['expires_at'] <= $now) {
                $db->exec('ROLLBACK');

                return null;
            }
            $fc = (int) $row['fetch_count'];
            if ($fc >= 2) {
                $db->exec('COMMIT');

                return new FetchTransition(false);
            }
            $this->exec($db, 'UPDATE attrition_generations SET fetch_count = :f WHERE artifact_id = :id', [':f' => $fc + 1, ':id' => $artifactId]);
            $db->exec('COMMIT');

            return new FetchTransition($fc === 0);
        } catch (Throwable $e) {
            $this->rollback($db);
            $this->bumpHealth('artifact_fetch_fault');

            return null;
        }
    }

    public function pruneExpired(int $limit, int $now): PruneResult
    {
        $db = $this->connect();
        if ($db === null) {
            return new PruneResult(0, 0);
        }
        try {
            $db->exec('BEGIN IMMEDIATE');
            $expired = $db->prepare('SELECT journey_id, logical_bytes FROM attrition_journeys WHERE expires_at <= :n ORDER BY expires_at LIMIT :l');
            $expired->bindValue(':n', $now, PDO::PARAM_INT);
            $expired->bindValue(':l', max(1, $limit), PDO::PARAM_INT);
            $expired->execute();
            $journeys = $expired->fetchAll(PDO::FETCH_ASSOC) ?: [];

            $rows = 0;
            $bytes = 0;
            $count = 0;
            foreach ($journeys as $j) {
                $jid = (string) $j['journey_id'];
                $jobAgg = $this->row($db, 'SELECT COALESCE(SUM(logical_bytes),0) b, COUNT(*) n FROM attrition_jobs WHERE journey_id = :id', [':id' => $jid]);
                $genAgg = $this->row($db, 'SELECT COALESCE(SUM(g.logical_bytes),0) b, COUNT(*) n FROM attrition_generations g JOIN attrition_jobs jb ON g.job_id = jb.job_id WHERE jb.journey_id = :id', [':id' => $jid]);
                $bytes += (int) $j['logical_bytes'] + (int) ($jobAgg['b'] ?? 0) + (int) ($genAgg['b'] ?? 0);
                $rows += 1 + (int) ($jobAgg['n'] ?? 0) + (int) ($genAgg['n'] ?? 0);
                $count++;
                $this->exec($db, 'DELETE FROM attrition_journeys WHERE journey_id = :id', [':id' => $jid]);
            }
            if ($rows > 0) {
                $this->exec($db, 'UPDATE attrition_quota SET row_count = MAX(0, row_count - :r), logical_bytes = MAX(0, logical_bytes - :b) WHERE singleton = 1', [':r' => $rows, ':b' => $bytes]);
            }
            $db->exec('COMMIT');

            return new PruneResult($count, $rows);
        } catch (Throwable $e) {
            $this->rollback($db);
            $this->bumpHealth('prune_fault');

            return new PruneResult(0, 0);
        }
    }

    public function maintain(): void
    {
        $db = $this->connect();
        if ($db === null) {
            return;
        }
        try {
            $db->exec('PRAGMA wal_checkpoint(TRUNCATE)');
            $db->exec('PRAGMA incremental_vacuum');
        } catch (Throwable $e) {
            $this->bumpHealth('maintain_fault');
        }
    }

    public function physicalBytes(): int
    {
        $total = 0;
        foreach (['', '-wal'] as $suffix) {
            $p = $this->dbPath . $suffix;
            if (is_file($p)) {
                $total += (int) @filesize($p);
            }
        }

        return $total;
    }

    // --- internals ---------------------------------------------------------------------------------

    /** True when the quota has room for the added rows/bytes; the caller holds the write lock. */
    private function hasRoom(PDO $db, int $newRows, int $newBytes): bool
    {
        $q = $this->row($db, 'SELECT row_count, logical_bytes FROM attrition_quota WHERE singleton = 1');
        $rowCount = (int) ($q['row_count'] ?? 0);
        $bytes = (int) ($q['logical_bytes'] ?? 0);

        return $rowCount + $newRows <= $this->limits->globalRows
            && $bytes + $newBytes <= $this->limits->globalStateBytes;
    }

    private function addQuota(PDO $db, int $rows, int $bytes): void
    {
        $this->exec($db, 'UPDATE attrition_quota SET row_count = row_count + :r, logical_bytes = logical_bytes + :b WHERE singleton = 1', [':r' => $rows, ':b' => $bytes]);
    }

    /** Best-effort bounded prune before a mutation, only under real quota/physical pressure. */
    private function relievePressure(PDO $db, int $newBytes, int $now): void
    {
        try {
            $q = $this->row($db, 'SELECT row_count, logical_bytes FROM attrition_quota WHERE singleton = 1');
            $rowCount = (int) ($q['row_count'] ?? 0);
            $bytes = (int) ($q['logical_bytes'] ?? 0);
            $tight = $rowCount + 2 > $this->limits->globalRows
                || $bytes + $newBytes > $this->limits->globalStateBytes
                || $this->physicalBytes() >= AttritionLimits::PHYSICAL_MAX_BYTES;
            if ($tight) {
                $this->pruneExpired(AttritionLimits::INLINE_PRUNE_ROWS, $now);
            }
        } catch (Throwable $e) {
            // opportunistic only — the authoritative cap check runs inside the mutation transaction
        }
    }

    /** Re-verify a new generation's eligibility inside the write lock (prepare was read-only). */
    private function recheckManifestEligible(PDO $db, ManifestCommit $c, int $now): bool
    {
        if ($c->generation === 0) {
            $job = $this->row($db, 'SELECT poll_count, first_manifest_id, expires_at FROM attrition_jobs WHERE job_id = :id', [':id' => $c->jobId]);

            return $job !== null
                && (int) $job['expires_at'] > $now
                && (int) $job['poll_count'] >= AttritionLimits::POLLS
                && (string) $job['first_manifest_id'] === $c->manifestId;
        }
        $pred = $this->row($db, 'SELECT generation, fetch_count, expires_at FROM attrition_generations WHERE next_manifest_id = :id', [':id' => $c->manifestId]);

        return $pred !== null
            && (int) $pred['expires_at'] > $now
            && (int) $pred['fetch_count'] >= 1
            && (int) $pred['generation'] + 1 === $c->generation;
    }

    /** @param array<string,mixed> $params @return array<string,mixed>|null */
    private function row(PDO $db, string $sql, array $params = []): ?array
    {
        $st = $db->prepare($sql);
        $st->execute($params);
        $row = $st->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : $row;
    }

    /** @param array<string,mixed> $params */
    private function exec(PDO $db, string $sql, array $params): void
    {
        $db->prepare($sql)->execute($params);
    }

    private function rollback(?PDO $db): void
    {
        if ($db === null) {
            return;
        }
        try {
            $db->exec('ROLLBACK');
        } catch (Throwable $e) {
            // no active transaction to roll back
        }
    }

    private function bumpHealth(string $key): void
    {
        try {
            $db = $this->db;
            if ($db === null) {
                return;
            }
            $db->prepare('INSERT INTO attrition_health (k, v) VALUES (:k, 1) ON CONFLICT(k) DO UPDATE SET v = v + 1')
                ->execute([':k' => $key]);
        } catch (Throwable $e) {
            // best-effort health only
        }
    }

    private function connect(): ?PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        try {
            $db = Sqlite::open($this->dbPath);
            $db->exec('PRAGMA busy_timeout=5');
            $db->exec('PRAGMA foreign_keys=ON');
            $this->migrate($db);

            return $this->db = $db;
        } catch (Throwable $e) {
            $this->db = null;

            return null;
        }
    }

    private function migrate(PDO $db): void
    {
        $db->exec('CREATE TABLE IF NOT EXISTS attrition_journeys (
            journey_id TEXT PRIMARY KEY CHECK(length(journey_id) = 32),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            job_count INTEGER NOT NULL DEFAULT 0 CHECK(job_count >= 0),
            generation_count INTEGER NOT NULL DEFAULT 0 CHECK(generation_count >= 0),
            logical_bytes INTEGER NOT NULL DEFAULT 0 CHECK(logical_bytes >= 0)
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS attrition_jobs (
            job_id TEXT PRIMARY KEY CHECK(length(job_id) = 32),
            journey_id TEXT NOT NULL,
            entry_id TEXT NOT NULL CHECK(length(entry_id) = 32),
            revision TEXT NOT NULL CHECK(revision IN (\'export-manifest/v1\')),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            poll_count INTEGER NOT NULL DEFAULT 0 CHECK(poll_count >= 0 AND poll_count <= 9),
            first_manifest_id TEXT NOT NULL UNIQUE CHECK(length(first_manifest_id) = 32),
            logical_bytes INTEGER NOT NULL DEFAULT 0 CHECK(logical_bytes >= 0),
            UNIQUE(journey_id, entry_id),
            FOREIGN KEY(journey_id) REFERENCES attrition_journeys(journey_id) ON DELETE CASCADE
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS attrition_generations (
            generation_id TEXT PRIMARY KEY CHECK(length(generation_id) = 32),
            job_id TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation >= 0 AND generation <= 2),
            renderer_revision TEXT NOT NULL CHECK(renderer_revision IN (\'attrition-export/v1\')),
            manifest_id TEXT NOT NULL UNIQUE CHECK(length(manifest_id) = 32),
            artifact_id TEXT NOT NULL UNIQUE CHECK(length(artifact_id) = 32),
            next_manifest_id TEXT UNIQUE CHECK(next_manifest_id IS NULL OR length(next_manifest_id) = 32),
            fetch_count INTEGER NOT NULL DEFAULT 0 CHECK(fetch_count >= 0 AND fetch_count <= 2),
            logical_bytes INTEGER NOT NULL DEFAULT 0 CHECK(logical_bytes >= 0),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            UNIQUE(job_id, generation),
            FOREIGN KEY(job_id) REFERENCES attrition_jobs(job_id) ON DELETE CASCADE
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS attrition_quota (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), row_count INTEGER NOT NULL, logical_bytes INTEGER NOT NULL)');
        $db->exec('CREATE TABLE IF NOT EXISTS attrition_health (k TEXT PRIMARY KEY, v INTEGER NOT NULL)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_attr_j_exp ON attrition_journeys(expires_at)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_attr_job_exp ON attrition_jobs(expires_at)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_attr_gen_exp ON attrition_generations(expires_at)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_attr_gen_next ON attrition_generations(next_manifest_id)');
        $this->reconcileQuotaIfAbsent($db);
    }

    /** Initialize the singleton quota once from the validated tables; a no-op on every later boot. */
    private function reconcileQuotaIfAbsent(PDO $db): void
    {
        if ((int) $db->query('SELECT COUNT(*) FROM attrition_quota')->fetchColumn() > 0) {
            return;
        }
        $rows = (int) $db->query('SELECT COUNT(*) FROM attrition_journeys')->fetchColumn()
            + (int) $db->query('SELECT COUNT(*) FROM attrition_jobs')->fetchColumn()
            + (int) $db->query('SELECT COUNT(*) FROM attrition_generations')->fetchColumn();
        $bytes = (int) $db->query('SELECT COALESCE(SUM(logical_bytes),0) FROM attrition_journeys')->fetchColumn()
            + (int) $db->query('SELECT COALESCE(SUM(logical_bytes),0) FROM attrition_jobs')->fetchColumn()
            + (int) $db->query('SELECT COALESCE(SUM(logical_bytes),0) FROM attrition_generations')->fetchColumn();
        $db->prepare('INSERT OR IGNORE INTO attrition_quota (singleton, row_count, logical_bytes) VALUES (1, :r, :b)')
            ->execute([':r' => $rows, ':b' => $bytes]);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use PDO;
use PDOStatement;
use Throwable;

/**
 * SQLite-canonical hit store (the single-box default, see docs/DATA-LAYER-DECISION.md).
 *
 * The SQLite file is the source of truth for every read: stats, aggregate widgets, and O(1)
 * delta/pagination by row id. WAL mode gives many concurrent readers plus one writer at a time,
 * which is the write shape the honeypot produces (short single-row inserts from php-fpm workers
 * and the protocol listeners), so a scan burst queues on the busy_timeout rather than erroring.
 *
 * An optional JSON-lines export log can be kept for operators who want a tailable file; it is not
 * canonical. On first boot against an empty database, an existing export log is imported once so
 * upgrading from the old file-canonical store loses no history.
 */
final class SqliteHitStore implements HitStore, AnalyticsStore
{
    /** FP-0249 rollup-safety clamp: `id <= COALESCE(...)` — COALESCE OUTSIDE the subquery, since the
     *  watermark row is absent until the first fold and a NULL bound would match nothing, silently
     *  no-opping every clamped delete. */
    private const WATERMARK_SQL = "COALESCE((SELECT CAST(v AS INTEGER) FROM rollup_state WHERE k = 'last_id'), 0)";

    private PDO $db;
    private string $dbPath;
    private ?PDOStatement $insertStmt = null;

    /**
     * @param string      $dbPath            path to the SQLite file (its dir is created if missing)
     * @param string|null $exportLog         optional JSON-lines file to also append to (not canonical)
     * @param int         $rollupTopK        cap on distinct values kept per (gran,bucket,dim); the
     *                                       tail folds into a single '(other)' row so a sprayed
     *                                       dimension cannot inflate rollup storage (spec §4)
     * @param int         $rollupRetainMinH  keep minute rollup buckets this many hours
     * @param int         $rollupRetainHourD keep hour rollup buckets this many days
     * @param int         $rollupRetainDayD  keep day rollup buckets this many days
     */
    public function __construct(
        string $dbPath,
        private ?string $exportLog = null,
        private int $rollupTopK = 20,
        private int $rollupRetainMinH = 48,
        private int $rollupRetainHourD = 30,
        private int $rollupRetainDayD = 365,
    ) {
        if (!extension_loaded('pdo_sqlite')) {
            throw new \RuntimeException('SqliteHitStore needs ext-pdo_sqlite');
        }
        $this->dbPath = $dbPath;
        $this->db = $this->open($dbPath);

        // First boot against an empty DB: seed it once from an existing export log so an upgrade
        // from the old file-canonical store carries its history forward.
        if ($this->exportLog !== null
            && (int) $this->db->query('SELECT COUNT(*) FROM hits')->fetchColumn() === 0
            && is_file($this->exportLog)
            && filesize($this->exportLog) > 0
        ) {
            $this->import();
        }
    }

    public function usingDb(): bool
    {
        return true;
    }

    public function append(array $entry): void
    {
        // Attacker-supplied fields carry raw bytes from the binary protocol honeypots (mysql/modbus
        // greetings, ssh pre-auth junk, telnet IAC). Store them UTF-8-safe + readable so one bad
        // byte can never blank the JSON feed or hide what was sent.
        if (isset($entry['path'])) {
            $entry['path'] = self::clean((string) $entry['path'], 400);
        }
        if (isset($entry['body'])) {
            $entry['body'] = self::clean((string) $entry['body'], 2000);
        }

        // ts is TEXT and retention compares it lexicographically, so it must always be ISO-8601.
        // Normalise an epoch int from a caller rather than let its rows sort before every date.
        if (isset($entry['ts']) && !is_string($entry['ts'])) {
            $entry['ts'] = gmdate('c', (int) $entry['ts']);
        }

        // Export + stderr first (so a row is never lost even if the canonical insert throws), then
        // the canonical DB write. Logging must never break the honeypot.
        $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
        if ($this->exportLog !== null) {
            @file_put_contents($this->exportLog, $line, FILE_APPEND | LOCK_EX);
        }
        @file_put_contents('php://stderr', $line);

        try {
            $this->insert($entry);
        } catch (Throwable $e) {
            // best-effort: the row survives in the export log / stderr and import() can backfill it.
        }
    }

    public function delta(int $cursor, array $filters = []): array
    {
        [$where, $params] = $this->where($filters);
        $max = (int) $this->db->query('SELECT COALESCE(MAX(id),0) FROM hits')->fetchColumn();
        $reset = ($cursor <= 0 || $cursor > $max);
        if ($reset) {
            $st = $this->db->prepare('SELECT * FROM hits' . ($where !== '' ? " WHERE $where" : '') . ' ORDER BY id DESC LIMIT 100');
            $st->execute($params);
            $rows = array_reverse(array_map([$this, 'mapRow'], $st->fetchAll(PDO::FETCH_ASSOC)));
        } else {
            $st = $this->db->prepare('SELECT * FROM hits WHERE id > :c' . ($where !== '' ? " AND $where" : '') . ' ORDER BY id ASC LIMIT 500');
            $st->execute([':c' => $cursor] + $params);
            $rows = array_map([$this, 'mapRow'], $st->fetchAll(PDO::FETCH_ASSOC));
        }

        return ['cursor' => $max, 'reset' => $reset, 'rows' => $rows];
    }

    public function older(int $skip, array $filters = []): array
    {
        [$where, $params] = $this->where($filters);
        $clause = $where !== '' ? " WHERE $where" : '';
        $st = $this->db->prepare("SELECT * FROM hits{$clause} ORDER BY id DESC LIMIT 100 OFFSET :o");
        foreach ($params as $k => $v) {
            $st->bindValue($k, $v);
        }
        $st->bindValue(':o', $skip, PDO::PARAM_INT);
        $st->execute();
        $rows = array_map([$this, 'mapRow'], $st->fetchAll(PDO::FETCH_ASSOC));

        $cnt = $this->db->prepare("SELECT COUNT(*) FROM hits{$clause}");
        $cnt->execute($params);
        $more = (int) $cnt->fetchColumn() > $skip + 100;

        return ['rows' => $rows, 'more' => $more];
    }

    /**
     * Build a parameterised WHERE fragment (no leading WHERE/AND) from a whitelisted filter set.
     * Only known columns are matched, and every value is bound, so a filter can never inject SQL.
     *
     * @param array<string,mixed> $f
     * @return array{0:string,1:array<string,mixed>}
     */
    private function where(array $f): array
    {
        $clauses = [];
        $params = [];
        foreach (['method', 'event', 'cc', 'severity', 'tool'] as $col) {   // exact match
            if (isset($f[$col]) && $f[$col] !== '') {
                $clauses[] = "$col = :$col";
                $params[":$col"] = (string) $f[$col];
            }
        }
        if (isset($f['ip']) && $f['ip'] !== '') {
            $clauses[] = 'ip LIKE :ip';
            $params[':ip'] = '%' . $f['ip'] . '%';
        }
        if (isset($f['q']) && $f['q'] !== '') {                     // free text over path + body + ua + tool
            $clauses[] = '(path LIKE :q OR body LIKE :q OR ua LIKE :q OR tool LIKE :q)';
            $params[':q'] = '%' . $f['q'] . '%';
        }
        if (!empty($f['matched'])) {
            $clauses[] = 'matched = 1';
        }
        if (!empty($f['served'])) {
            $clauses[] = 'served = 1';
        }
        if (!empty($f['known'])) {
            $clauses[] = 'known_attacker = 1';
        }
        if (!empty($f['recording']) || !empty($f['has_recording'])) {
            $clauses[] = "(recording IS NOT NULL AND recording <> '')";
        }
        // Time-series drill-down (FP-0243b): brushing a range on the analytics series adds a ts
        // window. `ts` is ISO-8601 TEXT and compares lexicographically (see append()), so an
        // ISO-8601 bound orders correctly. Both bounds are BOUND, never interpolated — no injection.
        if (isset($f['ts_from']) && $f['ts_from'] !== '') {
            $clauses[] = 'ts >= :ts_from';
            $params[':ts_from'] = (string) $f['ts_from'];
        }
        if (isset($f['ts_to']) && $f['ts_to'] !== '') {
            $clauses[] = 'ts <= :ts_to';
            $params[':ts_to'] = (string) $f['ts_to'];
        }

        return [implode(' AND ', $clauses), $params];
    }

    public function stats(): array
    {
        $r = $this->db->query(
            "SELECT COUNT(*) total, COALESCE(SUM(matched),0) detections, COALESCE(SUM(served),0) served,
                    COUNT(DISTINCT ip) ips, COALESCE(SUM(CASE WHEN body<>'' THEN 1 ELSE 0 END),0) harvested
             FROM hits"
        )->fetch(PDO::FETCH_ASSOC) ?: [];

        return array_map('intval', [
            'total' => $r['total'] ?? 0, 'detections' => $r['detections'] ?? 0,
            'served' => $r['served'] ?? 0, 'ips' => $r['ips'] ?? 0, 'harvested' => $r['harvested'] ?? 0,
        ]);
    }

    public function widgets(): array
    {
        $rows = fn (string $sql): array => $this->db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        try {
            $templates = $rows(
                "SELECT je.value t, COUNT(*) n FROM hits, json_each(hits.templates) je
                 WHERE hits.matched=1 GROUP BY je.value ORDER BY n DESC LIMIT 12"
            );
        } catch (Throwable $e) {
            $templates = []; // SQLite built without JSON1
        }

        return [
            'talkers' => $rows("SELECT ip, COUNT(*) n, MAX(cc) cc FROM hits WHERE ip<>'' GROUP BY ip ORDER BY n DESC LIMIT 10"),
            'countries' => $rows("SELECT cc, COUNT(*) n FROM hits WHERE cc<>'' GROUP BY cc ORDER BY n DESC LIMIT 12"),
            'templates' => $templates,
            'histogram' => array_reverse($rows("SELECT substr(ts,1,13) h, COUNT(*) n FROM hits WHERE ts<>'' GROUP BY h ORDER BY h DESC LIMIT 24")),
        ];
    }

    public function prune(int $keep): void
    {
        $st = $this->db->prepare('DELETE FROM hits WHERE id <= (SELECT COALESCE(MAX(id),0) FROM hits) - :k');
        $st->execute([':k' => $keep]);
        if ($this->exportLog !== null && is_file($this->exportLog)) {
            $lines = @file($this->exportLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            $lines = array_slice($lines, -$keep);
            @file_put_contents($this->exportLog, $lines === [] ? '' : implode("\n", $lines) . "\n", LOCK_EX);
        }
    }

    public function clear(): void
    {
        $this->db->exec('DELETE FROM hits');
        if ($this->exportLog !== null) {
            @file_put_contents($this->exportLog, '', LOCK_EX);
        }
    }

    public function import(): int
    {
        if ($this->exportLog === null || !is_file($this->exportLog)) {
            return 0;
        }
        $fh = fopen($this->exportLog, 'rb');
        if ($fh === false) {
            return 0;
        }
        $this->db->exec('DELETE FROM hits');
        $n = 0;
        $this->db->beginTransaction();
        while (($line = fgets($fh)) !== false) {
            $row = json_decode(trim($line), true);
            if (is_array($row)) {
                $this->insert($row);
                $n++;
            }
        }
        $this->db->commit();
        fclose($fh);

        return $n;
    }

    /**
     * Delete hits older than $days days (ISO-8601 UTC timestamps sort lexicographically). Rows removed.
     *
     * $clampToRollup (FP-0249): when true, never deletes a row the rollup fold hasn't reached yet — the
     * `id <= last_id` bound is evaluated INSIDE the DELETE, atomic with it, so it cannot race
     * {@see foldRollups()}'s watermark advance (SQLite's single-writer lock serializes the two). Must be
     * opt-in per call: when rollups are disabled the watermark never advances, so an unconditional clamp
     * would make retention a permanent no-op (unbounded disk — the exact invariant this guards against).
     * Age pressure alone never overrides the clamp; only retainBytes()'s emergency size-cap path may.
     */
    public function retainDays(int $days, bool $clampToRollup = false): int
    {
        if ($days <= 0) {
            return 0;
        }
        $cutoff = gmdate('c', time() - $days * 86400);
        $sql = "DELETE FROM hits WHERE ts <> '' AND ts < :c";
        if ($clampToRollup) {
            $sql .= ' AND id <= ' . self::WATERMARK_SQL;
        }
        $st = $this->db->prepare($sql);
        $st->execute([':c' => $cutoff]);
        $n = $st->rowCount();
        if ($n > 0) {
            $this->db->exec('PRAGMA incremental_vacuum');
        }

        return $n;
    }

    /**
     * Cap the database on disk: checkpoint the wal, then delete the oldest rows in chunks (reclaiming
     * pages as we go) until the wal-inclusive size is under $maxBytes, or nothing is left. Rows removed.
     *
     * $clampToRollup: see {@see retainDays()}. Here, bounded disk outranks rollup completeness: if the
     * clamped delete affects 0 rows while the store is STILL over cap, every remaining row sits above
     * the watermark (the rollup worker is dead/slow during a scan burst) — fall through to an unclamped
     * chunk delete so the cap is still enforced, and count the sacrificed (never-folded) rows into the
     * persistent `rollup_state['rollup_lost']` counter so the undercount is visible, not silent.
     */
    public function retainBytes(int $maxBytes, bool $clampToRollup = false): int
    {
        if ($maxBytes <= 0) {
            return 0;
        }
        $this->checkpointWal();
        if ($this->sizeBytes() <= $maxBytes) {
            return 0;
        }

        $removed = 0;
        while (true) {
            $this->checkpointWal();
            if ($this->sizeBytes() <= $maxBytes) {
                break;
            }
            // Over-delete guard: a long reader can pin the wal so TRUNCATE can't run. If the MAIN file
            // alone is already under cap, further deletes would only grow the (un-truncatable) wal —
            // stop and let a later pass (once the reader is gone) finish the reclaim.
            if ($this->mainSizeBytes() <= $maxBytes) {
                fwrite(STDERR, "retention: hits wal pinned by a reader, stopping under cap on main file alone\n");
                break;
            }
            $affected = (int) $this->db->exec(
                'DELETE FROM hits WHERE id IN (SELECT id FROM hits'
                . ($clampToRollup ? ' WHERE id <= ' . self::WATERMARK_SQL : '')
                . ' ORDER BY id ASC LIMIT 2000)'
            );
            if ($affected === 0) {
                if (!$clampToRollup) {
                    break; // table drained; the floor is an empty db, not an under-cap file
                }
                // Emergency path (see docblock): every remaining oldest row is unfolded. Sacrifice a
                // chunk unclamped so the size cap is still enforced.
                $sacrificed = (int) $this->db->exec('DELETE FROM hits WHERE id IN (SELECT id FROM hits ORDER BY id ASC LIMIT 2000)');
                if ($sacrificed === 0) {
                    break; // table fully drained
                }
                $this->addRollupLost($sacrificed);
                fwrite(STDERR, sprintf("retention: size cap forced %d unfolded hit(s) past the rollup watermark\n", $sacrificed));
                $removed += $sacrificed;
                $this->db->exec('PRAGMA incremental_vacuum');
                continue;
            }
            $removed += $affected;
            $this->db->exec('PRAGMA incremental_vacuum');
        }

        return $removed;
    }

    /** Add $n to the persistent `rollup_state['rollup_lost']` counter. A single UPSERT statement (not
     *  read-modify-write) so two concurrent retention passes (operator CLI + the timer loop) can never
     *  lose an increment to a race — SQLite's writer lock serializes the two UPSERTs. */
    private function addRollupLost(int $n): void
    {
        if ($n <= 0) {
            return;
        }
        $this->db->prepare(
            "INSERT INTO rollup_state (k, v) VALUES ('rollup_lost', CAST(:n AS TEXT))
             ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(v AS INTEGER) + CAST(excluded.v AS INTEGER) AS TEXT)"
        )->execute([':n' => $n]);
    }

    /** On-disk footprint in bytes: the main file (page_count * page_size) PLUS the `-wal` sidecar — WAL
     *  writes accumulate there between checkpoints, so main-file-only size understates true disk use
     *  under a busy long-reader, e.g. the dashboard's live-feed poll (`-shm` is a fixed-size mmap index,
     *  not counted). */
    public function sizeBytes(): int
    {
        return $this->mainSizeBytes() + $this->walBytes();
    }

    private function mainSizeBytes(): int
    {
        $pageCount = (int) $this->db->query('PRAGMA page_count')->fetchColumn();
        $pageSize = (int) $this->db->query('PRAGMA page_size')->fetchColumn();

        return $pageCount * $pageSize;
    }

    private function walBytes(): int
    {
        clearstatcache(true, $this->dbPath . '-wal');

        return (int) @filesize($this->dbPath . '-wal');
    }

    /** Fold the wal back into the main file so deletes actually reclaim disk. Best-effort: a concurrent
     *  reader can make this report busy — fine, the next retention pass retries. */
    public function checkpointWal(): void
    {
        try {
            $this->db->exec('PRAGMA wal_checkpoint(TRUNCATE)');
        } catch (Throwable $e) {
            // best-effort, see docblock
        }
    }

    public function probeVelocity(string $ip): array
    {
        if ($ip === '' || $ip === 'unknown') {
            return ['recent' => 0, 'extended' => 0];
        }
        $now = time();
        // Only genuine fall-throughs count as probing: a row that was served (engine fake, decoy
        // archive, LLM fake, panel) or matched (an attack payload — reported, not shed) is engagement
        // with our own bait, and a human following decoy links must never accrue velocity from it.
        $st = $this->db->prepare(
            'SELECT COUNT(DISTINCT CASE WHEN ts >= :c60 THEN path END) recent, COUNT(DISTINCT path) extended
             FROM hits WHERE ip = :ip AND ts >= :c600 AND served = 0 AND matched = 0'
        );
        $st->execute([':ip' => $ip, ':c60' => gmdate('c', $now - 60), ':c600' => gmdate('c', $now - 600)]);
        $row = $st->fetch(PDO::FETCH_ASSOC) ?: [];

        return ['recent' => (int) ($row['recent'] ?? 0), 'extended' => (int) ($row['extended'] ?? 0)];
    }

    public function recentEventCount(string $ip, string $event, int $sinceSeconds): int
    {
        if ($ip === '' || $ip === 'unknown') {
            return 0;
        }
        $st = $this->db->prepare('SELECT COUNT(*) FROM hits WHERE ip = :ip AND event = :ev AND ts >= :since');
        $st->execute([':ip' => $ip, ':ev' => $event, ':since' => gmdate('c', time() - max(0, $sinceSeconds))]);

        return (int) $st->fetchColumn();
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
        if ($ip === '' || $ip === 'unknown') {
            return;
        }
        $this->db->prepare('INSERT OR REPLACE INTO bulk_scan (ip, until) VALUES (:ip, :until)')
            ->execute([':ip' => $ip, ':until' => gmdate('c', time() + max(1, $hours) * 3600)]);
    }

    public function isBulkFlagged(string $ip): bool
    {
        if ($ip === '' || $ip === 'unknown') {
            return false;
        }
        $st = $this->db->prepare('SELECT until FROM bulk_scan WHERE ip = :ip');
        $st->execute([':ip' => $ip]);
        $until = $st->fetchColumn();

        return $until !== false && (strtotime((string) $until) ?: 0) > time();
    }

    // --- AnalyticsStore: the rollup worker + O(buckets) read API (FP-0243) ---

    /** High-cardinality dims topN() serves from the raw table. The value maps to a fixed column
     *  name here and NOWHERE else, so the column can never be driven by caller input. */
    private const TOPN_COLS = ['ip' => 'ip', 'asn' => 'asn', 'path' => 'path', 'tool' => 'tool', 'cc' => 'cc'];

    public function foldRollups(int $batch): int
    {
        $batch = max(1, $batch);

        // Take the write lock FIRST (BEGIN IMMEDIATE), THEN read the watermark and the batch inside
        // that transaction. Otherwise two folds running at once (an operator running
        // `php demo/rollup.php` by hand while the entrypoint timer loop also runs) would both read
        // the same `last_id`, aggregate the same rows, and both commit `n=n+delta` → a permanent
        // double count. With the lock held up front a second concurrent fold serializes behind this
        // one (or errors past busy_timeout and the worker retries next tick) and then reads the
        // advanced watermark, so it sees no rows to re-fold. Managed by hand because PDO's
        // inTransaction() only tracks beginTransaction(), not a manual BEGIN.
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $result = $this->foldLocked($batch);
            $this->db->exec('COMMIT');

            return $result;
        } catch (Throwable $e) {
            try {
                $this->db->exec('ROLLBACK');
            } catch (Throwable $ignore) {
                // no active transaction to roll back (e.g. the BEGIN itself failed) — nothing to undo
            }
            throw $e;
        }
    }

    /**
     * The body of one fold pass, run with the write lock already held by {@see foldRollups()}. Reads
     * the watermark + batch, aggregates, UPSERTs, prunes and advances the watermark — but does NOT
     * begin/commit; the caller owns the transaction so the watermark read and the writes are one
     * atomic, serialized unit. Returns the number of raw hit rows folded (0 when drained).
     */
    private function foldLocked(int $batch): int
    {
        $last = (int) ($this->stateGet('last_id') ?? 0);

        $sel = $this->db->prepare(
            'SELECT id, ts, method, event, severity, matched, served, known_attacker, cc, tool
             FROM hits WHERE id > :last ORDER BY id ASC LIMIT :lim'
        );
        $sel->bindValue(':last', $last, PDO::PARAM_INT);
        $sel->bindValue(':lim', $batch, PDO::PARAM_INT);
        $sel->execute();
        $rows = $sel->fetchAll(PDO::FETCH_ASSOC);
        if ($rows === []) {
            return 0;
        }

        // Aggregate the batch in PHP into per-(gran,bucket,dim,val) deltas. Every event contributes
        // to its minute, hour AND day bucket for each dim — the coarser granularities are folded
        // straight from this batch, never by re-reading (retention-prunable) minute rows.
        // $agg[$gran][$bucket][$dim][$val] = ['n'=>,'matched'=>,'served'=>]
        $agg = ['m' => [], 'h' => [], 'd' => []];
        $maxId = $last;
        foreach ($rows as $r) {
            $maxId = max($maxId, (int) $r['id']);
            $epoch = strtotime((string) ($r['ts'] ?? ''));
            if ($epoch === false) {
                continue; // no usable timestamp: cannot bucket it (the watermark still moves past it)
            }
            $matched = !empty($r['matched']) ? 1 : 0;
            $served = !empty($r['served']) ? 1 : 0;
            // Mutually-exclusive status so SUM(n) over dim='status' equals COUNT(*): a known
            // attacker beats a detection beats a served decoy beats a plain hit. The additive
            // matched/served flag totals live in every row's matched/served columns besides this.
            $status = !empty($r['known_attacker']) ? 'known_attacker'
                : ($matched ? 'matched' : ($served ? 'served' : 'none'));
            $dims = [
                'total' => '',
                'protocol' => (string) ($r['method'] ?? ''),
                'event' => (string) ($r['event'] ?? ''),
                'severity' => (string) ($r['severity'] ?? ''),
                'status' => $status,
                'country' => (string) ($r['cc'] ?? ''),
                'tool' => (string) ($r['tool'] ?? ''),
            ];
            $buckets = [
                'm' => $epoch - ($epoch % 60),
                'h' => $epoch - ($epoch % 3600),
                'd' => $epoch - ($epoch % 86400),
            ];
            foreach ($dims as $dim => $val) {
                // 'total' and 'status' are always present; a column-backed dim with an empty value
                // is not a bucket (mirrors the widgets() WHERE cc<>'' style).
                if ($val === '' && $dim !== 'total') {
                    continue;
                }
                foreach ($buckets as $g => $b) {
                    if (!isset($agg[$g][$b][$dim][$val])) {
                        $agg[$g][$b][$dim][$val] = ['n' => 0, 'matched' => 0, 'served' => 0];
                    }
                    $agg[$g][$b][$dim][$val]['n']++;
                    $agg[$g][$b][$dim][$val]['matched'] += $matched;
                    $agg[$g][$b][$dim][$val]['served'] += $served;
                }
            }
        }

        // All UPSERTs + prune + watermark advance happen inside the caller's single transaction, so
        // a crash before commit rolls the whole pass back and the next pass reprocesses with no
        // double count. The watermark was read above under the same lock, so a concurrent fold
        // cannot have read a stale value.
        $up = $this->db->prepare(
            'INSERT INTO rollup (gran, bucket, dim, val, n, matched, served)
             VALUES (:g, :b, :d, :v, :n, :m, :s)
             ON CONFLICT(gran, bucket, dim, val) DO UPDATE SET
                n       = n + excluded.n,
                matched = matched + excluded.matched,
                served  = served + excluded.served'
        );
        foreach ($agg as $g => $byBucket) {
            foreach ($byBucket as $b => $byDim) {
                foreach ($byDim as $dim => $byVal) {
                    foreach ($this->capTopK($byVal) as $val => $c) {
                        $up->execute([
                            ':g' => $g, ':b' => $b, ':d' => $dim, ':v' => $val,
                            ':n' => $c['n'], ':m' => $c['matched'], ':s' => $c['served'],
                        ]);
                    }
                }
            }
        }
        $this->pruneRollups();
        $this->stateSet('last_id', (string) $maxId);

        return count($rows);
    }

    /**
     * NOTE on capped dimensions: the top-K cap (see {@see capTopK()}) is applied per fold-batch, so
     * for a high-cardinality dim whose values change across batches the stored rows per
     * (gran,bucket,dim) can exceed K+1 cumulatively and a per-value count here is APPROXIMATE (a
     * value can be split between its own row and '(other)'). `dim='total'` and the SUM of all rows
     * stay exact, and storage stays bounded. All rollup dims today are app/classifier-bounded
     * (protocol/event/severity/status/country, and `tool` from the fixed FP-0213 attributor), so no
     * attacker input reaches the cap in practice; a full per-cumulative compaction pass is deferred
     * as YAGNI.
     */
    public function breakdown(string $dim, int $sinceEpoch, string $gran = 'h'): array
    {
        $st = $this->db->prepare(
            'SELECT val, SUM(n) n, SUM(matched) matched, SUM(served) served
             FROM rollup WHERE dim = :d AND gran = :g AND bucket >= :b
             GROUP BY val ORDER BY n DESC, val ASC'
        );
        $st->execute([':d' => $dim, ':g' => $this->normGran($gran), ':b' => $sinceEpoch]);

        return array_map(static fn (array $r): array => [
            'val' => (string) $r['val'],
            'n' => (int) $r['n'],
            'matched' => (int) $r['matched'],
            'served' => (int) $r['served'],
        ], $st->fetchAll(PDO::FETCH_ASSOC));
    }

    public function series(string $dim, array $vals, int $sinceEpoch, string $gran = 'm'): array
    {
        $vals = array_values(array_unique(array_map('strval', $vals)));
        if ($vals === []) {
            return [];
        }
        $ph = [];
        $params = [':d' => $dim, ':g' => $this->normGran($gran), ':b' => $sinceEpoch];
        foreach ($vals as $i => $v) {
            $ph[] = ":v$i";
            $params[":v$i"] = $v;
        }
        $st = $this->db->prepare(
            'SELECT bucket, val, SUM(n) n FROM rollup
             WHERE dim = :d AND gran = :g AND bucket >= :b AND val IN (' . implode(',', $ph) . ')
             GROUP BY bucket, val ORDER BY bucket ASC'
        );
        $st->execute($params);

        $out = array_fill_keys($vals, []);
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $out[(string) $r['val']][] = ['bucket' => (int) $r['bucket'], 'n' => (int) $r['n']];
        }

        return $out;
    }

    public function topN(string $dim, int $limit, int $sinceEpoch): array
    {
        $col = self::TOPN_COLS[$dim] ?? null;
        if ($col === null) {
            return []; // not a whitelisted high-cardinality dimension
        }
        // $col is a whitelisted literal, never caller input; $since/$limit are bound. No injection.
        $st = $this->db->prepare(
            "SELECT $col val, COUNT(*) n FROM hits
             WHERE $col <> '' AND ts >= :since GROUP BY $col ORDER BY n DESC LIMIT :lim"
        );
        $st->bindValue(':since', gmdate('c', $sinceEpoch));
        $st->bindValue(':lim', max(1, $limit), PDO::PARAM_INT);
        $st->execute();

        return array_map(static fn (array $r): array => [
            'val' => (string) $r['val'], 'n' => (int) $r['n'],
        ], $st->fetchAll(PDO::FETCH_ASSOC));
    }

    public function ataglance(int $windowS): array
    {
        $windowS = max(1, $windowS);
        $now = time();
        $sinceEpoch = $now - $windowS;
        $sinceTs = gmdate('c', $sinceEpoch);

        // Event count + rate over the window from the minute rollups (dim='total').
        $st = $this->db->prepare(
            "SELECT COALESCE(SUM(n),0) n FROM rollup WHERE dim = 'total' AND gran = 'm' AND bucket >= :b"
        );
        $st->execute([':b' => $sinceEpoch - ($sinceEpoch % 60)]);
        $events = (int) $st->fetchColumn();

        // Unique IPs + new-vs-returning are raw and windowed: a union of per-bucket IP sets is not
        // a sum, so these cannot be read off the rollups. Retention-bounded, analytics-only.
        $u = $this->db->prepare("SELECT COUNT(DISTINCT ip) FROM hits WHERE ip <> '' AND ts >= :s");
        $u->execute([':s' => $sinceTs]);
        $unique = (int) $u->fetchColumn();

        $ret = $this->db->prepare(
            "SELECT COUNT(DISTINCT h.ip) FROM hits h
             WHERE h.ip <> '' AND h.ts >= :s
               AND EXISTS (SELECT 1 FROM hits p WHERE p.ip = h.ip AND p.ts < :s2)"
        );
        $ret->execute([':s' => $sinceTs, ':s2' => $sinceTs]);
        $returning = (int) $ret->fetchColumn();

        return [
            'window_s' => $windowS,
            'events' => $events,
            'rate' => round($events / $windowS, 4),
            'unique_ips' => $unique,
            'new' => max(0, $unique - $returning),
            'returning' => $returning,
        ];
    }

    /**
     * Bound one (gran,bucket,dim) group to the top-K values by count, folding the rest into a
     * single '(other)' row (spec §4 cardinality guard). A group already within K is returned as-is,
     * so bounded dims (protocol/status/severity) are untouched. Total n across the group is
     * preserved — the tail is summed, never dropped — so a sprayed dimension cannot both inflate
     * storage and skew the totals.
     *
     * APPROXIMATION (per-batch): the cap is applied to THIS fold-batch's deltas, not to the
     * cumulative stored row. So if the top-K set for a (gran,bucket,dim) differs across the batches
     * that touch it, a value promoted in one batch and demoted in another ends up split between its
     * own row and '(other)', the stored distinct-row count for that group can drift above K+1 over
     * many folds, and a per-value {@see breakdown()} count for a capped dim is therefore
     * approximate. What stays exact regardless: `dim='total'`, the SUM of n across the group, and
     * the matched/served counters — and storage stays bounded per batch-touch. All current rollup
     * dims are app/classifier-bounded (well under K), so this only bites a hypothetical future
     * high-cardinality dim, never attacker input today; a per-cumulative compaction pass is deferred
     * as YAGNI.
     *
     * @param array<string,array{n:int,matched:int,served:int}> $byVal
     * @return array<string,array{n:int,matched:int,served:int}>
     */
    private function capTopK(array $byVal): array
    {
        if (count($byVal) <= $this->rollupTopK) {
            return $byVal;
        }
        uasort($byVal, static fn (array $a, array $b): int => $b['n'] <=> $a['n']);
        $kept = array_slice($byVal, 0, $this->rollupTopK, true);
        $other = $kept['(other)'] ?? ['n' => 0, 'matched' => 0, 'served' => 0];
        foreach (array_slice($byVal, $this->rollupTopK, null, true) as $c) {
            $other['n'] += $c['n'];
            $other['matched'] += $c['matched'];
            $other['served'] += $c['served'];
        }
        $kept['(other)'] = $other;

        return $kept;
    }

    private function pruneRollups(): void
    {
        $now = time();
        $cut = [
            'm' => $now - $this->rollupRetainMinH * 3600,
            'h' => $now - $this->rollupRetainHourD * 86400,
            'd' => $now - $this->rollupRetainDayD * 86400,
        ];
        $del = $this->db->prepare('DELETE FROM rollup WHERE gran = :g AND bucket < :c');
        foreach ($cut as $g => $c) {
            $del->execute([':g' => $g, ':c' => $c]);
        }
    }

    private function normGran(string $gran): string
    {
        return in_array($gran, ['m', 'h', 'd'], true) ? $gran : 'm';
    }

    private function stateGet(string $k): ?string
    {
        $st = $this->db->prepare('SELECT v FROM rollup_state WHERE k = :k');
        $st->execute([':k' => $k]);
        $v = $st->fetchColumn();

        return $v === false ? null : (string) $v;
    }

    private function stateSet(string $k, string $v): void
    {
        $this->db->prepare('INSERT INTO rollup_state (k, v) VALUES (:k, :v)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v')->execute([':k' => $k, ':v' => $v]);
    }

    // --- SQLite plumbing ---

    private function open(string $path): PDO
    {
        // Shared open/pragma seam (WAL, busy_timeout, synchronous=NORMAL, auto_vacuum=INCREMENTAL,
        // dir mkdir, chmod 0666). Schema-agnostic — this store creates its own tables below.
        $db = Sqlite::open($path);
        $db->exec(
            'CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, ip TEXT, method TEXT, path TEXT,
                matched INTEGER DEFAULT 0, severity TEXT, served INTEGER DEFAULT 0,
                templates TEXT, body TEXT, event TEXT,
                log4shell INTEGER DEFAULT 0, honeytoken TEXT,
                cc TEXT, city TEXT, lat REAL, lon REAL, asn TEXT,
                known_attacker INTEGER DEFAULT 0,
                recording TEXT,
                ua TEXT,
                tool TEXT
            )'
        );
        // Add columns introduced after a db was first created (idempotent migration for old files).
        $cols = $db->query('PRAGMA table_info(hits)')->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('known_attacker', $cols, true)) {
            $db->exec('ALTER TABLE hits ADD COLUMN known_attacker INTEGER DEFAULT 0');
        }
        if (!in_array('recording', $cols, true)) {
            $db->exec('ALTER TABLE hits ADD COLUMN recording TEXT');
        }
        if (!in_array('ua', $cols, true)) {
            $db->exec('ALTER TABLE hits ADD COLUMN ua TEXT');
        }
        if (!in_array('tool', $cols, true)) {
            $db->exec('ALTER TABLE hits ADD COLUMN tool TEXT');
        }
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ip ON hits(ip)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_known ON hits(known_attacker)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ip_ts ON hits(ip, ts)');   // covers the LLM-gate velocity query
        // Persistent bulk-scan pin: an IP that trips the velocity gate stays pinned to plain-404 for a
        // cooldown even after it goes quiet, so it cannot burst then slow-probe for fakes.
        $db->exec('CREATE TABLE IF NOT EXISTS bulk_scan (ip TEXT PRIMARY KEY, until TEXT NOT NULL)');

        // Aggregate analytics rollups (FP-0243, spec §5.1). Derived from `hits`, so co-located in
        // this same file to keep the worker's read+write in one transaction. A background worker
        // (demo/rollup.php) folds `hits` into these on a timer; the analytics reads are O(buckets),
        // flat in total event volume, instead of full-table GROUP BYs on every dashboard tick.
        //   gran    'm' minute | 'h' hour | 'd' day
        //   bucket  unix epoch (UTC) of the bucket start, floored to gran
        //   dim     'total'|'protocol'|'event'|'severity'|'status'|'country'|'tool'
        //   val     e.g. 'SIP','sipvicious','critical','' (total) or '(other)' (capped tail)
        // Bounded size: #gran × #dim × top-K values × #retained buckets — tens of thousands of rows,
        // independent of how many events are behind them.
        $db->exec(
            'CREATE TABLE IF NOT EXISTS rollup (
                gran    TEXT    NOT NULL,
                bucket  INTEGER NOT NULL,
                dim     TEXT    NOT NULL,
                val     TEXT    NOT NULL,
                n       INTEGER NOT NULL DEFAULT 0,
                matched INTEGER NOT NULL DEFAULT 0,
                served  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (gran, bucket, dim, val)
            ) WITHOUT ROWID'
        );
        $db->exec('CREATE INDEX IF NOT EXISTS idx_rollup_read ON rollup(dim, gran, bucket)');
        // rollup_state['last_id'] = highest hits.id folded into rollup (the exactly-once watermark).
        $db->exec('CREATE TABLE IF NOT EXISTS rollup_state (k TEXT PRIMARY KEY, v TEXT NOT NULL)');

        // One-time conversion of a legacy db created before incremental auto-vacuum so size-based
        // retention can reclaim disk on it too. Cheap and self-limiting: once converted, auto_vacuum
        // reads back as 2 and this is skipped on every later boot.
        if ((int) $db->query('PRAGMA auto_vacuum')->fetchColumn() !== 2) {
            $db->exec('PRAGMA auto_vacuum=INCREMENTAL');
            $db->exec('VACUUM');
        }

        return $db;
    }

    /** @param array<string,mixed> $e */
    private function insert(array $e): void
    {
        if ($this->insertStmt === null) {
            $this->insertStmt = $this->db->prepare(
                'INSERT INTO hits (ts,ip,method,path,matched,severity,served,templates,body,event,log4shell,honeytoken,cc,city,lat,lon,asn,known_attacker,recording,ua,tool)
                 VALUES (:ts,:ip,:method,:path,:matched,:severity,:served,:templates,:body,:event,:log4shell,:honeytoken,:cc,:city,:lat,:lon,:asn,:known_attacker,:recording,:ua,:tool)'
            );
        }
        $st = $this->insertStmt;
        $geo = $e['geo'] ?? [];
        $ua = (string) ($e['ua'] ?? ($e['userAgent'] ?? ''));
        $tool = (string) ($e['tool'] ?? '');
        $st->execute([
            ':ts' => (string) ($e['ts'] ?? ''),
            ':ip' => (string) ($e['ip'] ?? ''),
            ':method' => (string) ($e['method'] ?? ''),
            ':path' => (string) ($e['path'] ?? ''),
            ':matched' => !empty($e['matched']) ? 1 : 0,
            ':severity' => (string) ($e['severity'] ?? ''),
            ':served' => !empty($e['served']) ? 1 : 0,
            ':templates' => json_encode(array_values((array) ($e['templates'] ?? [])), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
            ':body' => (string) ($e['body'] ?? ''),
            ':event' => (string) ($e['event'] ?? ''),
            ':log4shell' => !empty($e['log4shell']) ? 1 : 0,
            ':honeytoken' => (string) ($e['honeytoken'] ?? ''),
            ':cc' => (string) ($geo['cc'] ?? ''),
            ':city' => (string) ($geo['city'] ?? ''),
            ':lat' => isset($geo['lat']) ? (float) $geo['lat'] : null,
            ':lon' => isset($geo['lon']) ? (float) $geo['lon'] : null,
            ':asn' => (string) ($geo['asn'] ?? ''),
            ':known_attacker' => !empty($e['known_attacker']) ? 1 : 0,
            ':recording' => (string) ($e['recording'] ?? ''),
            ':ua' => self::clean($ua, 250),
            ':tool' => self::clean($tool, 64),
        ]);
    }

    /** @return array<int,array<string,mixed>> */
    private function dbRows(string $sql): array
    {
        return array_map([$this, 'mapRow'], $this->db->query($sql)->fetchAll(PDO::FETCH_ASSOC));
    }

    /**
     * Shape one DB row for the feed. Kept byte-identical to the old store so the dashboard JS is
     * unchanged when the front controller is swapped onto this store.
     *
     * @param array<string,mixed> $r
     * @return array<string,mixed>
     */
    private function mapRow(array $r): array
    {
        return [
            'ts' => (string) ($r['ts'] ?? ''),
            'ip' => (string) ($r['ip'] ?? ''),
            'method' => (string) ($r['method'] ?? ''),
            'path' => (string) ($r['path'] ?? ''),
            'matched' => !empty($r['matched']),
            'severity' => (string) ($r['severity'] ?? ''),
            'served' => !empty($r['served']),
            'templates' => array_slice((array) json_decode((string) ($r['templates'] ?? '[]'), true), 0, 6),
            'body' => (string) ($r['body'] ?? ''),
            'event' => (string) ($r['event'] ?? ''),
            'cc' => (string) ($r['cc'] ?? ''),
            'lat' => $r['lat'] !== null ? (float) $r['lat'] : null,
            'lon' => $r['lon'] !== null ? (float) $r['lon'] : null,
            'known_attacker' => !empty($r['known_attacker']),
            'recording' => (string) ($r['recording'] ?? ''),
            'ua' => (string) ($r['ua'] ?? ''),
            'tool' => (string) ($r['tool'] ?? ''),
        ];
    }

    /**
     * Make an attacker byte string safe to store + render: keep printable ASCII, escape every other
     * byte (control + high/binary) as \xNN. Always valid UTF-8, so it can neither blank a
     * json_encode nor smuggle terminal-control bytes into the dashboard.
     */
    private static function clean(string $s, int $max): string
    {
        if (strlen($s) > $max) {
            $s = substr($s, 0, $max);
        }

        return (string) preg_replace_callback(
            '/[^\x20-\x7e]/',
            static fn (array $m): string => sprintf('\\x%02x', ord($m[0])),
            $s
        );
    }
}

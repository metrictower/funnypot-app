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
final class SqliteHitStore implements HitStore
{
    private PDO $db;
    private ?PDOStatement $insertStmt = null;

    /**
     * @param string      $dbPath    path to the SQLite file (its dir is created if missing)
     * @param string|null $exportLog optional JSON-lines file to also append to (not canonical)
     */
    public function __construct(string $dbPath, private ?string $exportLog = null)
    {
        if (!extension_loaded('pdo_sqlite')) {
            throw new \RuntimeException('SqliteHitStore needs ext-pdo_sqlite');
        }
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
        foreach (['method', 'event', 'cc', 'severity'] as $col) {   // exact match
            if (isset($f[$col]) && $f[$col] !== '') {
                $clauses[] = "$col = :$col";
                $params[":$col"] = (string) $f[$col];
            }
        }
        if (isset($f['ip']) && $f['ip'] !== '') {
            $clauses[] = 'ip LIKE :ip';
            $params[':ip'] = '%' . $f['ip'] . '%';
        }
        if (isset($f['q']) && $f['q'] !== '') {                     // free text over path + body
            $clauses[] = '(path LIKE :q OR body LIKE :q)';
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

    /** Delete hits older than $days days (ISO-8601 UTC timestamps sort lexicographically). Rows removed. */
    public function retainDays(int $days): int
    {
        if ($days <= 0) {
            return 0;
        }
        $cutoff = gmdate('c', time() - $days * 86400);
        $st = $this->db->prepare("DELETE FROM hits WHERE ts <> '' AND ts < :c");
        $st->execute([':c' => $cutoff]);
        $n = $st->rowCount();
        if ($n > 0) {
            $this->db->exec('PRAGMA incremental_vacuum');
        }

        return $n;
    }

    /**
     * Cap the database on disk: delete the oldest rows in chunks (reclaiming pages as we go) until
     * the file is under $maxBytes, or nothing is left. Rows removed.
     */
    public function retainBytes(int $maxBytes): int
    {
        if ($maxBytes <= 0 || $this->sizeBytes() <= $maxBytes) {
            return 0;
        }
        $removed = 0;
        while ($this->sizeBytes() > $maxBytes) {
            $affected = (int) $this->db->exec('DELETE FROM hits WHERE id IN (SELECT id FROM hits ORDER BY id ASC LIMIT 2000)');
            if ($affected === 0) {
                break; // table drained; the floor is an empty db, not an under-cap file
            }
            $removed += $affected;
            $this->db->exec('PRAGMA incremental_vacuum');
        }

        return $removed;
    }

    /** On-disk size of the database file in bytes (page_count * page_size, includes the freelist). */
    public function sizeBytes(): int
    {
        $pageCount = (int) $this->db->query('PRAGMA page_count')->fetchColumn();
        $pageSize = (int) $this->db->query('PRAGMA page_size')->fetchColumn();

        return $pageCount * $pageSize;
    }

    public function probeVelocity(string $ip): array
    {
        if ($ip === '' || $ip === 'unknown') {
            return ['recent' => 0, 'extended' => 0];
        }
        $now = time();
        $st = $this->db->prepare(
            'SELECT COUNT(DISTINCT CASE WHEN ts >= :c60 THEN path END) recent, COUNT(DISTINCT path) extended
             FROM hits WHERE ip = :ip AND ts >= :c600'
        );
        $st->execute([':ip' => $ip, ':c60' => gmdate('c', $now - 60), ':c600' => gmdate('c', $now - 600)]);
        $row = $st->fetch(PDO::FETCH_ASSOC) ?: [];

        return ['recent' => (int) ($row['recent'] ?? 0), 'extended' => (int) ($row['extended'] ?? 0)];
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

    // --- SQLite plumbing ---

    private function open(string $path): PDO
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        // SQLite creates the file 0644 no matter the umask. Force 0666 so the php-fpm workers
        // (www-data) and the root protocol listeners can share this one file. Do it BEFORE enabling
        // WAL: sqlite creates the -wal/-shm sidecars copying the db file's mode, and WAL needs the
        // -shm writable even for readers. A root listener opens the db every boot, so a stale
        // root-owned db from a prior run is re-chmodded here too.
        @chmod($path, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        // Incremental auto-vacuum so GB-based retention can hand freed pages back to disk without a
        // full VACUUM. Must be set before the table exists to take on a fresh db; a legacy db
        // (auto_vacuum=NONE) is converted once below.
        $db->exec('PRAGMA auto_vacuum=INCREMENTAL');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, ip TEXT, method TEXT, path TEXT,
                matched INTEGER DEFAULT 0, severity TEXT, served INTEGER DEFAULT 0,
                templates TEXT, body TEXT, event TEXT,
                log4shell INTEGER DEFAULT 0, honeytoken TEXT,
                cc TEXT, city TEXT, lat REAL, lon REAL, asn TEXT,
                known_attacker INTEGER DEFAULT 0
            )'
        );
        // Add columns introduced after a db was first created (idempotent migration for old files).
        $cols = $db->query('PRAGMA table_info(hits)')->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('known_attacker', $cols, true)) {
            $db->exec('ALTER TABLE hits ADD COLUMN known_attacker INTEGER DEFAULT 0');
        }
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ip ON hits(ip)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_known ON hits(known_attacker)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ip_ts ON hits(ip, ts)');   // covers the LLM-gate velocity query
        // Persistent bulk-scan pin: an IP that trips the velocity gate stays pinned to plain-404 for a
        // cooldown even after it goes quiet, so it cannot burst then slow-probe for fakes.
        $db->exec('CREATE TABLE IF NOT EXISTS bulk_scan (ip TEXT PRIMARY KEY, until TEXT NOT NULL)');

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
                'INSERT INTO hits (ts,ip,method,path,matched,severity,served,templates,body,event,log4shell,honeytoken,cc,city,lat,lon,asn,known_attacker)
                 VALUES (:ts,:ip,:method,:path,:matched,:severity,:served,:templates,:body,:event,:log4shell,:honeytoken,:cc,:city,:lat,:lon,:asn,:known_attacker)'
            );
        }
        $st = $this->insertStmt;
        $geo = $e['geo'] ?? [];
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

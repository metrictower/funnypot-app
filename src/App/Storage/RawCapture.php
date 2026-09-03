<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\Core\RequestContext;
use PDO;
use Throwable;

/**
 * Full-request capture, opt-in via FUNNYPOT_CAPTURE_RAW — for a vuln scan where the operator wants to see
 * EXACTLY what a scanner sent, not the classified summary. The canonical `hits` table (SqliteHitStore)
 * keeps only UA + Referer + a 300-char body slice; this keeps the COMPLETE request: every header, the full
 * query string, and the full body up to a 64KB cap (with the true byte size recorded so truncation is
 * visible).
 *
 * Written to its OWN sqlite file (raw-capture.sqlite), separate from the dashboard's hits DB, so a scan
 * burst never contends with the live feed. Every write is fail-open: capture must never break the honeypot.
 *
 * Retention (FP-0249): unlike the canonical hit store, raw capture is bounded by AGE and SIZE by default
 * (FUNNYPOT_RAW_RETAIN_DAYS=7 / FUNNYPOT_RAW_RETAIN_GB=1) — it is an opt-in debugging capture at ~136KB/row
 * worst case, so a single scan can otherwise fill the fixed disk allowance
 * (docs/pentest-2026-08-29.md:5,82). {@see retainDays()} / {@see retainBytes()} are driven from
 * demo/retention.php, never from capture(). LEGACY-VACUUM CAVEAT: a raw-capture.sqlite created before this
 * ticket has no incremental auto_vacuum, so freed pages sit on the freelist and the file never shrinks —
 * {@see ensureSizeReclaimable()} converts it once (auto_vacuum=INCREMENTAL + a full VACUUM), but ONLY from
 * a retain method (never capture()), since a multi-GB legacy file's one-time VACUUM must burn the retention
 * timer's time, not a request worker's.
 */
final class RawCapture
{
    /** Max stored bytes per field — a DoS guard so a huge scanner body can't fill the disk. */
    private const BODY_CAP = 65536;   // 64 KB
    private const HEAD_CAP = 65536;   // 64 KB of header JSON
    private const URL_CAP = 8192;     // 8 KB for path / query

    /** retainBytes() chunk size: a raw row can be up to ~136KB, so 200 rows ≈ 27MB per chunk keeps
     *  each delete transaction (and the wal growth it causes) bounded. */
    private const RETAIN_BYTES_CHUNK = 200;

    private ?PDO $db = null;

    public function __construct(private string $dbPath)
    {
    }

    /** The conventional raw-capture.sqlite path next to the canonical hits db — the ONE place this is
     *  derived, so retention and the front controller can never drift apart on where the file lives. */
    public static function defaultPath(string $hitDbPath): string
    {
        return \dirname($hitDbPath) . '/raw-capture.sqlite';
    }

    public function capture(RequestContext $ctx, string $clientIp): void
    {
        try {
            $body = $ctx->rawBody ?? '';
            $headers = (string) json_encode($ctx->headers, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

            $st = $this->db()->prepare(
                'INSERT INTO raw_requests
                    (ts, ip, method, path, query, headers, body, body_bytes, host, scheme, http_version)
                 VALUES
                    (:ts, :ip, :method, :path, :query, :headers, :body, :body_bytes, :host, :scheme, :http_version)'
            );
            $st->execute([
                ':ts' => gmdate('c'),
                ':ip' => $clientIp,
                ':method' => $ctx->method,
                ':path' => substr($ctx->path, 0, self::URL_CAP),
                ':query' => substr($ctx->query, 0, self::URL_CAP),
                ':headers' => substr($headers, 0, self::HEAD_CAP),
                ':body' => substr($body, 0, self::BODY_CAP),
                ':body_bytes' => strlen($body),   // true size, even when the stored body is capped
                ':host' => substr($ctx->host, 0, 255),
                ':scheme' => substr($ctx->scheme, 0, 8),
                ':http_version' => substr($ctx->httpVersion, 0, 16),
            ]);
        } catch (Throwable $e) {
            // Capture is best-effort — never let it break request handling.
        }
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        // Shared open/pragma seam (WAL, busy_timeout, synchronous=NORMAL, auto_vacuum=INCREMENTAL for a
        // FRESH file, dir mkdir, chmod 0666) — schema-agnostic, so the table/index DDL stays local here.
        // A pre-existing legacy file (auto_vacuum still NONE) is converted separately by
        // ensureSizeReclaimable(), called only from the retain methods below, never from here.
        $db = Sqlite::open($this->dbPath);
        $db->exec(
            'CREATE TABLE IF NOT EXISTS raw_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, ip TEXT, method TEXT, path TEXT, query TEXT,
                headers TEXT, body TEXT, body_bytes INTEGER DEFAULT 0,
                host TEXT, scheme TEXT, http_version TEXT
            )'
        );
        $db->exec('CREATE INDEX IF NOT EXISTS idx_raw_ip ON raw_requests(ip)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_raw_ts ON raw_requests(ts)');

        return $this->db = $db;
    }

    /** Delete raw_requests older than $days days (ISO-8601 ts sorts lexicographically). Rows removed. */
    public function retainDays(int $days): int
    {
        if ($days <= 0) {
            return 0;
        }
        $this->ensureSizeReclaimable();
        $cutoff = gmdate('c', time() - $days * 86400);
        $st = $this->db()->prepare("DELETE FROM raw_requests WHERE ts <> '' AND ts < :c");
        $st->execute([':c' => $cutoff]);
        $n = $st->rowCount();
        if ($n > 0) {
            $this->db()->exec('PRAGMA incremental_vacuum');
        }

        return $n;
    }

    /**
     * Cap the database on disk: checkpoint the wal, then delete the oldest rows in chunks (reclaiming
     * pages as we go) until the wal-inclusive size is under $maxBytes, or nothing is left. Rows removed.
     */
    public function retainBytes(int $maxBytes): int
    {
        if ($maxBytes <= 0) {
            return 0;
        }
        $this->ensureSizeReclaimable();
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
                fwrite(STDERR, "raw-capture retention: wal pinned by a reader, stopping under cap on main file alone\n");
                break;
            }
            $affected = (int) $this->db()->exec(
                'DELETE FROM raw_requests WHERE id IN (SELECT id FROM raw_requests ORDER BY id ASC LIMIT ' . self::RETAIN_BYTES_CHUNK . ')'
            );
            if ($affected === 0) {
                break; // table drained; the floor is an empty db, not an under-cap file
            }
            $removed += $affected;
            $this->db()->exec('PRAGMA incremental_vacuum');
        }

        return $removed;
    }

    /** On-disk footprint in bytes: the main file (page_count * page_size) PLUS the `-wal` sidecar — WAL
     *  writes accumulate there between checkpoints, so main-file-only size understates true disk use
     *  under a busy long-reader (`-shm` is a fixed-size mmap index, not counted). */
    public function sizeBytes(): int
    {
        return $this->mainSizeBytes() + $this->walBytes();
    }

    private function mainSizeBytes(): int
    {
        $pageCount = (int) $this->db()->query('PRAGMA page_count')->fetchColumn();
        $pageSize = (int) $this->db()->query('PRAGMA page_size')->fetchColumn();

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
            $this->db()->exec('PRAGMA wal_checkpoint(TRUNCATE)');
        } catch (Throwable $e) {
            // best-effort, see docblock
        }
    }

    /**
     * One-time legacy conversion so size-based retention can reclaim disk on a raw-capture.sqlite that
     * predates incremental auto-vacuum: enables it, then VACUUMs to actually hand freed pages back
     * (enabling the pragma alone does nothing for pages already free before it was set). Cheap and
     * self-limiting: once converted, auto_vacuum reads back as 2 and this is skipped on every later call.
     *
     * Called ONLY from retainDays()/retainBytes() (the retention timer), never from capture() — a
     * multi-GB legacy file's VACUUM needs up to ~2x its size in transient disk and blocks for its
     * duration; that cost belongs to the backgrounded retention pass, not a request worker (which would
     * otherwise silently drop captures for the whole VACUUM, breaking the fail-open contract).
     */
    private function ensureSizeReclaimable(): void
    {
        $db = $this->db();
        if ((int) $db->query('PRAGMA auto_vacuum')->fetchColumn() === 2) {
            return;
        }
        // VACUUM needs up to ~2x the file size in transient disk. A multi-GB legacy file could fill the
        // fixed disk allowance mid-VACUUM, which is exactly the self-DoS this ticket exists to prevent —
        // skip (+warn) when there isn't clearly enough headroom. The row deletes still run either way;
        // freelist reuse bounds further growth even without reclaim.
        clearstatcache(true, $this->dbPath);
        $fileSize = (int) @filesize($this->dbPath);
        $free = @disk_free_space(\dirname($this->dbPath));
        if ($fileSize > 0 && $free !== false && $free < $fileSize) {
            fwrite(STDERR, sprintf(
                "raw-capture retention: skipping one-time VACUUM (legacy db, %d bytes) — only %d bytes free\n",
                $fileSize,
                (int) $free
            ));

            return;
        }
        $db->exec('PRAGMA auto_vacuum=INCREMENTAL');
        $db->exec('VACUUM');
    }
}

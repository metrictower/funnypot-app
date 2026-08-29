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
 */
final class RawCapture
{
    /** Max stored bytes per field — a DoS guard so a huge scanner body can't fill the disk. */
    private const BODY_CAP = 65536;   // 64 KB
    private const HEAD_CAP = 65536;   // 64 KB of header JSON
    private const URL_CAP = 8192;     // 8 KB for path / query

    private ?PDO $db = null;

    public function __construct(private string $dbPath)
    {
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
        @mkdir(\dirname($this->dbPath), 0777, true);
        $db = new PDO('sqlite:' . $this->dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA busy_timeout=5000');
        $db->exec('PRAGMA synchronous=NORMAL');
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
}

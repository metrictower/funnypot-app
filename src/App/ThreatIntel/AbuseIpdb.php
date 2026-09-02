<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use PDO;
use Throwable;

/**
 * Report attacker IPs to AbuseIPDB. We only ever REPORT (never check/fetch — that costs API quota);
 * the honeypot's own blocklist is a separate, info-only feed.
 *
 * Reporting is split into enqueue (fast, local) and drain (the actual HTTP POSTs), because the
 * protocol honeypots run a single-process select loop that must never block on a network call. The
 * request/connection paths enqueue into intel.db; a background worker drains the queue on a timer.
 *
 * Guards, applied at enqueue so junk never queues:
 *  - INVARIANT: never report our own IP, and report nothing at all if our own IP is unknown.
 *  - public, routable IPs only.
 *  - per-IP dedup window + a daily cap (the free tier is ~1000/day).
 */
final class AbuseIpdb
{
    private ?PDO $db = null;

    /**
     * @param string[] $selfIps our own public IP(s); reporting is disabled when empty
     * @param callable(string,array<string>,string):array{status:int,body:string}|null $sender
     */
    public function __construct(
        private string $apiKey,
        private string $intelDbPath,
        private array $selfIps = [],
        private int $dailyCap = 1000,
        private int $dedupHours = 24,
        private $sender = null,
    ) {
    }

    /** AbuseIPDB category ids appropriate to a protocol honeypot hit. */
    public static function categoriesForProtocol(string $protocol): string
    {
        switch (strtolower($protocol)) {
            case 'ssh':
                return '18,22';        // brute-force, SSH
            case 'telnet':
                return '18,23';        // brute-force, IoT-targeted
            case 'ftp':
            case 'smtp':
            case 'pop3':
            case 'imap':
                return '18';           // brute-force
            case 'sip':
                return '8,18';         // Fraud VoIP + brute-force (REGISTER spray -> toll-fraud calls)
            case 'mssql':
                return '15,18';        // hacking + brute-force (sa spray -> xp_cmdshell RCE)
            case 'cwmp':
            case 'tr069':
                return '15,23,21';     // hacking + IoT-targeted + web-app-attack (TR-069 router worm)
            default:
                return '14,15';        // port scan, hacking
        }
    }

    /**
     * Queue a report if it passes the guards. Fast (a local SQLite write); safe to call from the
     * request path and the listener loop.
     *
     * @return array{queued:bool,reason:string}
     */
    public function enqueue(string $ip, string $comment, string $categories = '21'): array
    {
        if ($this->apiKey === '') {
            return $this->skip('no api key');
        }
        if ($this->selfIps === []) {
            return $this->skip('self ips not configured');   // fail safe
        }
        if (IpMatcher::matches($ip, $this->selfIps)) {         // FP-0247 (Fix J): exact IP or self CIDR
            return $this->skip('self');                       // the invariant
        }
        if (!self::reportable($ip)) {
            return $this->skip('not a public ip');
        }
        try {
            if ($this->recentlyReported($ip)) {
                return $this->skip('deduped');
            }
            if ($this->dailyCount() >= $this->dailyCap) {
                return $this->skip('daily cap');
            }
            $this->db()->prepare(
                'INSERT INTO abuse_queue (ip, categories, comment, created_at, attempts) VALUES (:ip,:c,:m,:t,0)'
            )->execute([':ip' => $ip, ':c' => $categories, ':m' => substr($comment, 0, 1000), ':t' => gmdate('c')]);
            $this->recordReported($ip);   // dedup mark now so the same IP does not re-queue

            return ['queued' => true, 'reason' => 'queued'];
        } catch (Throwable $e) {
            return $this->skip('error: ' . $e->getMessage());
        }
    }

    /**
     * Send queued reports. Stops at the daily cap; drops 2xx/4xx, retries transient failures up to
     * three times. Returns counts.
     *
     * @return array{sent:int,failed:int,pending:int}
     */
    public function drain(int $limit = 200): array
    {
        $sent = 0;
        $failed = 0;
        try {
            $rows = $this->db()->query('SELECT * FROM abuse_queue ORDER BY id ASC LIMIT ' . max(1, $limit))
                ->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return ['sent' => 0, 'failed' => 0, 'pending' => 0];
        }

        $send = $this->sender ?? [$this, 'httpPost'];
        foreach ($rows as $row) {
            if ($this->dailyCount() >= $this->dailyCap) {
                break;   // leave the rest for tomorrow
            }
            $status = 0;
            try {
                $res = $send(
                    'https://api.abuseipdb.com/api/v2/report',
                    ['Key: ' . $this->apiKey, 'Accept: application/json'],
                    http_build_query([
                        'ip' => $row['ip'],
                        'categories' => $row['categories'],
                        'comment' => $row['comment'],
                        'timestamp' => gmdate('c'),
                    ])
                );
                $status = (int) ($res['status'] ?? 0);
            } catch (Throwable $e) {
                $status = 0;
            }

            if ($status >= 200 && $status < 300) {
                $this->delete((int) $row['id']);
                $this->bumpDaily();
                $sent++;
            } elseif ($status >= 400 && $status < 500) {
                $this->delete((int) $row['id']);   // client error: it will never succeed
                $failed++;
            } else {
                $attempts = (int) $row['attempts'] + 1;
                if ($attempts >= 3) {
                    $this->delete((int) $row['id']);
                    $failed++;
                } else {
                    $this->db()->prepare('UPDATE abuse_queue SET attempts = :a WHERE id = :id')
                        ->execute([':a' => $attempts, ':id' => (int) $row['id']]);
                }
            }
        }

        return ['sent' => $sent, 'failed' => $failed, 'pending' => $this->queueCount()];
    }

    public function queueCount(): int
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM abuse_queue')->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /** @return array{queued:bool,reason:string} */
    private function skip(string $reason): array
    {
        return ['queued' => false, 'reason' => $reason];
    }

    private static function reportable(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }
        // FP-0247 (Fix J): RFC 6598 CGNAT (100.64.0.0/10) and the benchmarking ranges are not publicly
        // routable — a "source" there is local-side plumbing or a shared-NAT neighbour, so reporting it
        // always risks innocent collateral. The PHP filter flags do not exclude these; reject explicitly.
        foreach (['100.64.0.0/10', '192.0.0.0/24', '198.18.0.0/15'] as $cidr) {
            if (IpMatcher::inCidr($ip, $cidr)) {
                return false;
            }
        }

        return true;
    }

    private function recentlyReported(string $ip): bool
    {
        $st = $this->db()->prepare('SELECT reported_at FROM abuse_reports WHERE ip = :ip');
        $st->execute([':ip' => $ip]);
        $at = $st->fetchColumn();

        return $at !== false && (strtotime((string) $at) ?: 0) > time() - $this->dedupHours * 3600;
    }

    private function recordReported(string $ip): void
    {
        $this->db()->prepare('INSERT OR REPLACE INTO abuse_reports (ip, reported_at) VALUES (:ip,:at)')
            ->execute([':ip' => $ip, ':at' => gmdate('c')]);
    }

    private function delete(int $id): void
    {
        $this->db()->prepare('DELETE FROM abuse_queue WHERE id = :id')->execute([':id' => $id]);
    }

    private function dailyCount(): int
    {
        $st = $this->db()->prepare('SELECT n FROM abuse_daily WHERE day = :d');
        $st->execute([':d' => gmdate('Y-m-d')]);
        $n = $st->fetchColumn();

        return $n === false ? 0 : (int) $n;
    }

    private function bumpDaily(): void
    {
        $this->db()->prepare('INSERT INTO abuse_daily (day, n) VALUES (:d,1) ON CONFLICT(day) DO UPDATE SET n = n + 1')
            ->execute([':d' => gmdate('Y-m-d')]);
    }

    /**
     * @param string[] $headers
     * @return array{status:int,body:string}
     */
    private function httpPost(string $url, array $headers, string $body): array
    {
        $ctx = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => implode("\r\n", array_merge($headers, ['Content-Type: application/x-www-form-urlencoded'])),
            'content' => $body,
            'timeout' => 8,
            'ignore_errors' => true,
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        $status = 0;
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return ['status' => $status, 'body' => $resp === false ? '' : $resp];
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $dir = dirname($this->intelDbPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $this->intelDbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        @chmod($this->intelDbPath, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('CREATE TABLE IF NOT EXISTS abuse_reports (ip TEXT PRIMARY KEY, reported_at TEXT)');
        $db->exec('CREATE TABLE IF NOT EXISTS abuse_daily (day TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)');
        $db->exec('CREATE TABLE IF NOT EXISTS abuse_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, categories TEXT, comment TEXT, created_at TEXT, attempts INTEGER NOT NULL DEFAULT 0)');

        return $this->db = $db;
    }
}

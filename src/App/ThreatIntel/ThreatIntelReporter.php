<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use PDO;
use Throwable;

/**
 * Report attacker IPs to our own Threat Intel service (funnypot-mainnet's public POST /v1/report),
 * so the network collects the real threats the honeypot catches. Mirrors {@see AbuseIpdb}: we only
 * ever REPORT, never check/fetch.
 *
 * Same enqueue → drain split as AbuseIpdb: enqueue() is a fast local write safe to call from the
 * request path and the single-process protocol listener loop (which must never block on the network);
 * drain() does the actual HTTP POSTs from a background worker. Both are fail-silent — a Threat Intel
 * outage or timeout must never surface as a 500 or otherwise alter the served honeypot response.
 *
 * The endpoint is injected as a base URL (scheme + host only); the reporter appends /v1/report. Auth
 * is a sensor-tier key sent in the `Key:` header. Its own dedup/cap tables (ti_*) are distinct from
 * AbuseIpdb's (abuse_*) in the same SQLite file, so the two destinations throttle independently.
 *
 * Guards, applied at enqueue so junk never queues:
 *  - INVARIANT: never report our own IP, and report nothing at all if our own IP is unknown.
 *  - public, routable IPs only.
 *  - per-IP dedup window + a daily cap.
 */
final class ThreatIntelReporter
{
    private ?PDO $db = null;

    /**
     * @param string   $baseUrl scheme + host only (e.g. https://threatintel.metrictower.com); /v1/report is appended
     * @param string   $apiKey  sensor-tier key sent as the `Key:` header; empty key ⇒ reporter inert
     * @param string[] $selfIps our own public IP(s); reporting is disabled when empty
     * @param callable(string,array<string>,string):array{status:int,body:string}|null $sender
     */
    public function __construct(
        private string $baseUrl,
        private string $apiKey,
        private string $intelDbPath,
        private array $selfIps = [],
        private int $dailyCap = 1000,
        private int $dedupHours = 24,
        private $sender = null,
    ) {
    }

    /** Protocol → category-id CSV, shared with AbuseIpdb (mainnet keeps the AbuseIPDB 1–23 vocabulary). */
    public static function categoriesForProtocol(string $protocol): string
    {
        return AbuseIpdb::categoriesForProtocol($protocol);
    }

    /**
     * Queue a report if it passes the guards. Fast (a local SQLite write) and fail-silent; safe to call
     * from the request path and the listener loop. $signals/$confidence are the optional additive
     * request-shape payload forwarded verbatim at drain — absent by default, so the posted body is
     * unchanged when the caller supplies none.
     *
     * @param array<string,mixed> $signals forwarded verbatim; empty ⇒ omitted from the POST body
     * @return array{queued:bool,reason:string}
     */
    public function enqueue(
        string $ip,
        string $comment,
        string $categories = '21',
        array $signals = [],
        float $confidence = 0.0,
    ): array {
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
                'INSERT INTO ti_queue (ip, categories, comment, signals, confidence, created_at, attempts) '
                . 'VALUES (:ip,:c,:m,:s,:cf,:t,0)'
            )->execute([
                ':ip' => $ip,
                ':c' => $categories,
                ':m' => substr($comment, 0, 1000),
                ':s' => $signals === [] ? null : (string) json_encode($signals),
                ':cf' => $confidence > 0.0 ? $confidence : null,
                ':t' => gmdate('c'),
            ]);
            $this->recordReported($ip);   // dedup mark now so the same IP does not re-queue

            return ['queued' => true, 'reason' => 'queued'];
        } catch (Throwable $e) {
            return $this->skip('error: ' . $e->getMessage());
        }
    }

    /**
     * Send queued reports to $baseUrl.'/v1/report'. Stops at the daily cap; drops 2xx/4xx, retries
     * transient failures (5xx / transport error) up to three times. Fail-silent: any transport fault
     * is swallowed and the row retried. Returns counts.
     *
     * @return array{sent:int,failed:int,pending:int}
     */
    public function drain(int $limit = 200): array
    {
        $sent = 0;
        $failed = 0;
        try {
            $rows = $this->db()->query('SELECT * FROM ti_queue ORDER BY id ASC LIMIT ' . max(1, $limit))
                ->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            return ['sent' => 0, 'failed' => 0, 'pending' => 0];
        }

        $url = rtrim($this->baseUrl, '/') . '/v1/report';
        $sensorId = $this->sensorId();
        $send = $this->sender ?? [$this, 'httpPost'];
        foreach ($rows as $row) {
            if ($this->dailyCount() >= $this->dailyCap) {
                break;   // leave the rest for tomorrow
            }
            $fields = [
                'ip' => $row['ip'],
                'categories' => $row['categories'],
                'comment' => $row['comment'],
                'timestamp' => gmdate('c'),
                'sensor_id' => $sensorId,
            ];
            if (($row['signals'] ?? null) !== null && $row['signals'] !== '') {
                $decoded = json_decode((string) $row['signals'], true);
                if (is_array($decoded) && $decoded !== []) {
                    $fields['signals'] = $decoded;
                }
            }
            if (($row['confidence'] ?? null) !== null) {
                $fields['confidence'] = (float) $row['confidence'];
            }

            $status = 0;
            try {
                $res = $send(
                    $url,
                    ['Key: ' . $this->apiKey, 'Accept: application/json'],
                    http_build_query($fields)
                );
                $status = (int) ($res['status'] ?? 0);
            } catch (Throwable $e) {
                $status = 0;   // fail-silent: a transport fault is treated as a transient failure
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
                    $this->db()->prepare('UPDATE ti_queue SET attempts = :a WHERE id = :id')
                        ->execute([':a' => $attempts, ':id' => (int) $row['id']]);
                }
            }
        }

        return ['sent' => $sent, 'failed' => $failed, 'pending' => $this->queueCount()];
    }

    public function queueCount(): int
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM ti_queue')->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /**
     * Stable per-install id, sent as `sensor_id` on every report. Generated once (a v4-style UUID from
     * random_bytes, never a hardware id) and persisted locally; the same value on every later call.
     * A convenience label only — mainnet keys sensor distinctness on the observed source IP.
     */
    public function sensorId(): string
    {
        try {
            $st = $this->db()->prepare("SELECT v FROM ti_meta WHERE k = 'sensor_id'");
            $st->execute();
            $id = $st->fetchColumn();
            if ($id !== false && $id !== null && $id !== '') {
                return (string) $id;
            }
            $id = self::uuid4();
            $this->db()->prepare("INSERT OR IGNORE INTO ti_meta (k, v) VALUES ('sensor_id', :v)")
                ->execute([':v' => $id]);
            // Re-read in case a concurrent worker won the insert race.
            $st = $this->db()->prepare("SELECT v FROM ti_meta WHERE k = 'sensor_id'");
            $st->execute();
            $won = $st->fetchColumn();

            return $won !== false && $won !== null && $won !== '' ? (string) $won : $id;
        } catch (Throwable $e) {
            return '';
        }
    }

    private static function uuid4(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);   // version 4
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);   // variant
        $h = bin2hex($b);

        return sprintf('%s-%s-%s-%s-%s', substr($h, 0, 8), substr($h, 8, 4), substr($h, 12, 4), substr($h, 16, 4), substr($h, 20, 12));
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
        $st = $this->db()->prepare('SELECT reported_at FROM ti_reports WHERE ip = :ip');
        $st->execute([':ip' => $ip]);
        $at = $st->fetchColumn();

        return $at !== false && (strtotime((string) $at) ?: 0) > time() - $this->dedupHours * 3600;
    }

    private function recordReported(string $ip): void
    {
        $this->db()->prepare('INSERT OR REPLACE INTO ti_reports (ip, reported_at) VALUES (:ip,:at)')
            ->execute([':ip' => $ip, ':at' => gmdate('c')]);
    }

    private function delete(int $id): void
    {
        $this->db()->prepare('DELETE FROM ti_queue WHERE id = :id')->execute([':id' => $id]);
    }

    private function dailyCount(): int
    {
        $st = $this->db()->prepare('SELECT n FROM ti_daily WHERE day = :d');
        $st->execute([':d' => gmdate('Y-m-d')]);
        $n = $st->fetchColumn();

        return $n === false ? 0 : (int) $n;
    }

    private function bumpDaily(): void
    {
        $this->db()->prepare('INSERT INTO ti_daily (day, n) VALUES (:d,1) ON CONFLICT(day) DO UPDATE SET n = n + 1')
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
        $db->exec('CREATE TABLE IF NOT EXISTS ti_reports (ip TEXT PRIMARY KEY, reported_at TEXT)');
        $db->exec('CREATE TABLE IF NOT EXISTS ti_daily (day TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)');
        $db->exec('CREATE TABLE IF NOT EXISTS ti_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, categories TEXT, comment TEXT, signals TEXT, confidence REAL, created_at TEXT, attempts INTEGER NOT NULL DEFAULT 0)');
        $db->exec('CREATE TABLE IF NOT EXISTS ti_meta (k TEXT PRIMARY KEY, v TEXT)');

        return $this->db = $db;
    }
}

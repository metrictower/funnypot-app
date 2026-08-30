<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use PDO;
use Throwable;

/**
 * Operator-authored manual IP blocklist — the dashboard "block this IP forever" control. Distinct from
 * Blocklist, which is feed-driven and info-only ("it never blocks anyone"): entries here are added by the
 * operator and are ENFORCED — a blocked source is dropped as early and cheaply as possible across every
 * tier (the HTTP deception and the protocol emulators), serving nothing. Persisted in its own table in
 * intel.sqlite (on the data volume, so it survives a redeploy); the public-feed refresh never touches it.
 *
 * isBlocked() is the hot path — the long-lived protocol listeners call it per packet — so it holds an
 * in-memory snapshot and reloads at most once per $reloadEvery seconds; between reloads a check is a
 * single hash lookup with no DB read. A short-lived php-fpm worker just loads once for its request.
 * Fail-open everywhere: an unreadable/locked db never blocks a request or a packet (mirrors
 * Blocklist::isKnown) — the honeypot must degrade, never break. Supports exact IPs and IPv4 CIDR.
 */
final class OperatorBlocklist
{
    private ?PDO $db = null;

    /** @var array<string,true> exact IP set */
    private array $ips = [];

    /** @var list<array{0:int,1:int}> IPv4 [lo,hi] ranges */
    private array $ranges = [];

    private float $loadedAt = -INF;
    private bool $loaded = false;

    public function __construct(private string $dbPath, private float $reloadEvery = 10.0)
    {
    }

    /**
     * Is this source manually blocked? O(1) between reloads; the snapshot refreshes at most once per
     * $reloadEvery seconds, so a flood of packets never turns into a flood of DB reads.
     */
    public function isBlocked(string $ip): bool
    {
        if ($ip === '' || $ip === 'unknown') {
            return false;
        }
        $now = microtime(true);
        if (!$this->loaded || ($now - $this->loadedAt) >= $this->reloadEvery) {
            $this->reload($now);
        }
        if (isset($this->ips[$ip])) {
            return true;
        }
        if ($this->ranges !== []) {
            $n = ip2long($ip);
            if ($n !== false) {
                $u = $n & 0xFFFFFFFF;
                foreach ($this->ranges as $r) {
                    if ($u >= $r[0] && $u <= $r[1]) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /** A valid block entry: an exact IPv4/IPv6 address, or an IPv4 CIDR (`a.b.c.d/n`). Rejects typos and
     *  IPv6 CIDR (unsupported by the range matcher), so a stored entry always actually matches something. */
    public static function isValidEntry(string $entry): bool
    {
        $entry = trim($entry);
        if ($entry === '') {
            return false;
        }
        if (strpos($entry, '/') === false) {
            return filter_var($entry, FILTER_VALIDATE_IP) !== false;
        }

        return self::cidrToRange($entry) !== null;
    }

    /** Add an exact IP or an IPv4 CIDR (`a.b.c.d/n`). Operator-authored, idempotent (INSERT OR REPLACE).
     *  Silently ignores an invalid entry (the caller should isValidEntry() first to report it). */
    public function add(string $entry, string $note = ''): void
    {
        $entry = trim($entry);
        if (!self::isValidEntry($entry)) {
            return;
        }
        $st = $this->db()->prepare('INSERT OR REPLACE INTO manual_blocklist (ip, added_at, note) VALUES (:ip, :at, :note)');
        $st->execute([':ip' => $entry, ':at' => gmdate('c'), ':note' => ($note !== '' ? $note : null)]);
        $this->loaded = false; // force this process's snapshot to refresh on the next check
    }

    public function remove(string $entry): void
    {
        $entry = trim($entry);
        if ($entry === '') {
            return;
        }
        $this->db()->prepare('DELETE FROM manual_blocklist WHERE ip = :ip')->execute([':ip' => $entry]);
        $this->loaded = false;
    }

    /** @return list<array{ip:string,added_at:string,note:?string}> newest first (for the dashboard list) */
    public function all(): array
    {
        try {
            $rows = $this->db()->query('SELECT ip, added_at, note FROM manual_blocklist ORDER BY added_at DESC')
                ->fetchAll(PDO::FETCH_ASSOC);

            return array_map(static fn (array $r): array => [
                'ip' => (string) $r['ip'],
                'added_at' => (string) $r['added_at'],
                'note' => $r['note'] !== null ? (string) $r['note'] : null,
            ], $rows ?: []);
        } catch (Throwable $e) {
            return [];
        }
    }

    private function reload(float $now): void
    {
        // Stamp the attempt FIRST so a missing/locked db holds the stale snapshot for the whole window
        // instead of re-hitting the db on every packet.
        $this->loadedAt = $now;
        $this->loaded = true;
        try {
            $ips = [];
            $ranges = [];
            foreach ($this->db()->query('SELECT ip FROM manual_blocklist') as $row) {
                $entry = (string) $row['ip'];
                if (strpos($entry, '/') === false) {
                    $ips[$entry] = true;
                } else {
                    $r = self::cidrToRange($entry);
                    if ($r !== null) {
                        $ranges[] = $r;
                    }
                }
            }
            $this->ips = $ips;         // swap in only on a clean read
            $this->ranges = $ranges;
        } catch (Throwable $e) {
            // fail-open: keep the last good snapshot (empty until a first successful read = never blocks)
        }
    }

    /** @return array{0:int,1:int}|null [lo,hi] for an IPv4 CIDR; null for IPv6/invalid (skipped) */
    private static function cidrToRange(string $cidr): ?array
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return null;
        }
        $base = ip2long($parts[0]);
        $bits = (int) $parts[1];
        if ($base === false || (string) $bits !== $parts[1] || $bits < 0 || $bits > 32) {
            return null;
        }
        $mask = $bits === 0 ? 0 : ((0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF);
        $lo = ($base & $mask) & 0xFFFFFFFF;
        $hi = ($lo | (~$mask & 0xFFFFFFFF)) & 0xFFFFFFFF;

        return [$lo, $hi];
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $dir = dirname($this->dbPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $this->dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        @chmod($this->dbPath, 0666);   // shared by the root protocol listeners and the www-data web workers
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        $db->exec('CREATE TABLE IF NOT EXISTS manual_blocklist (ip TEXT PRIMARY KEY, added_at TEXT NOT NULL, note TEXT)');

        return $this->db = $db;
    }
}

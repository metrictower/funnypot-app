<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use PDO;
use Throwable;

/**
 * Known-attacker IP blocklist. Fetches public attacker/botnet IP feeds, corroborates across them
 * (an IP's "lists" count = how many feeds named it), and stores the result in its own SQLite file
 * (intel.db, separate from the hit store so a bulk refresh never contends with hit ingest). The
 * honeypot asks isKnown() at write time to flag a hit as coming from a known attacker.
 *
 * This is info-only: it drives the dashboard "known" badge/filter, it never blocks anyone.
 *
 * Both exact IPs and IPv4 CIDR ranges are supported. Ranges are stored as lo/hi integer pairs (the
 * same trick geo.php uses) and treated as high-confidence (curated netset feeds), so a range match
 * flags regardless of the corroboration threshold. IPv6 CIDR ranges are skipped.
 */
final class Blocklist
{
    /** Public plaintext IP feeds. ipsum ships an "IP count" corroboration column; the rest are flat. */
    private const SOURCES = [
        'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'https://www.blocklist.de/downloads/export-ips_all.txt',
        'https://cinsscore.com/list/ci-badguys.txt',
        'https://lists.blocklist.de/lists/ssh.txt',
        'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    ];

    private ?PDO $db = null;

    public function __construct(private string $dbPath, private int $minLists = 1)
    {
        $this->minLists = max(1, $minLists);
    }

    /** Is this IP a known attacker: an exact hit (>= minLists feeds) or inside a blocklisted range? */
    public function isKnown(string $ip): bool
    {
        if ($ip === '' || $ip === 'unknown') {
            return false;
        }
        try {
            $db = $this->db();
            $st = $db->prepare('SELECT lists FROM blocklist WHERE ip = :ip');
            $st->execute([':ip' => $ip]);
            $lists = $st->fetchColumn();
            if ($lists !== false && (int) $lists >= $this->minLists) {
                return true;
            }

            $n = ip2long($ip);           // IPv4 range membership (ranges are curated: not minLists-gated)
            if ($n !== false) {
                $rst = $db->prepare('SELECT 1 FROM blocklist_ranges WHERE :u BETWEEN lo AND hi LIMIT 1');
                $rst->execute([':u' => $n & 0xFFFFFFFF]);
                if ($rst->fetchColumn() !== false) {
                    return true;
                }
            }

            return false;
        } catch (Throwable $e) {
            return false; // no intel db yet / unreadable: fail open, never break a request
        }
    }

    public function count(): int
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM blocklist')->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    public function rangeCount(): int
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM blocklist_ranges')->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /**
     * Refresh from the feeds. $fetch(url) returns the body or null; the default uses a bounded HTTP
     * GET. Tests inject a fetcher so no network is touched.
     *
     * @param callable(string):?string|null $fetch
     * @param string[]|null                 $sources
     * @return array{sources:int,ips:int,ranges:int,skipped:bool}
     */
    public function import(?callable $fetch = null, ?array $sources = null): array
    {
        $fetch ??= static function (string $url): ?string {
            $ctx = stream_context_create(['http' => ['timeout' => 20, 'user_agent' => 'funnypot'], 'https' => ['timeout' => 20]]);
            $body = @file_get_contents($url, false, $ctx);

            return $body === false ? null : $body;
        };

        $exact = [];
        $ranges = [];   // list of [lo, hi, count]
        $ok = 0;
        foreach ($sources ?? self::SOURCES as $url) {
            $body = $fetch($url);
            if ($body === null || $body === '') {
                continue;
            }
            $ok++;
            foreach (preg_split('/\r?\n/', $body) ?: [] as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#' || $line[0] === ';') {
                    continue;
                }
                $parts = preg_split('/\s+/', $line) ?: [];
                $token = $parts[0] ?? '';
                if ($token === '') {
                    continue;
                }
                $count = (isset($parts[1]) && ctype_digit($parts[1])) ? max(1, (int) $parts[1]) : 1;

                if (strpos($token, '/') !== false) {
                    $range = self::cidrToRange($token);
                    if ($range !== null) {
                        $ranges[] = [$range[0], $range[1], $count];
                    }
                } elseif (filter_var($token, FILTER_VALIDATE_IP) !== false) {
                    $exact[$token] = ($exact[$token] ?? 0) + $count;
                }
            }
        }

        $db = $this->db();

        // FP-0247 (Fix B): a total feed outage must NOT wipe corroborated intel. The old code ran an
        // unconditional DELETE after the fetch loop, so if every feed failed (or returned garbage that
        // parsed to zero tokens) the transaction committed an empty table — one DNS/proxy blip erased
        // all known-attacker intel until the next good refresh. Keep the existing data instead.
        if ($ok === 0 || ($exact === [] && $ranges === [])) {
            return ['sources' => $ok, 'ips' => 0, 'ranges' => 0, 'skipped' => true];
        }

        $db->beginTransaction();
        $db->exec('DELETE FROM blocklist');
        $db->exec('DELETE FROM blocklist_ranges');
        $ei = $db->prepare('INSERT OR REPLACE INTO blocklist (ip, lists) VALUES (:ip, :l)');
        foreach ($exact as $ip => $c) {
            $ei->execute([':ip' => $ip, ':l' => $c]);
        }
        $ri = $db->prepare('INSERT INTO blocklist_ranges (lo, hi, lists) VALUES (:lo, :hi, :l)');
        foreach ($ranges as [$lo, $hi, $c]) {
            $ri->execute([':lo' => $lo, ':hi' => $hi, ':l' => $c]);
        }
        // Stamp the successful refresh time inside the same transaction, so refreshedAt()/isStale()
        // reflect only real, non-empty imports.
        $db->prepare("INSERT INTO blocklist_meta (k, v) VALUES ('refreshed_at', :t) "
            . 'ON CONFLICT(k) DO UPDATE SET v = :t')->execute([':t' => gmdate('c')]);
        $db->commit();

        return ['sources' => $ok, 'ips' => count($exact), 'ranges' => count($ranges), 'skipped' => false];
    }

    /** ISO-8601 UTC time of the last successful (non-empty) import, or null if never refreshed. */
    public function refreshedAt(): ?string
    {
        try {
            $st = $this->db()->query("SELECT v FROM blocklist_meta WHERE k = 'refreshed_at'");
            $v = $st->fetchColumn();

            return ($v === false || $v === null || $v === '') ? null : (string) $v;
        } catch (Throwable $e) {
            return null;
        }
    }

    /** True if the data is older than $maxAgeHours. Fail-safe: a never-refreshed / unreadable store
     *  reads as stale, so the operator log surfaces the condition rather than hiding it. */
    public function isStale(int $maxAgeHours = 48): bool
    {
        $at = $this->refreshedAt();
        if ($at === null) {
            return true;
        }
        $ts = strtotime($at);

        return $ts === false || $ts < time() - $maxAgeHours * 3600;
    }

    /**
     * Convert an IPv4 CIDR to an unsigned [lo, hi] pair, or null for IPv6 / invalid input.
     *
     * @return array{0:int,1:int}|null
     */
    private static function cidrToRange(string $cidr): ?array
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2 || !ctype_digit($parts[1])) {
            return null;
        }
        $n = ip2long($parts[0]);
        $bits = (int) $parts[1];
        if ($n === false || $bits < 0 || $bits > 32) {
            return null;   // IPv6 or malformed
        }
        $n &= 0xFFFFFFFF;
        $mask = $bits === 0 ? 0 : ((0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF);
        $lo = $n & $mask;
        $hi = $lo | (~$mask & 0xFFFFFFFF);

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
        @chmod($this->dbPath, 0666);   // shared by the root refresh runner and the www-data web workers
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        $db->exec('CREATE TABLE IF NOT EXISTS blocklist (ip TEXT PRIMARY KEY, lists INTEGER NOT NULL DEFAULT 1)');
        $db->exec('CREATE TABLE IF NOT EXISTS blocklist_ranges (lo INTEGER NOT NULL, hi INTEGER NOT NULL, lists INTEGER NOT NULL DEFAULT 1)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_bl_ranges ON blocklist_ranges(lo, hi)');
        $db->exec('CREATE TABLE IF NOT EXISTS blocklist_meta (k TEXT PRIMARY KEY, v TEXT)');   // FP-0247 (Fix B): refresh staleness

        return $this->db = $db;
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Shell;

use Funnypot\Shell\Fs\Overlay;
use PDO;

/**
 * Server-side state for the streaming web terminal: one row per (browser session, host), carrying the
 * shell's overlay + cwd + env + history so the terminal reacts across requests (cd/touch persist,
 * reload survives) without holding any filesystem state in the browser. Bounded — idle rows expire (TTL)
 * and the table is LRU-capped — so a scanner can't exhaust the honeypot's disk/memory. Uses real
 * wall-clock (session bookkeeping is ephemeral, not the deterministic FS). Inert: stores diffs, not code.
 */
final class ConsoleSessionStore
{
    private const TTL = 3600;       // idle session expiry (seconds)
    private const MAX_ROWS = 500;   // hard LRU cap on live sessions
    private const MAX_HISTORY = 200;

    private ?PDO $db = null;

    public function __construct(private string $dbPath)
    {
    }

    /**
     * Open the SQLite file on first use, not at construction — non-console requests (the vast majority)
     * never touch it, and the open happens inside ConsoleRouter's fault guard so a store failure degrades
     * to empty output rather than a 500. ERRMODE_SILENT: a lost console session is acceptable, and a
     * throwing store must never become a tell.
     */
    private function db(): PDO
    {
        if ($this->db === null) {
            $this->db = new PDO('sqlite:' . $this->dbPath);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
            $this->db->exec('CREATE TABLE IF NOT EXISTS console_sessions ('
                . 'k TEXT PRIMARY KEY, host TEXT, cwd TEXT, overlay TEXT, env TEXT, history TEXT, last_exit INT, seen INT)');
        }

        return $this->db;
    }

    /** @return array{cwd:string,overlay:Overlay,env:array<string,string>,history:string[],lastExit:int}|null */
    public function load(string $key): ?array
    {
        $st = $this->db()->prepare('SELECT cwd, overlay, env, history, last_exit FROM console_sessions WHERE k = ? AND seen > ?');
        $st->execute([$key, time() - self::TTL]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        if ($r === false) {
            return null;
        }

        return [
            'cwd' => (string) $r['cwd'],
            'overlay' => Overlay::fromArray(self::jsonArr((string) $r['overlay'])),
            'env' => self::jsonStrMap((string) $r['env']),
            'history' => array_values(array_map('strval', self::jsonArr((string) $r['history']))),
            'lastExit' => (int) $r['last_exit'],
        ];
    }

    /**
     * @param array{host:string,cwd:string,overlay:Overlay,env:array<string,string>,history:string[],lastExit:int} $state
     */
    public function save(string $key, array $state): void
    {
        $st = $this->db()->prepare('REPLACE INTO console_sessions (k, host, cwd, overlay, env, history, last_exit, seen) '
            . 'VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
        $st->execute([
            $key,
            $state['host'],
            $state['cwd'],
            (string) json_encode($state['overlay']->toArray()),
            (string) json_encode($state['env']),
            (string) json_encode(array_slice($state['history'], -self::MAX_HISTORY)),
            $state['lastExit'],
            time(),
        ]);
        $this->evict();
    }

    /** Drop a session (exit/logout) so the next command from that cookie starts a fresh login. */
    public function delete(string $key): void
    {
        $this->db()->prepare('DELETE FROM console_sessions WHERE k = ?')->execute([$key]);
    }

    /** Expire idle rows, then LRU-cap the table (defense against a scanner opening endless sessions). */
    private function evict(): void
    {
        $this->db()->exec('DELETE FROM console_sessions WHERE seen < ' . (time() - self::TTL));
        $this->db()->exec('DELETE FROM console_sessions WHERE k IN ('
            . 'SELECT k FROM console_sessions ORDER BY seen DESC LIMIT -1 OFFSET ' . self::MAX_ROWS . ')');
    }

    /** @return array<mixed> */
    private static function jsonArr(string $json): array
    {
        $v = json_decode($json, true);

        return is_array($v) ? $v : [];
    }

    /** @return array<string,string> */
    private static function jsonStrMap(string $json): array
    {
        $out = [];
        foreach (self::jsonArr($json) as $k => $v) {
            if (is_string($k) && is_scalar($v)) {
                $out[$k] = (string) $v;
            }
        }

        return $out;
    }
}

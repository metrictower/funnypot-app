<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use PDO;
use Throwable;

/**
 * Bounded, TTL'd store for the panel's fake persistence layer. A scanner that tests STORED (not just
 * reflected) vulns writes a note/message/edit and re-polls to check it "landed"; echoing the submitted
 * text back on the later read makes the panel look genuinely stateful and deepens the trap.
 *
 * Keyed by ip + persona seed + view key, so one visitor never sees another's submission (a shared echo
 * would be both a wrong answer and a fingerprint). Same PDO idiom as SqliteHitStore/LlmFakeCache (WAL,
 * busy_timeout, 0666 before WAL) in its own file so it never contends with hit ingest, and fail-open
 * throughout: any store error degrades to "nothing stored", never a thrown error the caller must handle.
 *
 * The stored text is raw; escaping is the renderer's job at echo time (never persist executable markup).
 * Growth is capped three ways — a per-view item cap, a per-value length cap, and a global row cap — plus
 * a TTL so a submission evaporates on its own well after the write-then-repoll window has passed.
 */
final class FakePersistenceStore
{
    /** How long a submission is echoed back before it evaporates (comfortably past a re-poll window). */
    private const TTL_SECONDS = 1800;

    /** Newest N submissions kept per (ip, seed, view); older ones for that view are pruned on write. */
    private const MAX_ITEMS_PER_VIEW = 10;

    /** Field names kept per submission (a write endpoint has a handful of inputs, never more). */
    private const MAX_FIELDS = 8;

    /** Each stored value is truncated to this many bytes so a single POST cannot grow the row unbounded. */
    private const MAX_VALUE_LEN = 500;

    /** Global row ceiling; oldest rows are pruned first once the table would exceed it. */
    private const MAX_ROWS = 5000;

    private ?PDO $db = null;

    /** @var callable():int injectable clock so the TTL is testable without sleeping */
    private $clock;

    public function __construct(private string $dbPath, ?callable $clock = null, private int $ttlSeconds = self::TTL_SECONDS)
    {
        $this->clock = $clock ?? 'time';
    }

    /**
     * Record one submission for a view. Fields are cleaned (bounded count + length, empties dropped)
     * and stored as JSON; the write also prunes expired rows, over-cap items for this view, and the
     * global overflow. A no-op (silently) when the fields clean to nothing or the store errors.
     *
     * @param array<string,scalar> $fields
     */
    public function record(string $ip, int $seed, string $viewKey, array $fields): void
    {
        try {
            $clean = $this->clean($fields);
            if ($clean === []) {
                return;
            }
            $payload = json_encode($clean, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($payload === false) {
                return;
            }
            $now = ($this->clock)();
            $db = $this->db();
            $db->prepare('INSERT INTO stored_bait (ip, seed, view_key, payload, created_at) VALUES (:ip, :seed, :vk, :p, :t)')
                ->execute([':ip' => $ip, ':seed' => $seed, ':vk' => $viewKey, ':p' => $payload, ':t' => $now]);
            $this->prune($db, $ip, $seed, $viewKey, $now);
        } catch (Throwable $e) {
            // fail-open: the panel simply looks stateless, never errors
        }
    }

    /**
     * Non-expired submissions for a view, newest first (already TTL- and count-bounded). Each item is
     * the decoded field map. Empty on a miss or any error.
     *
     * @return list<array<string,string>>
     */
    public function read(string $ip, int $seed, string $viewKey): array
    {
        try {
            $cutoff = ($this->clock)() - $this->ttlSeconds;
            $st = $this->db()->prepare(
                'SELECT payload FROM stored_bait
                 WHERE ip = :ip AND seed = :seed AND view_key = :vk AND created_at > :c
                 ORDER BY id DESC LIMIT :lim'
            );
            $st->bindValue(':ip', $ip);
            $st->bindValue(':seed', $seed, PDO::PARAM_INT);
            $st->bindValue(':vk', $viewKey);
            $st->bindValue(':c', $cutoff, PDO::PARAM_INT);
            $st->bindValue(':lim', self::MAX_ITEMS_PER_VIEW, PDO::PARAM_INT);
            $st->execute();

            $out = [];
            foreach ($st->fetchAll(PDO::FETCH_COLUMN) ?: [] as $payload) {
                $decoded = json_decode((string) $payload, true);
                if (is_array($decoded)) {
                    $item = [];
                    foreach ($decoded as $k => $v) {
                        if (is_string($k) && is_scalar($v)) {
                            $item[$k] = (string) $v;
                        }
                    }
                    if ($item !== []) {
                        $out[] = $item;
                    }
                }
            }

            return $out;
        } catch (Throwable $e) {
            return [];
        }
    }

    /**
     * @param array<string,scalar> $fields
     * @return array<string,string>
     */
    private function clean(array $fields): array
    {
        $out = [];
        foreach ($fields as $key => $value) {
            if (count($out) >= self::MAX_FIELDS) {
                break;
            }
            if (!is_string($key) || !is_scalar($value)) {
                continue;
            }
            $val = (string) $value;
            if ($val === '') {
                continue;
            }
            if (strlen($val) > self::MAX_VALUE_LEN) {
                $val = substr($val, 0, self::MAX_VALUE_LEN);
            }
            $out[substr($key, 0, 64)] = $val;
        }

        return $out;
    }

    private function prune(PDO $db, string $ip, int $seed, string $viewKey, int $now): void
    {
        // Drop everything past its TTL first — keeps the table from accreting dead rows over time.
        $db->prepare('DELETE FROM stored_bait WHERE created_at <= :c')->execute([':c' => $now - $this->ttlSeconds]);

        // Per-view cap: keep only the newest N for this (ip, seed, view). Ids are monotonic, so anything
        // below the oldest kept id is surplus.
        $st = $db->prepare('SELECT id FROM stored_bait WHERE ip = :ip AND seed = :seed AND view_key = :vk ORDER BY id DESC LIMIT :lim');
        $st->bindValue(':ip', $ip);
        $st->bindValue(':seed', $seed, PDO::PARAM_INT);
        $st->bindValue(':vk', $viewKey);
        $st->bindValue(':lim', self::MAX_ITEMS_PER_VIEW, PDO::PARAM_INT);
        $st->execute();
        $keep = $st->fetchAll(PDO::FETCH_COLUMN) ?: [];
        if ($keep !== []) {
            $floor = (int) min($keep);
            $del = $db->prepare('DELETE FROM stored_bait WHERE ip = :ip AND seed = :seed AND view_key = :vk AND id < :floor');
            $del->bindValue(':ip', $ip);
            $del->bindValue(':seed', $seed, PDO::PARAM_INT);
            $del->bindValue(':vk', $viewKey);
            $del->bindValue(':floor', $floor, PDO::PARAM_INT);
            $del->execute();
        }

        // Global ceiling: if the whole table is over cap, delete the oldest overflow.
        $count = (int) $db->query('SELECT COUNT(*) FROM stored_bait')->fetchColumn();
        if ($count > self::MAX_ROWS) {
            $over = $db->prepare('DELETE FROM stored_bait WHERE id IN (SELECT id FROM stored_bait ORDER BY id ASC LIMIT :n)');
            $over->bindValue(':n', $count - self::MAX_ROWS, PDO::PARAM_INT);
            $over->execute();
        }
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
        @chmod($this->dbPath, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS stored_bait (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, seed INTEGER, view_key TEXT,
                payload TEXT, created_at INTEGER
            )'
        );
        $db->exec('CREATE INDEX IF NOT EXISTS idx_bait_view ON stored_bait(ip, seed, view_key, id)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_bait_age ON stored_bait(created_at)');

        return $this->db = $db;
    }
}

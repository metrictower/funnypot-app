<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use PDO;
use Throwable;

/**
 * The separate, explicit, OFF-by-default raw-prompt capture (FUNNYPOT_AI_PROMPT_CAPTURE_RAW). It is NOT
 * implied by the general scanner-debug capture and is the ONLY place a raw prompt may be retained — and
 * only accepted OpenAI/Ollama system/user message text and Anthropic top-level system/user text, with
 * role markers, provider/model, timestamp, an opaque actor digest and true/stored byte counts. It stores
 * no headers, query, authorization, cookies, tool definitions, arguments, results or response, and has
 * no dashboard/export/reporter reader.
 *
 * Its own file in a private 0700 directory as mode 0600, never following a symlink. Hard bounds: 16 KiB
 * per row, a per-actor and a global rolling-hour admission cap, a global row cap, and a fixed 24-hour
 * retention no environment setting can lengthen. Every path is fail-open: a failure drops the optional
 * capture, never the decoy response.
 */
final class AiPromptCapture
{
    private const MAX_ROW_BYTES = 16384;      // 16 KiB stored per message
    private const MAX_PER_ACTOR_HOUR = 30;
    private const MAX_GLOBAL_HOUR = 500;
    private const MAX_ROWS = 2048;
    private const RETAIN_S = 86400;            // 24 hours, hard
    private const PRUNE_BATCH = 64;

    private ?PDO $db = null;
    private bool $failed = false;

    /** @var callable():int */
    private $clock;

    public function __construct(private string $dbPath, ?callable $clock = null)
    {
        $this->clock = $clock ?? 'time';
    }

    public static function defaultPath(string $hitDbPath): string
    {
        return \dirname($hitDbPath) . '/ai-capture/ai-prompt-capture.sqlite';
    }

    /**
     * Store the accepted system/user prompt messages for one request. No-op (silently) when capture is
     * off (the caller gates on the flag), when a cap is hit, or on any store fault.
     */
    public function capture(ChatRequest $req, string $ip): void
    {
        if ($req->promptMessages === []) {
            return;
        }
        try {
            $db = $this->db();
            if ($db === null) {
                return;
            }
            $now = ($this->clock)();
            $actor = hash('sha256', 'a|' . $ip);
            $db->exec('BEGIN IMMEDIATE');

            $this->prune($db, $now);

            $hourAgo = $now - 3600;
            $perActor = $this->countSince($db, 'WHERE actor = :a AND ts >= :t', [':a' => $actor, ':t' => $hourAgo]);
            $global = $this->countSince($db, 'WHERE ts >= :t', [':t' => $hourAgo]);
            $total = (int) $db->query('SELECT COUNT(*) FROM prompt_capture')->fetchColumn();
            if ($perActor >= self::MAX_PER_ACTOR_HOUR || $global >= self::MAX_GLOBAL_HOUR || $total >= self::MAX_ROWS) {
                $db->exec('ROLLBACK');

                return;
            }

            $ins = $db->prepare(
                'INSERT INTO prompt_capture (ts, actor, provider, model, role, text, true_bytes, stored_bytes)
                 VALUES (:ts, :actor, :prov, :model, :role, :text, :true, :stored)'
            );
            foreach ($req->promptMessages as $msg) {
                $role = (string) ($msg['role'] ?? '');
                $text = (string) ($msg['text'] ?? '');
                if ($role === '' || $text === '') {
                    continue;
                }
                $trueBytes = strlen($text);
                $stored = substr($text, 0, self::MAX_ROW_BYTES);
                $ins->execute([
                    ':ts' => $now,
                    ':actor' => $actor,
                    ':prov' => $req->dialect,
                    ':model' => substr($req->model, 0, 120),
                    ':role' => $role,
                    ':text' => $stored,
                    ':true' => $trueBytes,
                    ':stored' => strlen($stored),
                ]);
            }
            $db->exec('COMMIT');
        } catch (Throwable $e) {
            $this->rollback();
            $this->failed = true;
        }
    }

    /**
     * Retention: delete rows past the fixed 24-hour age, then trim any overflow above the row cap. Runs
     * from the retention CLI whether or not capture is currently enabled, so an existing file is serviced.
     * Fail-open. Returns the number of rows removed (0 on any fault).
     */
    public function retain(): int
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return 0;
            }
            $now = ($this->clock)();
            $removed = 0;
            $db->exec('BEGIN IMMEDIATE');
            $removed += $this->deleteExpired($db, $now);
            $removed += $this->trimOverflow($db);
            $db->exec('COMMIT');

            return $removed;
        } catch (Throwable $e) {
            $this->rollback();

            return 0;
        }
    }

    /** Test-only reader: every stored row, newest last. This store has no other reader. */
    public function allRows(): array
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return [];
            }
            $rows = $db->query('SELECT ts, actor, provider, model, role, text, true_bytes, stored_bytes FROM prompt_capture ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);

            return $rows === false ? [] : $rows;
        } catch (Throwable $e) {
            return [];
        }
    }

    /** @param array<string,mixed> $params */
    private function countSince(PDO $db, string $where, array $params): int
    {
        $st = $db->prepare('SELECT COUNT(*) FROM prompt_capture ' . $where);
        $st->execute($params);

        return (int) $st->fetchColumn();
    }

    private function prune(PDO $db, int $now): void
    {
        $this->deleteExpired($db, $now);
    }

    private function deleteExpired(PDO $db, int $now): int
    {
        $cutoff = $now - self::RETAIN_S;
        $ids = $db->query('SELECT id FROM prompt_capture WHERE ts < ' . $cutoff . ' ORDER BY id LIMIT ' . self::PRUNE_BATCH)->fetchAll(PDO::FETCH_COLUMN);
        if (!$ids) {
            return 0;
        }
        $db->exec('DELETE FROM prompt_capture WHERE id IN (' . implode(',', array_map('intval', $ids)) . ')');

        return count($ids);
    }

    private function trimOverflow(PDO $db): int
    {
        $total = (int) $db->query('SELECT COUNT(*) FROM prompt_capture')->fetchColumn();
        if ($total <= self::MAX_ROWS) {
            return 0;
        }
        $over = $total - self::MAX_ROWS;
        $ids = $db->query('SELECT id FROM prompt_capture ORDER BY id LIMIT ' . $over)->fetchAll(PDO::FETCH_COLUMN);
        if (!$ids) {
            return 0;
        }
        $db->exec('DELETE FROM prompt_capture WHERE id IN (' . implode(',', array_map('intval', $ids)) . ')');

        return count($ids);
    }

    private function rollback(): void
    {
        try {
            if ($this->db !== null && $this->db->inTransaction()) {
                $this->db->exec('ROLLBACK');
            }
        } catch (Throwable $e) {
            // ignore
        }
    }

    private function db(): ?PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        if ($this->failed) {
            return null;
        }
        try {
            $dir = \dirname($this->dbPath);
            if (is_link($dir) || is_link($this->dbPath)) {
                $this->failed = true;

                return null;
            }
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
            }
            @chmod($dir, 0700);
            $db = new PDO('sqlite:' . $this->dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            @chmod($this->dbPath, 0600);
            $db->exec('PRAGMA busy_timeout=1000');
            $db->exec('PRAGMA journal_mode=WAL');
            $db->exec('PRAGMA synchronous=NORMAL');
            $db->exec(
                'CREATE TABLE IF NOT EXISTS prompt_capture (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    role TEXT NOT NULL,
                    text TEXT NOT NULL,
                    true_bytes INTEGER NOT NULL,
                    stored_bytes INTEGER NOT NULL
                )'
            );
            $db->exec('CREATE INDEX IF NOT EXISTS idx_capture_ts ON prompt_capture(ts)');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_capture_actor ON prompt_capture(actor, ts)');

            return $this->db = $db;
        } catch (Throwable $e) {
            $this->failed = true;

            return null;
        }
    }
}

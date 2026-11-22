<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Ssrf\KeyIndexBuilder;
use Funnypot\App\Tarpit\Ssrf\KeyIndexView;
use PDO;
use PDOException;
use Throwable;

/**
 * The served-key index, in its own SQLite file (ssrf-keyidx.sqlite) so building it never holds the
 * decoy state store's write lock.
 *
 * Each row is a 12-byte keyed hash of one fact (a key or a settings.py host) under a version tag; no
 * raw value is stored. The index is built one slice per request at most, in its own short BEGIN
 * IMMEDIATE taken without waiting: a request that finds the lock held skips the slice and answers as if
 * the index were still incomplete. The build is not charged to any source: its total is fixed per
 * version.
 *
 * Versioning is cheap per request. The deploy id (persona, cap, pointer flag and the build stamp the
 * composition root passes in) is compared on every advance; the generators' output fingerprint, the
 * costly part, is recomputed only when the deploy id changes and at most hourly after that. A new
 * version takes a new tag, so a stale index is never read, and the old tag's rows are deleted in
 * bounded chunks by later slices rather than in one long clear.
 */
final class SsrfKeyIndex implements KeyIndexView
{
    public const GARBAGE_PER_SLICE = 4096;
    public const RECHECK_S = 3600;

    private ?PDO $db = null;
    private bool $failed = false;

    /** @var array<string,string>|null */
    private ?array $meta = null;

    public int $slicesRun = 0;
    public int $sectionsRun = 0;
    public bool $busySkipped = false;

    public function __construct(
        private string $path,
        private string $key,
        private KeyIndexBuilder $builder,
        private string $deployId,
    ) {
    }

    /**
     * The deploy id: everything that decides what the generators serve and that is cheap to read on
     * every request. $buildStamp is the installed code's reference, passed in by the composition root.
     */
    public static function deployId(string $key, int $personaSeed, int $capBytes, bool $pointers, string $buildStamp): string
    {
        return hash_hmac('sha256', 'deploy|' . $personaSeed . '|' . $capBytes . '|' . ($pointers ? 1 : 0) . '|' . $buildStamp, $key);
    }

    public function hashOf(string $kind, string $value): string
    {
        return substr(hash_hmac('sha256', $kind . "\0" . $value, $this->key), 0, 24);
    }

    public function contains(string $kind, string $value): bool
    {
        return $this->containsHash($this->hashOf($kind, $value));
    }

    public function containsHash(string $hashHex): bool
    {
        try {
            $db = $this->db();
            $meta = $this->meta();
            if ($db === null || $meta === null || preg_match('/\A[0-9a-f]{24}\z/', $hashHex) !== 1) {
                return false;
            }
            $st = $db->prepare('SELECT 1 FROM ssrf_keyidx WHERE v = :v AND h = :h');
            $st->bindValue(':v', (int) $meta['vtag'], PDO::PARAM_INT);
            $st->bindValue(':h', (string) hex2bin($hashHex), PDO::PARAM_LOB);
            $st->execute();

            return $st->fetchColumn() !== false;
        } catch (Throwable $e) {
            return false;
        }
    }

    public function complete(): bool
    {
        $meta = $this->meta();

        return $meta !== null && $meta['complete'] === '1' && $meta['deploy'] === $this->deployId;
    }

    /**
     * Run at most one bounded step: the version check when it is due, else one slice of the build,
     * plus a bounded chunk of an old version's rows. Never waits for the lock.
     */
    public function advance(int $now): void
    {
        $db = $this->db();
        if ($db === null) {
            return;
        }
        $meta = $this->meta();
        if ($meta !== null && $meta['complete'] === '1' && $meta['deploy'] === $this->deployId
            && $now - (int) $meta['fp_at'] < self::RECHECK_S && $meta['old'] === '') {
            return;
        }
        try {
            $db->exec('BEGIN IMMEDIATE');
        } catch (PDOException $e) {
            $this->busySkipped = true;

            return;
        }
        try {
            $m = $this->readMeta($db);
            $checked = false;
            if ($m['deploy'] !== $this->deployId || $now - (int) $m['fp_at'] >= self::RECHECK_S || $m['version'] === '') {
                $version = hash_hmac('sha256', $this->deployId . "\0" . $this->builder->fingerprint(), $this->key);
                if ($version !== $m['version']) {
                    if ($m['version'] !== '') {
                        $m['old'] = trim($m['old'] . ',' . $m['vtag'], ',');
                    }
                    $m['vtag'] = (string) ((int) $m['vtag'] + 1);
                    $m['next'] = '0';
                    $m['complete'] = '0';
                    $m['version'] = $version;
                }
                $m['deploy'] = $this->deployId;
                $m['fp_at'] = (string) $now;
                $checked = true;
            }
            if ($m['old'] !== '') {
                $tags = explode(',', $m['old']);
                $tag = (int) $tags[0];
                $del = $db->prepare('DELETE FROM ssrf_keyidx WHERE v = :v AND h IN (SELECT h FROM ssrf_keyidx WHERE v = :v2 LIMIT ' . self::GARBAGE_PER_SLICE . ')');
                $del->execute([':v' => $tag, ':v2' => $tag]);
                if ($del->rowCount() < self::GARBAGE_PER_SLICE) {
                    array_shift($tags);
                    $m['old'] = implode(',', $tags);
                }
            }
            if (!$checked && $m['complete'] !== '1') {
                $slice = (int) $m['next'];
                $ins = $db->prepare('INSERT OR IGNORE INTO ssrf_keyidx (v, h) VALUES (:v, :h)');
                $facts = $this->builder->slice($slice);
                foreach ($facts as [$kind, $value]) {
                    $ins->bindValue(':v', (int) $m['vtag'], PDO::PARAM_INT);
                    $ins->bindValue(':h', (string) hex2bin($this->hashOf($kind, $value)), PDO::PARAM_LOB);
                    $ins->execute();
                }
                $this->slicesRun++;
                $this->sectionsRun += $slice === 0 ? 0 : intdiv(count($facts), 4);
                $m['next'] = (string) ($slice + 1);
                if ($slice + 1 >= $this->builder->slices()) {
                    $m['complete'] = '1';
                }
            }
            $up = $db->prepare('INSERT INTO ssrf_meta (name, v) VALUES (:n, :v) ON CONFLICT(name) DO UPDATE SET v = excluded.v');
            foreach ($m as $name => $v) {
                $up->execute([':n' => $name, ':v' => $v]);
            }
            $db->exec('COMMIT');
            $this->meta = $m;
        } catch (Throwable $e) {
            try {
                $db->exec('ROLLBACK');
            } catch (Throwable $e2) {
                // nothing was open
            }
            $this->meta = null;
        }
    }

    /** @return array<string,int|string> rows, slices and state, for tests and the lab read-out */
    public function stats(): array
    {
        $db = $this->db();
        $m = $this->meta();
        if ($db === null || $m === null) {
            return [];
        }
        $rows = $db->prepare('SELECT COUNT(*) FROM ssrf_keyidx WHERE v = :v');
        $rows->execute([':v' => (int) $m['vtag']]);

        return ['rows' => (int) $rows->fetchColumn(), 'all_rows' => (int) $db->query('SELECT COUNT(*) FROM ssrf_keyidx')->fetchColumn()] + $m;
    }

    /** @return array<string,string>|null */
    private function meta(): ?array
    {
        if ($this->meta === null) {
            $db = $this->db();
            if ($db === null) {
                return null;
            }
            try {
                $this->meta = $this->readMeta($db);
            } catch (Throwable $e) {
                return null;
            }
        }

        return $this->meta;
    }

    /** @return array<string,string> */
    private function readMeta(PDO $db): array
    {
        $m = ['deploy' => '', 'fp_at' => '0', 'version' => '', 'vtag' => '0', 'next' => '0', 'complete' => '0', 'old' => ''];
        foreach ($db->query('SELECT name, v FROM ssrf_meta')->fetchAll(PDO::FETCH_ASSOC) as $r) {
            if (array_key_exists((string) $r['name'], $m)) {
                $m[(string) $r['name']] = (string) $r['v'];
            }
        }

        return $m;
    }

    public function db(): ?PDO
    {
        if ($this->failed) {
            return null;
        }
        if ($this->db !== null) {
            return $this->db;
        }
        try {
            $db = Sqlite::open($this->path);
            $db->exec('CREATE TABLE IF NOT EXISTS ssrf_keyidx (v INTEGER NOT NULL, h BLOB NOT NULL, PRIMARY KEY (v, h)) WITHOUT ROWID');
            $db->exec('CREATE TABLE IF NOT EXISTS ssrf_meta (name TEXT PRIMARY KEY, v TEXT NOT NULL)');
            $db->exec('PRAGMA busy_timeout=0');

            return $this->db = $db;
        } catch (Throwable $e) {
            $this->failed = true;

            return null;
        }
    }
}

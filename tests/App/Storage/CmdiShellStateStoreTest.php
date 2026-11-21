<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\CmdiShellStateStore;
use Funnypot\App\Tarpit\Cmdi\Outcome;
use Funnypot\App\Tarpit\Cmdi\ShellLexer;
use Funnypot\App\Tarpit\Cmdi\SourceState;
use PDO;
use PHPUnit\Framework\TestCase;

/** The console history store: bounded on every axis, keyed without raw IPs, and fail-open. */
final class CmdiShellStateStoreTest extends TestCase
{
    private string $dir = '';
    private int $now = 1795000000;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->dir = sys_get_temp_dir() . '/fp-cmdi-store-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    private function store(int $maxRows = CmdiShellStateStore::MAX_ROWS, int $globalHr = CmdiShellStateStore::GLOBAL_HR, int $turnsCap = CmdiShellStateStore::TURNS_CAP): CmdiShellStateStore
    {
        return new CmdiShellStateStore($this->dir . '/cmdi-shell.sqlite', 'store-key', fn (): int => $this->now, $maxRows, $globalHr, $turnsCap);
    }

    private function pdo(): PDO
    {
        return new PDO('sqlite:' . $this->dir . '/cmdi-shell.sqlite');
    }

    /** One turn's delta, as AdaptiveShell commits it. @return array<string,mixed> */
    private static function delta(string $line = 'ls | cat'): array
    {
        return SourceState::delta(ShellLexer::lex($line), new Outcome(Outcome::ERROR, 'phantom', 'unexpected_|', '|', 'pipe', 'pick')) + ['sticky' => '/upload.php'];
    }

    /** The state a fresh source has after that one turn. */
    private static function state(string $line = 'ls | cat'): SourceState
    {
        return SourceState::empty()->apply(self::delta($line));
    }

    /** @return array<string,scalar> */
    private static function turn(): array
    {
        return ['identity' => 'www-data', 'value_source' => 'body', 'simple' => 0, 'kind' => 'error', 'sub' => 'phantom',
            'family' => 'pipe', 'msg_id' => 'unexpected_|', 'owned_by_rule' => 'attack-webshell-panel', 'console_rule' => 'A', 'delay_ms' => 0];
    }

    public function test_round_trip(): void
    {
        $s = $this->store();
        self::assertEquals(SourceState::empty(), $s->load('198.51.100.1'), 'unknown source: empty');
        self::assertTrue($s->save('198.51.100.1', self::delta(), self::turn()));
        self::assertEquals(self::state(), $this->store()->load('198.51.100.1'), 'a fresh connection reads it back');
        self::assertEquals(SourceState::empty(), $s->load('198.51.100.2'), 'sources do not share state');
    }

    public function test_idle_rows_expire(): void
    {
        $s = $this->store();
        $s->save('198.51.100.1', self::delta(), self::turn());
        $this->now += CmdiShellStateStore::TTL_S + 1;
        self::assertEquals(SourceState::empty(), $s->load('198.51.100.1'));
        $s->save('198.51.100.9', self::delta(), self::turn());
        self::assertSame(2, (int) $this->pdo()->query('SELECT COUNT(*) FROM cmdi_shell')->fetchColumn(), 'the idle row was purged (gauge + one source left)');
    }

    public function test_row_count_is_lru_capped(): void
    {
        self::assertSame(2000, CmdiShellStateStore::MAX_ROWS);
        $s = $this->store(20);
        for ($i = 0; $i <= 20; $i++) {
            $this->now++;
            $s->save("10.0.0.{$i}", self::delta(), self::turn());
        }
        self::assertSame(20, (int) $this->pdo()->query("SELECT COUNT(*) FROM cmdi_shell WHERE k != '#global'")->fetchColumn());
        self::assertEquals(SourceState::empty(), $s->load('10.0.0.0'), 'the least recently seen source was evicted');
        self::assertEquals(self::state(), $s->load('10.0.0.20'));
    }

    public function test_memo_is_capped_at_64(): void
    {
        $s = $this->store();
        for ($i = 0; $i < 80; $i++) {
            $this->now++;
            $s->save('198.51.100.1', SourceState::delta(ShellLexer::lex('ls' . str_repeat(' | cat', $i + 1)), new Outcome(Outcome::ERROR, 'phantom', 'unexpected_|', '|', 'pipe', 'pick')), self::turn());
        }
        self::assertCount(SourceState::MEMO_CAP, $s->load('198.51.100.1')->memo);
    }

    public function test_per_source_writes_are_capped_per_hour(): void
    {
        $this->now = 1795000000 - (1795000000 % 3600);
        $s = $this->store();
        for ($i = 0; $i < CmdiShellStateStore::PER_SOURCE_HR; $i++) {
            self::assertTrue($s->save('198.51.100.1', self::delta(), self::turn()), "write {$i}");
        }
        $before = $s->load('198.51.100.1');
        self::assertFalse($s->save('198.51.100.1', self::delta('id; id'), self::turn()), 'the 601st write this hour is refused');
        self::assertEquals($before, $s->load('198.51.100.1'), 'and nothing changed');
        self::assertNull($before->memoFor(ShellLexer::lex('id; id')->shapeKey));
        self::assertTrue($s->save('198.51.100.2', self::delta(), self::turn()), 'another source still writes');
        $this->now += 3600;
        self::assertTrue($s->save('198.51.100.1', self::delta('id; id'), self::turn()), 'writes resume the next hour');
    }

    public function test_global_writes_are_capped_per_hour(): void
    {
        self::assertSame(20000, CmdiShellStateStore::GLOBAL_HR);
        $this->now = 1795000000 - (1795000000 % 3600);
        $s = $this->store(CmdiShellStateStore::MAX_ROWS, 30);
        for ($i = 0; $i < 30; $i++) {
            self::assertTrue($s->save("10.1.0.{$i}", self::delta(), self::turn()));
        }
        self::assertFalse($s->save('10.2.0.1', self::delta(), self::turn()), 'a rotating-IP flood stops at the gauge');
        self::assertEquals(SourceState::empty(), $s->load('10.2.0.1'));
    }

    public function test_an_unwritable_path_fails_open(): void
    {
        $s = new CmdiShellStateStore('/proc/fp-no-such-dir/x/cmdi-shell.sqlite', 'k');
        self::assertEquals(SourceState::empty(), $s->load('198.51.100.1'));
        self::assertFalse($s->save('198.51.100.1', self::delta(), self::turn()));
    }

    public function test_the_stored_key_is_not_the_ip(): void
    {
        $s = $this->store();
        $s->save('198.51.100.77', self::delta(), self::turn());
        $keys = $this->pdo()->query("SELECT k FROM cmdi_shell WHERE k != '#global'")->fetchAll(PDO::FETCH_COLUMN);
        self::assertCount(1, $keys);
        self::assertMatchesRegularExpression('~^[0-9a-f]{32}$~', $keys[0]);
        self::assertSame($s->key('198.51.100.77'), $keys[0]);
        $dump = (string) file_get_contents($this->dir . '/cmdi-shell.sqlite') . (string) @file_get_contents($this->dir . '/cmdi-shell.sqlite-wal');
        self::assertStringNotContainsString('198.51.100.77', $dump, 'no raw IP anywhere in the file');
    }

    public function test_turn_log_is_fifo_capped_and_purged(): void
    {
        $s = $this->store(CmdiShellStateStore::MAX_ROWS, CmdiShellStateStore::GLOBAL_HR, 10);
        for ($i = 0; $i < 15; $i++) {
            $s->save("10.3.0.{$i}", self::delta(), ['msg_id' => "m{$i}"] + self::turn());
        }
        $ids = $this->pdo()->query('SELECT msg_id FROM cmdi_turns ORDER BY id')->fetchAll(PDO::FETCH_COLUMN);
        self::assertCount(10, $ids);
        self::assertSame('m5', $ids[0], 'oldest rows dropped first');
        $this->now += CmdiShellStateStore::TURNS_RETAIN_S + 1;
        $s->save('10.3.1.1', self::delta(), self::turn());
        self::assertSame(1, (int) $this->pdo()->query('SELECT COUNT(*) FROM cmdi_turns')->fetchColumn(), 'week-old rows purged');
        $row = $this->pdo()->query('SELECT * FROM cmdi_turns')->fetch(PDO::FETCH_ASSOC);
        self::assertSame('www-data', $row['identity']);
        self::assertSame('A', $row['console_rule']);
        self::assertSame('attack-webshell-panel', $row['owned_by_rule']);
    }

    public function test_busy_timeout_is_short(): void
    {
        $s = $this->store();
        $s->load('198.51.100.1');
        $db = (new \ReflectionProperty($s, 'db'))->getValue($s);
        self::assertInstanceOf(PDO::class, $db);
        self::assertSame(CmdiShellStateStore::BUSY_TIMEOUT_MS, (int) $db->query('PRAGMA busy_timeout')->fetchColumn());
        self::assertSame(25, CmdiShellStateStore::BUSY_TIMEOUT_MS);
    }

    public function test_the_file_is_shared_mode(): void
    {
        $this->store()->load('198.51.100.1');
        clearstatcache();
        self::assertSame(0666, fileperms($this->dir . '/cmdi-shell.sqlite') & 0777, 'same 0666 as every Sqlite::open() file');
    }

    public function test_a_row_stays_bounded_under_a_long_adversarial_sequence(): void
    {
        // Long control-character redirect targets and junk paths: the worst JSON-escaping case.
        $target = str_repeat("\x01", 3500);
        $state = SourceState::empty();
        $s = $this->store();
        for ($j = 0; $j < 150; $j++) {
            $lex = ShellLexer::lex(str_repeat('a;', $j + 1) . "echo x > '" . $target . "'");
            self::assertSame(strlen($target), strlen($lex->redirectTargets[0] ?? ''), 'sanity: the target is that long');
            $delta = SourceState::delta($lex, new Outcome(Outcome::ACCEPT, Outcome::RUNTIME, 'readonly', $lex->redirectTargets[0], null, 'pick'));
            foreach (['/' . str_repeat('"', 150) . $j . '.php', '/' . str_repeat("\x02", 199), '/up/' . $j . '.php'] as $k => $path) {
                $this->now++;
                self::assertTrue($s->save('198.51.100.5', ($k === 0 ? $delta : []) + ['sticky' => $path], self::turn()), "write {$j}.{$k}");
                $state = $state->apply(($k === 0 ? $delta : []) + ['sticky' => $path]);
            }
        }
        self::assertLessThanOrEqual(SourceState::MAX_ROW_BYTES, strlen($state->toJson()));
        $stored = (string) $this->pdo()->query("SELECT state FROM cmdi_shell WHERE k != '#global'")->fetchColumn();
        self::assertLessThanOrEqual(SourceState::MAX_ROW_BYTES, strlen($stored), 'the stored row is bounded');
        self::assertStringNotContainsString("\\u0001", $stored, 'no attacker target is stored');
        self::assertStringNotContainsString('\\u0002', $stored, 'no unprintable path is stored');
        $back = $s->load('198.51.100.5');
        self::assertNotEmpty($back->memo);
        foreach ($back->memo as $d) {
            self::assertSame('', $d['t'], 'a stored readonly outcome carries no target');
        }
        self::assertTrue($back->isSticky('/up/149.php'));
        self::assertSame(12288, SourceState::MAX_ROW_BYTES);
    }

    public function test_overlapping_turns_from_one_source_both_land(): void
    {
        // Two workers each read the row before either writes (two separate connections).
        $a = $this->store();
        $b = $this->store();
        $a->load('198.51.100.8');
        $b->load('198.51.100.8');
        $da = SourceState::delta(ShellLexer::lex('id; whoami'), new Outcome(Outcome::ERROR, 'phantom', 'unexpected_;', ';', 'semicolon', 'pick'));
        $db = SourceState::delta(ShellLexer::lex('cat /etc/hosts | head'), new Outcome(Outcome::ACCEPT, Outcome::FIRST, '', '', null, 'pick'));
        self::assertTrue($a->save('198.51.100.8', $da, self::turn()));
        self::assertTrue($b->save('198.51.100.8', $db, self::turn()));
        $back = $this->store()->load('198.51.100.8');
        self::assertNotNull($back->memoFor(ShellLexer::lex('id; whoami')->shapeKey), 'the first turn\'s memo survives the second write');
        self::assertNotNull($back->memoFor(ShellLexer::lex('cat /etc/hosts | head')->shapeKey));
        self::assertSame(['unexpected_;', 'accept'], $back->recentMsgIds, 'both messages, in commit order');
    }

    public function test_sticky_paths_round_trip_and_are_capped(): void
    {
        $s = $this->store();
        for ($i = 0; $i < 10; $i++) {
            $this->now++;
            $s->save('198.51.100.1', ['sticky' => "/u/{$i}.php"], self::turn());
        }
        $back = $s->load('198.51.100.1');
        self::assertCount(SourceState::STICKY_CAP, $back->stickyPaths);
        self::assertTrue($back->isSticky('/u/9.php'));
        self::assertFalse($back->isSticky('/u/0.php'));
    }
}

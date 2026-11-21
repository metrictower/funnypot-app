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

    private static function state(string $line = 'ls | cat'): SourceState
    {
        $lex = ShellLexer::lex($line);

        return SourceState::empty()->after($lex, new Outcome(Outcome::ERROR, 'phantom', 'unexpected_|', '|', 'pipe', 'pick'))->withSticky('/upload.php');
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
        self::assertTrue($s->save('198.51.100.1', self::state(), self::turn()));
        self::assertEquals(self::state(), $this->store()->load('198.51.100.1'), 'a fresh connection reads it back');
        self::assertEquals(SourceState::empty(), $s->load('198.51.100.2'), 'sources do not share state');
    }

    public function test_idle_rows_expire(): void
    {
        $s = $this->store();
        $s->save('198.51.100.1', self::state(), self::turn());
        $this->now += CmdiShellStateStore::TTL_S + 1;
        self::assertEquals(SourceState::empty(), $s->load('198.51.100.1'));
        $s->save('198.51.100.9', self::state(), self::turn());
        self::assertSame(2, (int) $this->pdo()->query('SELECT COUNT(*) FROM cmdi_shell')->fetchColumn(), 'the idle row was purged (gauge + one source left)');
    }

    public function test_row_count_is_lru_capped(): void
    {
        self::assertSame(2000, CmdiShellStateStore::MAX_ROWS);
        $s = $this->store(20);
        for ($i = 0; $i <= 20; $i++) {
            $this->now++;
            $s->save("10.0.0.{$i}", self::state(), self::turn());
        }
        self::assertSame(20, (int) $this->pdo()->query("SELECT COUNT(*) FROM cmdi_shell WHERE k != '#global'")->fetchColumn());
        self::assertEquals(SourceState::empty(), $s->load('10.0.0.0'), 'the least recently seen source was evicted');
        self::assertEquals(self::state(), $s->load('10.0.0.20'));
    }

    public function test_memo_is_capped_at_64(): void
    {
        $state = SourceState::empty();
        for ($i = 0; $i < 80; $i++) {
            $state = $state->after(ShellLexer::lex('ls' . str_repeat(' | cat', $i + 1)), new Outcome(Outcome::ERROR, 'phantom', 'unexpected_|', '|', 'pipe', 'pick'));
        }
        $s = $this->store();
        $s->save('198.51.100.1', $state, self::turn());
        self::assertCount(SourceState::MEMO_CAP, $s->load('198.51.100.1')->memo);
    }

    public function test_per_source_writes_are_capped_per_hour(): void
    {
        $this->now = 1795000000 - (1795000000 % 3600);
        $s = $this->store();
        for ($i = 0; $i < CmdiShellStateStore::PER_SOURCE_HR; $i++) {
            self::assertTrue($s->save('198.51.100.1', self::state(), self::turn()), "write {$i}");
        }
        self::assertFalse($s->save('198.51.100.1', self::state('id; id'), self::turn()), 'the 601st write this hour is refused');
        self::assertEquals(self::state(), $s->load('198.51.100.1'), 'and nothing changed');
        self::assertTrue($s->save('198.51.100.2', self::state(), self::turn()), 'another source still writes');
        $this->now += 3600;
        self::assertTrue($s->save('198.51.100.1', self::state('id; id'), self::turn()), 'writes resume the next hour');
    }

    public function test_global_writes_are_capped_per_hour(): void
    {
        self::assertSame(20000, CmdiShellStateStore::GLOBAL_HR);
        $this->now = 1795000000 - (1795000000 % 3600);
        $s = $this->store(CmdiShellStateStore::MAX_ROWS, 30);
        for ($i = 0; $i < 30; $i++) {
            self::assertTrue($s->save("10.1.0.{$i}", self::state(), self::turn()));
        }
        self::assertFalse($s->save('10.2.0.1', self::state(), self::turn()), 'a rotating-IP flood stops at the gauge');
        self::assertEquals(SourceState::empty(), $s->load('10.2.0.1'));
    }

    public function test_an_unwritable_path_fails_open(): void
    {
        $s = new CmdiShellStateStore('/proc/fp-no-such-dir/x/cmdi-shell.sqlite', 'k');
        self::assertEquals(SourceState::empty(), $s->load('198.51.100.1'));
        self::assertFalse($s->save('198.51.100.1', self::state(), self::turn()));
    }

    public function test_the_stored_key_is_not_the_ip(): void
    {
        $s = $this->store();
        $s->save('198.51.100.77', self::state(), self::turn());
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
            $s->save("10.3.0.{$i}", self::state(), ['msg_id' => "m{$i}"] + self::turn());
        }
        $ids = $this->pdo()->query('SELECT msg_id FROM cmdi_turns ORDER BY id')->fetchAll(PDO::FETCH_COLUMN);
        self::assertCount(10, $ids);
        self::assertSame('m5', $ids[0], 'oldest rows dropped first');
        $this->now += CmdiShellStateStore::TURNS_RETAIN_S + 1;
        $s->save('10.3.1.1', self::state(), self::turn());
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

    public function test_sticky_paths_round_trip_and_are_capped(): void
    {
        $state = SourceState::empty();
        for ($i = 0; $i < 10; $i++) {
            $state = $state->withSticky("/u/{$i}.php");
        }
        $s = $this->store();
        $s->save('198.51.100.1', $state, self::turn());
        $back = $s->load('198.51.100.1');
        self::assertCount(SourceState::STICKY_CAP, $back->stickyPaths);
        self::assertTrue($back->isSticky('/u/9.php'));
        self::assertFalse($back->isSticky('/u/0.php'));
    }
}

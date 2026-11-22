<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\TokenMintOutcome;
use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Storage\TokenMintTx;
use Funnypot\App\Tarpit\Mint\MintState;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;

final class TokenMintStoreTest extends TestCase
{
    private const NOW = 1763800000;
    private string $dir = '';

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite required');
        }
        $this->dir = sys_get_temp_dir() . '/fp_tms_' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        exec('chmod -R u+rwx ' . escapeshellarg($this->dir) . ' 2>/dev/null; rm -rf ' . escapeshellarg($this->dir));
    }

    private function store(array $limits = [], ?\Closure $faults = null): TokenMintStore
    {
        return new TokenMintStore($this->dir . '/tm.sqlite', $limits, $faults);
    }

    private static function write(string $marker, bool $change = true, int $units = 1): callable
    {
        return static function (?MintState $s, TokenMintTx $tx) use ($marker, $change, $units): TokenMintOutcome {
            $s ??= MintState::fresh($tx->now, str_repeat('e', 16));
            $s->d['sn'] = $marker === '' ? 0 : crc32($marker);
            $s->d['marker'] = $marker;

            return new TokenMintOutcome($s, $change, $units, $marker);
        };
    }

    public function test_schema_busy_timeout_and_no_raw_secret_or_ip(): void
    {
        $st = $this->store();
        self::assertTrue($st->ready());
        self::assertSame(100, (int) $st->db()->query('PRAGMA busy_timeout')->fetchColumn());
        $res = $st->transact(str_repeat('a', 32), str_repeat('a', 16), self::NOW, function (?MintState $s, TokenMintTx $tx): TokenMintOutcome {
            $tx->insertCode(hash('sha256', 'code'), 1, 2, ['read:user'], 'req', self::NOW + 600);

            return new TokenMintOutcome(MintState::fresh(self::NOW, 'ee'), true, 3, 'ok');
        });
        self::assertTrue($res['ok']);
        $bytes = (string) file_get_contents($this->dir . '/tm.sqlite') . (string) @file_get_contents($this->dir . '/tm.sqlite-wal');
        self::assertStringNotContainsString('45.79.12.34', $bytes);
        foreach (['mint_state', 'mint_codes', 'mint_refresh', 'mint_turns', 'mint_gauge'] as $t) {
            self::assertNotFalse($st->db()->query("SELECT COUNT(*) FROM {$t}"));
        }
    }

    public function test_transact_commits_and_an_exception_rolls_back(): void
    {
        $st = $this->store();
        $k = str_repeat('b', 32);
        self::assertTrue($st->transact($k, 'b', self::NOW, self::write('one'))['ok']);
        self::assertSame('one', $st->load($k)?->d['marker']);
        try {
            $st->transact($k, 'b', self::NOW, static function (?MintState $s, TokenMintTx $tx): TokenMintOutcome {
                $tx->insertCode('h1', 1, 1, [], '', self::NOW + 60);
                throw new \RuntimeException('bug');
            });
            self::fail('a non-store throwable propagates');
        } catch (\RuntimeException $e) {
            self::assertSame('bug', $e->getMessage());
        }
        self::assertSame('one', $st->load($k)?->d['marker']);
        self::assertNull($st->codeRow('h1'), 'the side write rolled back too');
        $r = $st->transact($k, 'b', self::NOW, self::write('two'));
        self::assertTrue($r['ok'], 'the connection is usable after a rollback');
    }

    /** @dataProvider failureModes */
    public function test_every_store_error_is_one_typed_failure_and_changes_nothing(string $mode): void
    {
        $k = str_repeat('c', 32);
        $seed = $this->store();
        self::assertTrue($seed->transact($k, 'c', self::NOW, self::write('before'))['ok']);
        $lock = null;
        $faults = null;
        $limits = [];
        if (in_array($mode, ['begin', 'load', 'write', 'commit'], true)) {
            $faults = static function (string $stage) use ($mode): void {
                if ($stage === $mode) {
                    throw new PDOException("injected {$stage}");
                }
            };
        }
        if ($mode === 'locked') {
            $lock = new PDO('sqlite:' . $this->dir . '/tm.sqlite');
            $lock->exec('BEGIN IMMEDIATE');
        }
        if ($mode === 'cap') {
            $limits = ['source_writes_hr' => 1];
        }
        $st = $mode === 'unopenable'
            ? new TokenMintStore($this->dir . '/none/' . str_repeat('x', 300) . '/tm.sqlite')
            : $this->store($limits, $faults);
        if ($mode === 'unopenable') {
            chmod($this->dir, 0500);
        }
        $t = hrtime(true);
        $r = $st->transact($k, 'c', self::NOW, self::write('after'));
        $ms = (hrtime(true) - $t) / 1e6;
        if ($mode === 'unopenable') {
            chmod($this->dir, 0700);
        }
        $lock?->exec('ROLLBACK');
        self::assertFalse($r['ok'], $mode);
        self::assertSame($mode === 'cap' ? TokenMintStore::FAIL_CAP : TokenMintStore::FAIL_STORE, $r['failure'], $mode);
        self::assertSame('before', $this->store()->load($k)?->d['marker'], "{$mode} left the row unchanged");
        if ($mode === 'locked') {
            self::assertGreaterThanOrEqual(90, $ms, 'it waited out the busy timeout');
            self::assertLessThan(2000, $ms);
        }
    }

    /** @return array<string,array{0:string}> */
    public static function failureModes(): array
    {
        return ['busy at begin' => ['locked'], 'begin' => ['begin'], 'statement' => ['load'], 'write' => ['write'], 'commit' => ['commit'], 'unopenable' => ['unopenable'], 'write cap' => ['cap']];
    }

    public function test_counter_only_writes_are_not_capped_and_units_accumulate_per_hour(): void
    {
        $st = $this->store(['source_writes_hr' => 1]);
        $k = str_repeat('d', 32);
        self::assertTrue($st->transact($k, 'd', self::NOW, self::write('a', true, 3))['ok']);
        self::assertSame(TokenMintStore::FAIL_CAP, $st->transact($k, 'd', self::NOW, self::write('b', true))['failure']);
        self::assertTrue($st->transact($k, 'd', self::NOW, self::write('c', false, 2))['ok'], 'a counter bump is not a state change');
        $seen = null;
        $st->transact($k, 'd', self::NOW, static function (?MintState $s, TokenMintTx $tx) use (&$seen): TokenMintOutcome {
            $seen = $tx->unitsUsed;

            return new TokenMintOutcome(null, false, 0, null);
        });
        self::assertSame(6, $seen, 'a: 3, the capped b: 1 (a refused write is still charged), c: 2');
        $st->transact($k, 'd', self::NOW + 3600, static function (?MintState $s, TokenMintTx $tx) use (&$seen): TokenMintOutcome {
            $seen = $tx->unitsUsed;

            return new TokenMintOutcome(null, false, 0, null);
        });
        self::assertSame(0, $seen, 'a new hour starts a new bucket');
    }

    public function test_a_write_refused_by_the_cap_still_charges_its_units_and_undoes_its_side_writes(): void
    {
        $st = $this->store(['source_writes_hr' => 1]);
        $k = str_repeat('f', 32);
        self::assertTrue($st->transact($k, 'f', self::NOW, self::write('a', true, 3))['ok']);
        $r = $st->transact($k, 'f', self::NOW, static function (?MintState $s, TokenMintTx $tx): TokenMintOutcome {
            $tx->insertCode(str_repeat('c', 64), 1, 1, ['read:user'], 'r', self::NOW + 600);
            $s = $s ?? MintState::fresh($tx->now, str_repeat('e', 16));
            $s->d['marker'] = 'refused';

            return new TokenMintOutcome($s, true, 4, null);
        });
        self::assertSame(TokenMintStore::FAIL_CAP, $r['failure']);
        self::assertSame('a', $st->load($k)?->d['marker'], 'the refused state change is undone');
        $seen = null;
        $st->transact($k, 'f', self::NOW, static function (?MintState $s, TokenMintTx $tx) use (&$seen): TokenMintOutcome {
            $seen = [$tx->unitsUsed, $tx->consumeCode(str_repeat('c', 64))];

            return new TokenMintOutcome(null, false, 0, null);
        });
        self::assertSame([7, null], $seen, 'its 4 units are charged and its code never existed');
    }

    public function test_global_write_cap_and_row_ttl_and_lru(): void
    {
        $st = $this->store(['global_writes_hr' => 3, 'rows' => 3, 'idle_s' => 100]);
        for ($i = 0; $i < 3; $i++) {
            self::assertTrue($st->transact(str_pad((string) $i, 32, 'k'), 'k', self::NOW + $i, self::write("r{$i}"))['ok']);
        }
        self::assertSame(TokenMintStore::FAIL_CAP, $st->transact(str_pad('9', 32, 'k'), 'k', self::NOW + 5, self::write('r9'))['failure'], 'the global gauge');
        $st2 = $this->store(['rows' => 3, 'idle_s' => 100]);
        self::assertTrue($st2->transact(str_pad('9', 32, 'k'), 'k', self::NOW + 3600, self::write('r9'))['ok']);
        $count = (int) $st2->db()->query('SELECT COUNT(*) FROM mint_state')->fetchColumn();
        self::assertLessThanOrEqual(3, $count);
        self::assertNull($st2->load(str_pad('0', 32, 'k')), 'idle rows expired');
    }

    public function test_codes_are_single_use_capped_per_account_and_pruned(): void
    {
        $st = $this->store(['codes_per_account' => 2, 'codes' => 5]);
        $k = str_repeat('e', 32);
        $st->transact($k, 'e', self::NOW, static function (?MintState $s, TokenMintTx $tx): TokenMintOutcome {
            foreach (['c1', 'c2', 'c3'] as $c) {
                $tx->insertCode($c, 7, 1, ['read:user'], '', self::NOW + 600);
            }

            return new TokenMintOutcome(MintState::fresh(self::NOW, 'ee'), true, 0, null);
        });
        self::assertNull($st->codeRow('c1'), 'the oldest live code gave way at the per-account cap');
        $first = $second = null;
        $st->transact($k, 'e', self::NOW, static function (?MintState $s, TokenMintTx $tx) use (&$first): TokenMintOutcome {
            $first = $tx->consumeCode('c2');

            return new TokenMintOutcome(null, false, 0, null);
        });
        $st->transact($k, 'e', self::NOW, static function (?MintState $s, TokenMintTx $tx) use (&$second): TokenMintOutcome {
            $second = $tx->consumeCode('c2');

            return new TokenMintOutcome(null, false, 0, null);
        });
        self::assertNotNull($first);
        self::assertNull($second, 'a code is consumed once');
        $late = 'unset';
        $st->transact($k, 'e', self::NOW + 601, static function (?MintState $s, TokenMintTx $tx) use (&$late): TokenMintOutcome {
            $late = $tx->consumeCode('c3');

            return new TokenMintOutcome(null, false, 0, null);
        });
        self::assertNull($late, 'an expired code is never consumed');
        $other = 'unset';
        $st->transact(str_repeat('f', 32), 'f', self::NOW, static function (?MintState $s, TokenMintTx $tx) use (&$other): TokenMintOutcome {
            $other = $tx->consumeCode('c3');

            return new TokenMintOutcome(null, false, 0, null);
        });
        self::assertNull($other, 'a code is consumed only on its own row');
    }

    public function test_turns_are_fifo_capped_and_pruned(): void
    {
        $st = $this->store(['turns' => 64, 'turns_ttl_s' => 1000]);
        for ($i = 0; $i < 200; $i++) {
            $st->attribute('ab', self::NOW + $i, ['route' => 'tokens', 'outcome' => 'x' . $i]);
        }
        $n = (int) $st->db()->query('SELECT COUNT(*) FROM mint_turns')->fetchColumn();
        self::assertLessThanOrEqual(64 + 63, $n, "turns stay near the cap ({$n})");
        $st->attribute('ab', self::NOW + 5000, ['route' => 'x']);
        for ($i = 0; $i < 64; $i++) {
            $st->attribute('ab', self::NOW + 5000, ['route' => 'x']);
        }
        self::assertSame(0, (int) $st->db()->query('SELECT COUNT(*) FROM mint_turns WHERE ts < ' . (self::NOW + 4000))->fetchColumn(), 'old turns pruned');
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\SsrfOutcome;
use Funnypot\App\Storage\SsrfStore;
use Funnypot\App\Storage\SsrfTx;
use Funnypot\App\Tarpit\Ssrf\SsrfState;
use PDOException;
use PHPUnit\Framework\TestCase;

final class SsrfStoreTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp0816store_' . bin2hex(random_bytes(5));
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->dir);
    }

    private function store(array $limits = [], ?object $faults = null): SsrfStore
    {
        return new SsrfStore($this->dir . '/ssrf.sqlite', $limits, $faults);
    }

    private static function write(SsrfStore $s, string $owner, string $source, int $now, int $units = 3, bool $change = true): array
    {
        return $s->transact($owner, $source, $now, static function (?SsrfState $st, SsrfTx $tx) use ($now, $units, $change): SsrfOutcome {
            $st ??= SsrfState::fresh($now);
            $st->d['hn'] = (int) $st->d['hn'] + 1;

            return new SsrfOutcome($st, $change, $units, $tx->unitsUsed);
        });
    }

    private function ledger(SsrfStore $s, string $source): array
    {
        $st = $s->db()->prepare('SELECT units, writes FROM ssrf_ledger WHERE s = :s');
        $st->execute([':s' => $source]);

        return $st->fetch(\PDO::FETCH_ASSOC) ?: [];
    }

    public function test_migrate_and_caps(): void
    {
        $s = $this->store(['source_writes_hr' => 3]);
        self::assertTrue($s->ready());
        for ($i = 0; $i < 3; $i++) {
            self::assertTrue(self::write($s, 'o1', 's1', 7200 + $i)['ok']);
        }
        $capped = self::write($s, 'o1', 's1', 7210);
        self::assertSame(SsrfStore::FAIL_CAP, $capped['failure']);
        self::assertSame(3, $s->load('o1')?->d['hn'], 'a capped write changes nothing');
        self::assertSame(['units' => 12, 'writes' => 3], $this->ledger($s, 's1'), 'a capped write is still charged');
        self::assertTrue(self::write($s, 'o1', 's1', 7210, 1, false)['ok'], 'a read that changes nothing still answers past the cap');
        self::assertTrue(self::write($s, 'o1', 's1', 10800)['ok'], 'the next hour is a new count');
        $g = $this->store(['global_writes_hr' => 2]);
        self::assertTrue(self::write($g, 'oa', 'sa', 100)['ok']);
        self::assertTrue(self::write($g, 'ob', 'sb', 100)['ok']);
        self::assertSame(SsrfStore::FAIL_CAP, self::write($g, 'oc', 'sc', 100)['failure'], 'the global gauge caps every source');
    }

    public function test_worst_case_row_fits_without_eviction(): void
    {
        $s = SsrfState::fresh(1);
        $url = 'http://' . str_repeat('a', 40) . '.example/' . str_repeat('p', SsrfState::MAX_URL - 60);
        $cr = ['k' => 'asia', 'h' => str_repeat('f', 24), 'f' => 'core_render', 'd' => 1795300000, 'x' => 604800, 'st' => 'mismatch', 'w' => 'userinfo'];
        $facts = ['o' => 'dns_transient', 'e' => 'private_other', 'k' => 'registry', 'n' => 'cd:' . str_repeat('h', SsrfState::MAX_HOST),
            'p' => 65535, 'pc' => 'verify', 'm' => 'DELETE', 'vd' => 'throttled'];
        for ($h = 0; $h < SsrfState::MAX_HOOKS; $h++) {
            $pos = $s->addHook(str_repeat('a', 11) . $h, $s->nextHookSerial(), 'form', str_repeat('S', 64), ['token', 'member', 'order', 'export'], true, ['url' => $url, 'cr' => $cr], 1);
            for ($v = 0; $v < 5; $v++) {
                $s->addVersion($pos, ['url' => $url, 'cr' => $cr], 2);
            }
            self::assertCount(SsrfState::MAX_VERSIONS, $s->d['h'][$pos]['u']);
            for ($d = 0; $d < 14; $d++) {
                $s->addDelivery($pos, ['id' => str_repeat('d', 12), 'c' => 1795300000, 'vi' => 99, 'ev' => 'export', 'rd' => 1, 'f' => $facts]);
            }
        }
        for ($i = 0; $i < 7; $i++) {
            $s->addImport(['id' => str_repeat('i', 12), 'n' => 999, 'k' => 'orders_json', 'url' => $url, 'cr' => $cr, 'c' => 1795300000, 'r' => 5, 'rs' => 1795300000, 'f' => $facts]);
        }
        $s->d['st'] = ['b' => str_repeat('b', 63), 'ak' => str_repeat('a', 24), 'sk' => str_repeat('s', 24), 'url' => $url, 'cr' => $cr, 'c' => 1795300000, 't' => 1795300000, 'v' => []];
        for ($i = 0; $i < 9; $i++) {
            $s->addVerification(['id' => str_repeat('v', 12), 'c' => 1795300000, 'u' => str_repeat('u', 120), 'f' => $facts]);
        }
        for ($i = 0; $i < 40; $i++) {
            $s->pushRate(1795300000 + $i);
        }
        $len = strlen($s->toJson());
        fwrite(STDERR, "\nworst-case SSRF row: {$len} bytes (cap " . SsrfState::ROW_CAP . ")\n");
        self::assertTrue($s->fits(), "worst case {$len} B fits the row cap");
        self::assertCount(SsrfState::MAX_HOOKS * SsrfState::MAX_DELIVERIES, array_merge(...array_map(static fn (array $h): array => $h['d'], $s->d['h'])));
        self::assertCount(SsrfState::MAX_IMPORTS, $s->d['i']);
        self::assertCount(SsrfState::MAX_VERIFICATIONS, $s->d['st']['v']);
        $store = $this->store();
        self::assertTrue($store->transact('o', 's', 5, static fn (?SsrfState $x, SsrfTx $tx): SsrfOutcome => new SsrfOutcome($s, true, 1, null))['ok']);
        self::assertSame($s->toJson(), $store->load('o')?->toJson());
    }

    public function test_ttl_and_lru(): void
    {
        $s = $this->store(['owners' => 3, 'ledgers' => 3]);
        foreach (['a', 'b', 'c'] as $i => $o) {
            self::write($s, $o, 's' . $o, 1000 + $i);
        }
        self::write($s, 'd', 'sd', 1003);
        self::assertNull($s->load('a'), 'the least recently seen account is evicted at the cap');
        self::assertNotNull($s->load('d'));
        self::write($s, 'e', 'se', 1003 + 86401);
        self::assertNull($s->load('b'), 'idle a day');
        self::assertNotNull($s->load('e'));
        self::assertLessThanOrEqual(3, (int) $s->db()->query('SELECT COUNT(*) FROM ssrf_ledger')->fetchColumn());
    }

    public function test_store_error_gives_typed_failure(): void
    {
        foreach (['begin', 'load', 'write', 'commit'] as $stage) {
            $faults = new class ($stage) {
                public bool $armed = false;

                public function __construct(private string $at)
                {
                }

                public function stage(string $s): void
                {
                    if ($this->armed && $s === $this->at) {
                        throw new PDOException('database is locked');
                    }
                }
            };
            $s = $this->store([], $faults);
            self::assertTrue(self::write($s, 'o-' . $stage, 's-' . $stage, 100)['ok']);
            $faults->armed = true;
            $r = self::write($s, 'o-' . $stage, 's-' . $stage, 101);
            self::assertFalse($r['ok'], $stage);
            self::assertSame(SsrfStore::FAIL_STORE, $r['failure'], $stage);
            $faults->armed = false;
            self::assertSame(1, $s->load('o-' . $stage)?->d['hn'], "{$stage}: nothing changed");
            self::assertSame(['units' => 3, 'writes' => 1], $this->ledger($s, 's-' . $stage), "{$stage}: units rolled back with the state");
        }
        $bad = new SsrfStore('/nonexistent-dir-' . bin2hex(random_bytes(3)) . '/x/y.sqlite');
        self::assertSame(SsrfStore::FAIL_STORE, @self::write($bad, 'o', 's', 1)['failure'], 'a store that will not open');
    }

    public function test_units_are_charged_in_the_state_transaction(): void
    {
        $faults = new class () {
            public bool $armed = false;

            public function stage(string $s): void
            {
                if ($this->armed && $s === 'commit') {
                    throw new PDOException('disk I/O error');
                }
            }
        };
        $s = $this->store([], $faults);
        self::write($s, 'o', 's', 100, 4);
        $faults->armed = true;
        self::assertFalse(self::write($s, 'o', 's', 101, 4)['ok']);
        self::assertSame(['units' => 4, 'writes' => 1], $this->ledger($s, 's'), 'a failed COMMIT leaves units and state both unchanged');
        self::assertSame(1, $s->load('o')?->d['hn']);
    }

    public function test_a_row_over_the_cap_is_refused_whole(): void
    {
        $s = $this->store();
        $r = $s->transact('o', 's', 1, static function (?SsrfState $x, SsrfTx $tx): SsrfOutcome {
            $st = SsrfState::fresh(1);
            $st->d['pad'] = str_repeat('x', SsrfState::ROW_CAP);

            return new SsrfOutcome($st, true, 1, null);
        });
        self::assertSame(SsrfStore::FAIL_STORE, $r['failure']);
        self::assertNull($s->load('o'));
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use Funnypot\App\Docker\PhantomStore;
use PHPUnit\Framework\TestCase;

/**
 * The bounded, TTL'd phantom-container record over its own docker.sqlite. It keeps NO real state and
 * runs nothing; it only remembers enough for create → start → inspect to cohere. Verifies the
 * addendum's MUST-FIX caps: a ~16-field spec is not silently dropped, the id list is one-record-per-id
 * (not an overflowing CSV), the started flag is a re-record (newest wins), and a non-UTF-8 field never
 * makes the record silently unwritable (201-then-404).
 */
final class PhantomStoreTest extends TestCase
{
    private const SEED = 7;
    private const IP = '9.9.9.9';

    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function store(?callable $clock = null, int $ttl = 3600): PhantomStore
    {
        $p = sys_get_temp_dir() . '/fpphantom_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return new PhantomStore($p, self::SEED, $clock, $ttl);
    }

    /** @return array<string,mixed> */
    private function spec(): array
    {
        return [
            'image' => 'alpine', 'command' => 'chroot /host sh', 'entrypoint' => ['/entry'],
            'cmd' => ['chroot', '/host', 'sh'], 'env' => ['A=1', 'B=2'], 'binds' => ['/:/host'],
            'mounts' => [['type' => 'bind', 'source' => '/etc', 'target' => '/e', 'read_only' => true]],
            'name' => 'sysupdate', 'created' => 1_700_000_000, 'user' => 'root', 'hostname' => 'h',
            'tty' => true, 'privileged' => true, 'pid_mode' => 'host', 'network_mode' => 'host',
        ];
    }

    public function test_full_spec_round_trips_no_field_dropped(): void
    {
        $s = $this->store();
        $s->createContainer(self::IP, 'id-abc', $this->spec());
        $got = $s->spec('id-abc');

        self::assertNotNull($got);
        self::assertSame('alpine', $got['image']);
        self::assertSame(['chroot', '/host', 'sh'], $got['cmd']);
        self::assertSame(['/entry'], $got['entrypoint']);
        self::assertSame(['A=1', 'B=2'], $got['env']);
        self::assertSame(['/:/host'], $got['binds']);
        self::assertSame('sysupdate', $got['name']);
        self::assertTrue($got['privileged']);
        self::assertTrue($got['tty']);
        self::assertSame('host', $got['pid_mode']);
        self::assertSame('host', $got['network_mode']);
        self::assertFalse($got['started'], 'a fresh container is not started');
    }

    public function test_started_flag_is_a_re_record_newest_wins(): void
    {
        $s = $this->store();
        $s->createContainer(self::IP, 'id-abc', $this->spec());
        self::assertFalse($s->spec('id-abc')['started']);

        self::assertTrue($s->markStarted('id-abc'), 'first start returns true');
        self::assertTrue($s->spec('id-abc')['started']);
        self::assertSame('alpine', $s->spec('id-abc')['image'], 'the rest of the spec survives the re-record');
        self::assertFalse($s->markStarted('id-abc'), 'a second start is a no-op (already running)');
        self::assertFalse($s->markStarted('unknown-id'), 'starting an unknown id is false');
    }

    public function test_id_list_holds_many_ids_without_a_csv_overflow(): void
    {
        $s = $this->store();
        $ids = [];
        for ($i = 0; $i < 8; $i++) {
            $id = str_repeat((string) $i, 64);   // 64-byte ids; a CSV of these would overflow a 500 B value
            $ids[] = $id;
            $s->createContainer(self::IP, $id, ['image' => 'a', 'command' => 'c', 'created' => 1_700_000_000]);
        }
        $stored = $s->phantomIds(self::IP);
        // newest-first, capped at the store's per-view 10; all fit as one-record-per-id.
        self::assertGreaterThanOrEqual(8, count($stored));
        foreach ($ids as $id) {
            self::assertContains($id, $stored);
        }
    }

    public function test_resolve_by_id_prefix_and_name(): void
    {
        $s = $this->store();
        $id = str_repeat('a', 64);
        $s->createContainer(self::IP, $id, ['image' => 'alpine', 'command' => 'c', 'name' => 'sysupdate', 'created' => 1]);
        self::assertSame($id, $s->resolve(self::IP, $id)['id']);
        self::assertSame($id, $s->resolve(self::IP, substr($id, 0, 12))['id']);
        self::assertSame($id, $s->resolve(self::IP, 'sysupdate')['id']);
        self::assertNull($s->resolve(self::IP, 'nope'));
        self::assertNull($s->resolve('other-ip', $id), 'another IP cannot resolve this phantom by id list');
    }

    public function test_pulled_and_hidden_are_deduped(): void
    {
        $s = $this->store();
        $s->recordPull(self::IP, 'docker.io/library/alpine:latest');
        $s->recordPull(self::IP, 'docker.io/library/alpine:latest');
        $s->recordPull(self::IP, 'docker.io/library/nginx:latest');
        self::assertCount(2, $s->pulled(self::IP));

        $s->hide(self::IP, 'vault-secret-store');
        $s->hide(self::IP, 'vault-secret-store');
        self::assertSame(['vault-secret-store'], $s->hidden(self::IP));
    }

    public function test_running_vs_created_filter(): void
    {
        $s = $this->store();
        $s->createContainer(self::IP, 'a', ['image' => 'x', 'command' => 'c', 'created' => 1]);
        $s->createContainer(self::IP, 'b', ['image' => 'x', 'command' => 'c', 'created' => 1]);
        $s->markStarted('a');
        self::assertCount(1, $s->phantoms(self::IP, true));
        self::assertCount(1, $s->phantoms(self::IP, false));
        self::assertCount(2, $s->phantoms(self::IP, null));
    }

    public function test_ttl_eviction(): void
    {
        $now = 1_700_000_000;
        $s = $this->store(static function () use (&$now): int {
            return $now;
        }, 3600);
        $s->createContainer(self::IP, 'id-abc', ['image' => 'x', 'command' => 'c', 'created' => $now]);
        self::assertNotNull($s->spec('id-abc'));
        $now += 3601;
        self::assertNull($s->spec('id-abc'), 'evaporated after the TTL');
        self::assertSame([], $s->phantomIds(self::IP));
    }

    public function test_non_utf8_field_is_scrubbed_not_dropped(): void
    {
        $s = $this->store();
        // A hostile non-UTF-8 image byte must not make the whole record unwritable (201 then 404).
        $s->createContainer(self::IP, 'id-bad', ['image' => "alp\xffine", 'command' => "c\xfe", 'created' => 1]);
        $got = $s->spec('id-bad');
        self::assertNotNull($got, 'the phantom must be readable back');
        self::assertStringContainsString('alp', $got['image']);
    }

    public function test_exec_record_round_trips(): void
    {
        $s = $this->store();
        $s->recordExec('exec-1', ['command' => 'id', 'user' => 'root', 'container' => 'cid']);
        $rec = $s->execRecord('exec-1');
        self::assertSame('id', $rec['command']);
        self::assertSame('cid', $rec['container']);
        self::assertNull($s->execRecord('missing'));
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\FakePersistenceStore;
use PHPUnit\Framework\TestCase;

/**
 * The bounded, TTL'd store behind the panel's fake persistence layer: a write-then-read round trip that
 * is scoped to one visitor (ip + persona seed + view), evaporates on its TTL, and cannot grow unbounded
 * (per-value length, per-view count, and global row caps). Everything is fail-open — a bad store never
 * throws, it just looks stateless.
 */
final class FakePersistenceStoreTest extends TestCase
{
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

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_bait_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    public function test_record_then_read_round_trips(): void
    {
        $store = new FakePersistenceStore($this->dbPath());
        $store->record('9.9.9.9', 7, 'hr/edit/emp-1', ['title' => 'Root', 'location' => 'HQ']);

        $items = $store->read('9.9.9.9', 7, 'hr/edit/emp-1');
        self::assertCount(1, $items);
        self::assertSame(['title' => 'Root', 'location' => 'HQ'], $items[0]);
    }

    public function test_read_is_scoped_by_ip(): void
    {
        $store = new FakePersistenceStore($this->dbPath());
        $store->record('1.1.1.1', 7, 'k', ['message' => 'mine']);

        self::assertNotEmpty($store->read('1.1.1.1', 7, 'k'));
        self::assertSame([], $store->read('2.2.2.2', 7, 'k'), 'another ip must never see it');
    }

    public function test_read_is_scoped_by_seed_and_view(): void
    {
        $store = new FakePersistenceStore($this->dbPath());
        $store->record('1.1.1.1', 7, 'k', ['message' => 'a']);

        self::assertSame([], $store->read('1.1.1.1', 8, 'k'), 'a different persona seed is a different tenant');
        self::assertSame([], $store->read('1.1.1.1', 7, 'other'), 'a different view key does not collide');
    }

    public function test_newest_is_returned_first(): void
    {
        $store = new FakePersistenceStore($this->dbPath());
        $store->record('1.1.1.1', 7, 'k', ['message' => 'first']);
        $store->record('1.1.1.1', 7, 'k', ['message' => 'second']);

        $items = $store->read('1.1.1.1', 7, 'k');
        self::assertSame('second', $items[0]['message']);
    }

    public function test_ttl_expires_the_submission(): void
    {
        $now = 1000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $store = new FakePersistenceStore($this->dbPath(), $clock, 100);
        $store->record('1.1.1.1', 7, 'k', ['message' => 'x']);

        $now = 1050;
        self::assertNotEmpty($store->read('1.1.1.1', 7, 'k'), 'still within the TTL');

        $now = 1200;
        self::assertSame([], $store->read('1.1.1.1', 7, 'k'), 'gone after the TTL');
    }

    public function test_value_length_is_capped(): void
    {
        $store = new FakePersistenceStore($this->dbPath());
        $store->record('1.1.1.1', 7, 'k', ['message' => str_repeat('A', 5000)]);

        $items = $store->read('1.1.1.1', 7, 'k');
        self::assertLessThanOrEqual(500, strlen($items[0]['message']));
    }

    public function test_field_count_is_capped(): void
    {
        $fields = [];
        for ($i = 0; $i < 20; $i++) {
            $fields['f' . $i] = 'v' . $i;
        }
        $store = new FakePersistenceStore($this->dbPath());
        $store->record('1.1.1.1', 7, 'k', $fields);

        self::assertLessThanOrEqual(8, count($store->read('1.1.1.1', 7, 'k')[0]));
    }

    public function test_per_view_item_count_is_capped_to_newest(): void
    {
        $store = new FakePersistenceStore($this->dbPath());
        for ($i = 0; $i < 25; $i++) {
            $store->record('1.1.1.1', 7, 'k', ['message' => 'm' . $i]);
        }

        $items = $store->read('1.1.1.1', 7, 'k');
        self::assertLessThanOrEqual(10, count($items), 'over-cap items are pruned');
        self::assertSame('m24', $items[0]['message'], 'the newest survives');
        $messages = array_column($items, 'message');
        self::assertNotContains('m0', $messages, 'the oldest is gone');
    }

    public function test_empty_or_blank_fields_are_a_noop(): void
    {
        $store = new FakePersistenceStore($this->dbPath());
        $store->record('1.1.1.1', 7, 'k', []);
        $store->record('1.1.1.1', 7, 'k', ['message' => '']);

        self::assertSame([], $store->read('1.1.1.1', 7, 'k'));
    }

    public function test_read_fails_open_on_an_unusable_path(): void
    {
        // A path whose parent cannot be created (a file used as a directory) must not throw.
        $file = $this->dbPath();
        file_put_contents($file, 'x');
        $store = new FakePersistenceStore($file . '/nested.sqlite');

        $store->record('1.1.1.1', 7, 'k', ['message' => 'x']);   // no throw
        self::assertSame([], $store->read('1.1.1.1', 7, 'k'));    // fail-open
    }
}

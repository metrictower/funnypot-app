<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Panel\FakePersistence;
use Funnypot\App\Storage\FakePersistenceStore;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The request-scoped facade that maps a panel write endpoint to the view key both the capture side and
 * the echoing section share, and pulls only the endpoint's whitelisted fields out of the POST body.
 */
final class FakePersistenceTest extends TestCase
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

    private function store(): FakePersistenceStore
    {
        $p = sys_get_temp_dir() . '/fp_facade_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return new FakePersistenceStore($p);
    }

    private function post(string $path, string $body): RequestContext
    {
        return new RequestContext('POST', $path, '', [], $body);
    }

    public function test_signage_message_write_is_captured_and_echoed_to_the_same_view(): void
    {
        $fp = new FakePersistence($this->store(), '9.9.9.9', 7);
        $fp->capture($this->post('/admin/appliances/signage/all/message', 'message=EVACUATE+NOW'));

        $items = $fp->items(FakePersistence::signageMessageKey('all'));
        self::assertSame('EVACUATE NOW', $items[0]['message'] ?? null);
    }

    public function test_hr_edit_write_captures_whitelisted_fields_only(): void
    {
        $fp = new FakePersistence($this->store(), '9.9.9.9', 7);
        // `pin` is not a whitelisted field for this endpoint (E6: access codes are never reflected).
        $fp->capture($this->post('/admin/hr/employees/emp-1001/edit/saved', 'title=CISO&location=Vault&pin=1234'));

        $item = $fp->items(FakePersistence::hrEditKey('emp-1001'))[0] ?? [];
        self::assertSame('CISO', $item['title'] ?? null);
        self::assertSame('Vault', $item['location'] ?? null);
        self::assertArrayNotHasKey('pin', $item, 'a non-whitelisted field must never be captured');
    }

    public function test_a_get_is_never_captured(): void
    {
        $store = $this->store();
        $fp = new FakePersistence($store, '9.9.9.9', 7);
        $fp->capture(new RequestContext('GET', '/admin/appliances/signage/all/message'));

        self::assertSame([], $fp->items(FakePersistence::signageMessageKey('all')));
    }

    public function test_raw_payload_is_stored_unescaped_escaping_is_the_renderers_job(): void
    {
        $fp = new FakePersistence($this->store(), '9.9.9.9', 7);
        $fp->capture($this->post('/admin/appliances/signage/all/message', 'message=' . rawurlencode('"><script>alert(1)</script>')));

        // The store keeps the raw text; the section escapes it at render time.
        self::assertSame('"><script>alert(1)</script>', $fp->items(FakePersistence::signageMessageKey('all'))[0]['message']);
    }

    public function test_is_persistable_path_matches_only_the_write_and_read_views(): void
    {
        self::assertTrue(FakePersistence::isPersistablePath('/admin/appliances/signage/all/message'));
        self::assertTrue(FakePersistence::isPersistablePath('/admin/hr/employees/emp-1001/edit/saved'));
        self::assertTrue(FakePersistence::isPersistablePath('/admin/hr/employees/emp-1001/edit'));

        self::assertFalse(FakePersistence::isPersistablePath('/admin/appliances/signage/all'), 'the list/detail views are not persistable');
        self::assertFalse(FakePersistence::isPersistablePath('/admin/hr/employees/emp-1001'), 'the plain profile is not persistable');
        self::assertFalse(FakePersistence::isPersistablePath('/admin/hvac'));
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\WebDav;

use Funnypot\App\Storage\WriteCaptureStore;
use Funnypot\App\WebDav\WebDavTrap;
use Funnypot\Core\RequestContext;
use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use PHPUnit\Framework\TestCase;

/**
 * FP-0200 (core slice): the WebDAV honeypot at /webdav/. OPTIONS advertises DAV; PUT drops a file into the
 * bounded capture store; GET fetches it back; PROPFIND lists the source's own drops; DELETE/MKCOL succeed;
 * a non-/webdav path is not claimed. Per-source isolated, inert.
 */
final class WebDavTrapTest extends TestCase
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
            @rmdir(\dirname($f));
        }
    }

    private function trap(): WebDavTrap
    {
        $path = sys_get_temp_dir() . '/fp0200-' . bin2hex(random_bytes(6)) . '/wc.sqlite';
        $this->tmp[] = $path;

        return new WebDavTrap(new WriteCaptureStore($path));
    }

    private function trapWithFs(): WebDavTrap
    {
        $path = sys_get_temp_dir() . '/fp0200fs-' . bin2hex(random_bytes(6)) . '/wc.sqlite';
        $this->tmp[] = $path;
        $fs = new FakeFilesystem(Draw::seed("webdav-test\0ops"), 'ops', 4242);

        return new WebDavTrap(new WriteCaptureStore($path), $fs);
    }

    private function req(string $method, string $path, string $body = '', array $headers = []): RequestContext
    {
        return new RequestContext($method, $path, '', $headers, $body === '' ? null : $body, 'x.test');
    }

    public function test_propfind_lists_the_fake_filesystem_tree(): void
    {
        $r = $this->trapWithFs()->handle($this->req('PROPFIND', '/webdav/', '', ['Depth' => '1']), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(207, $r->status);
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($r->body);
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc, 'valid multistatus');
        $doc->registerXPathNamespace('D', 'DAV:');
        self::assertGreaterThan(1, count($doc->xpath('//D:response')), 'the FS root contributes children beyond the collection itself');
    }

    public function test_dropped_file_still_wins_over_the_fake_fs(): void
    {
        $t = $this->trapWithFs();
        $t->handle($this->req('PUT', '/webdav/mine.txt', 'my bytes'), '10.0.0.1');
        self::assertSame('my bytes', $t->handle($this->req('GET', '/webdav/mine.txt'), '10.0.0.1')->body);
    }

    public function test_deterministic_fs_read_is_stable(): void
    {
        // The fake FS is deterministic: the same seed lists the same root both times.
        $a = $this->trapWithFs();
        $r1 = $a->handle($this->req('PROPFIND', '/webdav/', '', ['Depth' => '1']), '10.0.0.1');
        $b = $this->trapWithFs();
        $r2 = $b->handle($this->req('PROPFIND', '/webdav/', '', ['Depth' => '1']), '10.0.0.1');
        self::assertSame($r1->body, $r2->body, 'same seed -> identical listing');
    }

    public function test_options_advertises_dav(): void
    {
        $r = $this->trap()->handle($this->req('OPTIONS', '/webdav/'), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('1, 2', $r->headers['DAV'] ?? '');
        self::assertStringContainsString('PROPFIND', $r->headers['Allow'] ?? '');
    }

    public function test_non_webdav_path_is_not_claimed(): void
    {
        self::assertNull($this->trap()->handle($this->req('PROPFIND', '/wp-admin/'), '10.0.0.1'));
        self::assertNull($this->trap()->handle($this->req('GET', '/index.php'), '10.0.0.1'));
    }

    public function test_put_then_get_roundtrips(): void
    {
        $t = $this->trap();
        $put = $t->handle($this->req('PUT', '/webdav/notes.txt', 'hello dav'), '10.0.0.1');
        self::assertNotNull($put);
        self::assertSame(201, $put->status);
        $get = $t->handle($this->req('GET', '/webdav/notes.txt'), '10.0.0.1');
        self::assertNotNull($get);
        self::assertSame(200, $get->status);
        self::assertSame('hello dav', $get->body);
    }

    public function test_put_then_propfind_lists_the_file(): void
    {
        $t = $this->trap();
        $t->handle($this->req('PUT', '/webdav/shell.php', '<?php echo 1;?>'), '10.0.0.1');
        $r = $t->handle($this->req('PROPFIND', '/webdav/', '', ['Depth' => '1']), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(207, $r->status);
        self::assertStringContainsString('/webdav/shell.php', $r->body, 'the dropped file is listed');
        // valid multistatus
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($r->body);
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc);
    }

    public function test_propfind_is_isolated_per_source(): void
    {
        $t = $this->trap();
        $t->handle($this->req('PUT', '/webdav/secret.txt', 'x'), '10.0.0.1');
        $r = $t->handle($this->req('PROPFIND', '/webdav/', '', ['Depth' => '1']), '10.0.0.2');
        self::assertNotNull($r);
        self::assertStringNotContainsString('secret.txt', $r->body, 'a different source must not see the drop');
    }

    public function test_get_missing_is_404(): void
    {
        $r = $this->trap()->handle($this->req('GET', '/webdav/nope.txt'), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(404, $r->status);
    }

    public function test_delete_and_mkcol_succeed(): void
    {
        $t = $this->trap();
        self::assertSame(204, $t->handle($this->req('DELETE', '/webdav/x.txt'), '10.0.0.1')->status);
        self::assertSame(201, $t->handle($this->req('MKCOL', '/webdav/newdir/'), '10.0.0.1')->status);
    }

    public function test_lock_returns_a_token(): void
    {
        $r = $this->trap()->handle($this->req('LOCK', '/webdav/x.txt'), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('opaquelocktoken:', $r->headers['Lock-Token'] ?? '');
    }

    public function test_move_relocates_a_captured_file(): void
    {
        $t = $this->trap();
        $t->handle($this->req('PUT', '/webdav/a.txt', 'payload'), '10.0.0.1');
        $mv = $t->handle($this->req('MOVE', '/webdav/a.txt', '', ['Destination' => 'http://x.test/webdav/b.txt']), '10.0.0.1');
        self::assertNotNull($mv);
        self::assertContains($mv->status, [201, 204]);
        self::assertSame('payload', $t->handle($this->req('GET', '/webdav/b.txt'), '10.0.0.1')->body, 'dest has the content');
        self::assertSame(404, $t->handle($this->req('GET', '/webdav/a.txt'), '10.0.0.1')->status, 'src is gone after MOVE');
    }

    public function test_copy_duplicates_a_captured_file(): void
    {
        $t = $this->trap();
        $t->handle($this->req('PUT', '/webdav/a.txt', 'dup'), '10.0.0.1');
        $t->handle($this->req('COPY', '/webdav/a.txt', '', ['Destination' => '/webdav/c.txt']), '10.0.0.1');
        self::assertSame('dup', $t->handle($this->req('GET', '/webdav/c.txt'), '10.0.0.1')->body);
        self::assertSame('dup', $t->handle($this->req('GET', '/webdav/a.txt'), '10.0.0.1')->body, 'src still present after COPY');
    }

    public function test_move_missing_source_is_404(): void
    {
        $r = $this->trap()->handle($this->req('MOVE', '/webdav/nope.txt', '', ['Destination' => '/webdav/x.txt']), '10.0.0.1');
        self::assertSame(404, $r->status);
    }

    public function test_move_without_destination_is_400(): void
    {
        $t = $this->trap();
        $t->handle($this->req('PUT', '/webdav/a.txt', 'x'), '10.0.0.1');
        self::assertSame(400, $t->handle($this->req('MOVE', '/webdav/a.txt'), '10.0.0.1')->status);
    }

    public function test_proppatch_pretends_success(): void
    {
        $r = $this->trap()->handle($this->req('PROPPATCH', '/webdav/a.txt', '<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><Z:x xmlns:Z="z:">1</Z:x></D:prop></D:set></D:propertyupdate>'), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(207, $r->status);
        self::assertStringContainsString('HTTP/1.1 200 OK', $r->body);
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($r->body);
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc);
    }

    public function test_propfind_depth_0_returns_only_the_collection(): void
    {
        $t = $this->trap();
        $t->handle($this->req('PUT', '/webdav/a.txt', 'x'), '10.0.0.1');
        $r = $t->handle($this->req('PROPFIND', '/webdav/', '', ['Depth' => '0']), '10.0.0.1');
        self::assertNotNull($r);
        self::assertStringNotContainsString('a.txt', $r->body, 'depth 0 lists only the requested collection');
    }
}

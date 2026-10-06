<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\WriteCaptureStore;
use Funnypot\App\Storage\WriteCaptureTrap;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * FP-0467 phase 2b/3: the capture/verify trap over WriteCaptureStore + WriteRedirectExtractor. A write
 * stager is captured keyed by an opaque source scope and the webroot-relative URL path; a later GET to
 * that URL path for the same source serves the stored sentinel. GET/HEAD only; per-source isolated;
 * non-write requests are a no-op.
 */
final class WriteCaptureTrapTest extends TestCase
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

    private function trap(): WriteCaptureTrap
    {
        $path = sys_get_temp_dir() . '/fp0467t-' . bin2hex(random_bytes(6)) . '/wc.sqlite';
        $this->tmp[] = $path;

        return new WriteCaptureTrap(new WriteCaptureStore($path));
    }

    private function ctx(string $method, string $path, string $query = '', ?string $body = null): RequestContext
    {
        return new RequestContext($method, $path, $query, [], $body, 'x.test');
    }

    public function test_scope_is_opaque_and_never_the_raw_ip(): void
    {
        $t = $this->trap();
        $scope = $t->scopeFor('203.0.113.7');
        self::assertStringNotContainsString('203.0.113.7', $scope);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $scope);
        self::assertNotSame($t->scopeFor('203.0.113.7'), $t->scopeFor('203.0.113.8'), 'distinct IPs → distinct scopes');
    }

    /** @dataProvider webrootPaths */
    public function test_url_path_maps_webroot_fs_path(string $fsPath, string $expected): void
    {
        self::assertSame($expected, $this->trap()->urlPathFor($fsPath));
    }

    /** @return array<string,array{0:string,1:string}> */
    public function webrootPaths(): array
    {
        return [
            'var-www-html' => ['/var/www/html/out.txt', '/out.txt'],
            'nginx'        => ['/usr/share/nginx/html/a/b.php', '/a/b.php'],
            'nested'       => ['/var/www/html/uploads/x.txt', '/uploads/x.txt'],
            'dotdot'       => ['/var/www/html/../html/c.txt', '/c.txt'],
            'relative'     => ['./verify.html', '/verify.html'],
            'outside'      => ['/tmp/x.sh', '/tmp/x.sh'],
        ];
    }

    public function test_capture_then_verify_serves_the_sentinel(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'cmd=' . rawurlencode('echo VULN_9f3 > /var/www/html/out.txt')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/out.txt'), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('VULN_9f3', $r->body);
        self::assertStringContainsString('text/plain', $r->headers['Content-Type']);
    }

    public function test_verify_is_isolated_per_source(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('GET', '/x', 'c=' . rawurlencode('echo A > /var/www/html/out.txt')), '10.0.0.1');
        self::assertNull($t->maybeServe($this->ctx('GET', '/out.txt'), '10.0.0.2'), 'a different source must not read the capture');
        self::assertNotNull($t->maybeServe($this->ctx('GET', '/out.txt'), '10.0.0.1'));
    }

    public function test_serve_is_get_or_head_only(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('GET', '/x', 'c=' . rawurlencode('echo A > /var/www/html/out.txt')), '10.0.0.1');
        self::assertNull($t->maybeServe($this->ctx('POST', '/out.txt'), '10.0.0.1'), 'a verify fetch is never a POST');
        $head = $t->maybeServe($this->ctx('HEAD', '/out.txt'), '10.0.0.1');
        self::assertNotNull($head);
        self::assertSame('', $head->body, 'HEAD carries no body');
    }

    public function test_php_drop_served_as_html(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo "<?php echo 1;?>" > /var/www/html/s.php')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/s.php'), '10.0.0.1');
        self::assertNotNull($r);
        self::assertStringContainsString('text/html', $r->headers['Content-Type']);
        self::assertStringContainsString('<?php echo 1;?>', $r->body);
    }

    public function test_non_write_request_is_a_noop(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('GET', '/search', 'q=' . rawurlencode('hello world')), '10.0.0.1');
        self::assertNull($t->maybeServe($this->ctx('GET', '/search'), '10.0.0.1'));
        self::assertNull($t->maybeServe($this->ctx('GET', '/anything.txt'), '10.0.0.1'));
    }

    public function test_dynamic_write_without_literal_is_not_captured(): void
    {
        // `id > rce.txt` has no static content — not captured (a verify GET 404s / returns null here).
        $t = $this->trap();
        $t->maybeCapture($this->ctx('GET', '/x', 'c=' . rawurlencode('id > /var/www/html/rce.txt')), '10.0.0.1');
        self::assertNull($t->maybeServe($this->ctx('GET', '/rce.txt'), '10.0.0.1'));
    }
}

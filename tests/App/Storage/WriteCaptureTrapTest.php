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

    // --- FP-0149: dropped-webshell execution-failure emulation -------------------------------------

    public function test_captured_php_with_a_command_serves_an_exec_failure_not_the_source(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo "<?php system($_GET[0]);?>" > /var/www/html/s.php')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/s.php', 'cmd=' . rawurlencode('id')), '10.0.0.1');
        self::assertNotNull($r);
        self::assertStringContainsString('has been disabled for security reasons', $r->body, 'a command attempt gets a disabled_functions failure');
        self::assertStringContainsString('/var/www/html/s.php', $r->body, 'the warning names the filesystem path');
        self::assertStringNotContainsString('<?php system', $r->body, 'the captured source is NOT served on an exec attempt');
    }

    public function test_named_exec_function_is_reported_in_the_warning(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo x > /var/www/html/s.php')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/s.php', 'x=' . rawurlencode('passthru(whoami)')), '10.0.0.1');
        self::assertNotNull($r);
        self::assertStringContainsString('passthru() has been disabled', $r->body, 'the attempted function is named (from the fixed set)');
    }

    public function test_warning_blames_the_function_the_dropped_shell_itself_calls(): void
    {
        // The shell's own source calls passthru(); a generic `cmd=` attempt (no named function) must
        // still blame passthru(), coherent with the attacker's planted code — not the default system().
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo "<?php passthru($_GET[0]);?>" > /var/www/html/s.php')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/s.php', 'cmd=' . rawurlencode('id')), '10.0.0.1');
        self::assertNotNull($r);
        self::assertStringContainsString('passthru() has been disabled', $r->body);
        self::assertStringNotContainsString('system() has been disabled', $r->body);
    }

    public function test_exec_failure_content_type_matches_the_bare_view(): void
    {
        // Same resource must not change Content-Type depending on whether a param is present.
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo "<?php system($_GET[0]);?>" > /var/www/html/s.php')), '10.0.0.1');
        $view = $t->maybeServe($this->ctx('GET', '/s.php'), '10.0.0.1');
        $exec = $t->maybeServe($this->ctx('GET', '/s.php', 'cmd=id'), '10.0.0.1');
        self::assertNotNull($view);
        self::assertNotNull($exec);
        self::assertSame($view->headers['Content-Type'], $exec->headers['Content-Type'], 'no Content-Type flip between view and exec');
    }

    public function test_captured_php_bare_view_still_returns_the_source(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo "<?php echo 1;?>" > /var/www/html/s.php')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/s.php'), '10.0.0.1'); // no query = a view, not a command
        self::assertNotNull($r);
        self::assertStringContainsString('<?php echo 1;?>', $r->body, 'a bare view returns the stored source');
        self::assertStringNotContainsString('disabled for security', $r->body);
    }

    public function test_exec_failure_does_not_reflect_the_submitted_command(): void
    {
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo x > /var/www/html/s.php')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/s.php', 'cmd=' . rawurlencode('system(cat /etc/CANARY)')), '10.0.0.1');
        self::assertNotNull($r);
        self::assertStringNotContainsString('CANARY', $r->body, 'the submitted command is never echoed');
    }

    public function test_non_php_captured_file_with_a_query_still_serves_content(): void
    {
        // The exec-failure is php-only; a .txt with a query is not an "execution" attempt.
        $t = $this->trap();
        $t->maybeCapture($this->ctx('POST', '/api', '', 'c=' . rawurlencode('echo TAG > /var/www/html/out.txt')), '10.0.0.1');
        $r = $t->maybeServe($this->ctx('GET', '/out.txt', 'x=1'), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame('TAG', $r->body);
    }

    public function test_dynamic_write_without_literal_is_not_captured(): void
    {
        // `id > rce.txt` has no static content — not captured (a verify GET 404s / returns null here).
        $t = $this->trap();
        $t->maybeCapture($this->ctx('GET', '/x', 'c=' . rawurlencode('id > /var/www/html/rce.txt')), '10.0.0.1');
        self::assertNull($t->maybeServe($this->ctx('GET', '/rce.txt'), '10.0.0.1'));
    }
}

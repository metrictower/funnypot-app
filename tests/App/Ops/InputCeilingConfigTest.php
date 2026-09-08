<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Ops;

use Funnypot\App\Http\EarlyIngressGuard;
use PHPUnit\Framework\TestCase;

/** Source/byte parity only. Real nginx parser/headers/timeout acceptance runs in the image job. */
final class InputCeilingConfigTest extends TestCase
{
    private function read(string $path): string
    {
        return (string) file_get_contents(dirname(__DIR__, 3) . '/' . $path);
    }

    private function block(string $header): string
    {
        self::assertSame(1, preg_match('/^' . preg_quote($header, '/') . ' \{\n(.*?)\n\}/ms',
            $this->read('demo/funnypot-location.conf'), $match));
        return $match[1];
    }

    public function test_raw_request_map_counts_origin_absolute_and_repeated_method_spaces(): void
    {
        $nginx = $this->read('demo/nginx.conf');
        self::assertSame(1, preg_match('/map \$request \$funnypot_target_overlong \{\s+default 0;\s+"~([^"]+)" 1;\s+\}/', $nginx, $match));
        self::assertSame('^[^ ]+ +[^ ]{4097}', $match[1]);
        self::assertLessThan(strpos($nginx, 'server {'), strpos($nginx, 'map $request'));
        foreach ([1, 2, 16] as $spaces) {
            foreach ([4095, 4096, 4097] as $bytes) {
                foreach ([str_pad('/.env?', $bytes, 'q'), 'http://' . str_repeat('a', $bytes - 9) . '/x'] as $target) {
                    self::assertSame($bytes, strlen($target));
                    $result = preg_match('~' . $match[1] . '~', 'GET' . str_repeat(' ', $spaces) . $target . ' HTTP/1.1');
                    $error = preg_last_error();
                    self::assertSame(PREG_NO_ERROR, $error);
                    self::assertSame((int) !EarlyIngressGuard::accepts($target), $result);
                }
            }
        }
    }

    public function test_all_vhosts_share_server_rewrite_admission_before_static_and_fastcgi(): void
    {
        $nginx = $this->read('demo/nginx.conf');
        self::assertSame(2, preg_match_all('/^server \{.*?^\}/ms', $nginx, $servers));
        foreach ($servers[0] as $server) {
            self::assertSame(1, substr_count($server, 'include /etc/nginx/funnypot-location.conf;'));
            self::assertStringContainsString('access_log off;', $server);
        }
        $producer = $this->read('src/App/Identity/IdentityPreparer.php');
        self::assertStringContainsString('include /etc/nginx/funnypot-location.conf;', $producer, 'rendered admin TLS vhost');
        $shared = $this->read('demo/funnypot-location.conf');
        self::assertStringContainsString("if (\$funnypot_target_overlong) {\n    return 414;\n}", $shared);
        self::assertLessThan(strpos($shared, 'location @'), strpos($shared, 'if ($funnypot_target_overlong)'));
        self::assertStringContainsString('error_page 414 = @funnypot_target_rejected;', $shared);
        foreach (['client_header_buffer_size 1k;', 'large_client_header_buffers 4 8k;',
            'client_header_timeout 5s;', 'client_max_body_size 1m;', 'error_log /dev/null emerg;'] as $directive) {
            self::assertSame(1, substr_count($shared, $directive));
            self::assertStringNotContainsString($directive, $nginx, 'one shared source, not per-vhost copies');
        }
        self::assertStringNotContainsString('error_log /dev/null', $nginx, 'global startup diagnostics remain');
        $docker = $this->read('demo/Dockerfile');
        self::assertMatchesRegularExpression('~COPY demo/nginx\.conf\s+/etc/nginx/http\.d/default\.conf~', $docker);
        self::assertMatchesRegularExpression('~COPY demo/funnypot-location\.conf\s+/etc/nginx/funnypot-location\.conf~', $docker);
    }

    public function test_edge_and_dependency_free_php_reject_envelopes_are_byte_identical_and_clean(): void
    {
        $index = $this->read('demo/index.php');
        self::assertSame(1, preg_match('/\$funnypot414 = static function.*?\n};/s', $index, $php));
        $edge = $this->block('location @funnypot_target_rejected');
        self::assertSame(1, preg_match('/echo \'([^\']+)\';/', $php[0], $body));
        self::assertSame(1, preg_match('/return 414 "([^"]+)";/', $edge, $nginx));
        self::assertSame($body[1], $nginx[1]);
        self::assertLessThanOrEqual(128, strlen($body[1]));
        self::assertStringContainsString('http_response_code(414);', $php[0]);
        self::assertStringContainsString("header('Content-Type: text/html; charset=UTF-8');", $php[0]);
        self::assertStringContainsString('default_type "text/html; charset=UTF-8";', $edge);
        self::assertStringContainsString("header('Cache-Control: no-store');", $php[0]);
        self::assertStringContainsString('add_header Cache-Control no-store always;', $edge);
        self::assertStringContainsString("header('Connection: close');", $php[0]);
        self::assertStringContainsString('keepalive_timeout 0;', $edge, 'nginx emits one Connection header itself');
        self::assertStringContainsString('types { }', $edge);
        self::assertStringNotContainsString('add_header Connection', $edge, 'avoid duplicate Connection fields');
        self::assertLessThan(strpos($index, "require __DIR__ . '/lib/geo.php'"), strpos($index, 'EarlyIngressGuard::accepts('));
        self::assertLessThan(strpos($index, '$configStore = new'), strpos($index, 'EarlyIngressGuard::accepts('));
        $deny = require dirname(__DIR__, 3) . '/resources/app-fingerprint-denylist.php';
        foreach ($deny['literals'] ?? [] as $literal) {
            if ($literal !== '') {
                self::assertStringNotContainsStringIgnoringCase($literal, $body[1]);
            }
        }
        foreach ($deny['patterns'] ?? [] as $pattern) {
            self::assertSame(0, preg_match('~' . $pattern . '~i', $body[1]));
        }
        foreach ($deny['own_vocabulary'] ?? [] as $word) {
            self::assertSame(0, preg_match('~(?<![a-z0-9])' . preg_quote($word, '~') . '(?![a-z0-9])~i', $body[1]));
        }
    }

    public function test_static_408_is_generic_not_a_claim_about_partial_header_wire_behavior(): void
    {
        $edge = $this->block('location @funnypot_header_timeout');
        self::assertStringContainsString('default_type "text/plain; charset=utf-8";', $edge);
        self::assertStringContainsString('keepalive_timeout 0;', $edge);
        self::assertStringContainsString('add_header Cache-Control no-store always;', $edge);
        self::assertStringContainsString('return 408 "Request Timeout\\n";', $edge);
        self::assertStringContainsString('error_page 408 = @funnypot_header_timeout;', $this->read('demo/funnypot-location.conf'));
    }
}

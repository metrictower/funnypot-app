<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Ops;

use Funnypot\App\Http\DownloadRouter;
use PHPUnit\Framework\TestCase;

/**
 * The nginx envelope around the gate-exempt download bait, pinned: the three zones exist, the /__dl/
 * location applies conservative concurrency/rate/spool bounds (the global concurrency cap leaves at
 * least three quarters of the fpm pool to the deception), it reaches the same front controller as
 * `location /` with identical FastCGI wiring, and a throttled request gets a controlled 429 whose
 * body passes the fingerprint denylist rather than nginx's stock page.
 */
final class DownloadLimitsConfigTest extends TestCase
{
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }

    private static function block(string $conf, string $header): string
    {
        self::assertSame(1, preg_match('/^' . preg_quote($header, '/') . ' \{\n(.*?)\n\}/ms', $conf, $m), "block '{$header}' present");

        return $m[1];
    }

    /** @return list<string> the directive lines of a block, trimmed, comments dropped */
    private static function directives(string $block): array
    {
        $out = [];
        foreach (explode("\n", $block) as $line) {
            $line = trim((string) preg_replace('/#.*$/', '', $line));
            if ($line !== '') {
                $out[] = $line;
            }
        }

        return $out;
    }

    public function test_zones_are_declared_in_http_context(): void
    {
        $nginx = (string) file_get_contents(self::root() . '/demo/nginx.conf');
        self::assertMatchesRegularExpression('/^limit_conn_zone \$binary_remote_addr zone=funnypot_dl_ip:\d+m;$/m', $nginx, 'per-source connection zone');
        self::assertMatchesRegularExpression('/^limit_conn_zone \S+ zone=funnypot_dl_all:\d+m;$/m', $nginx, 'global connection zone');
        self::assertDoesNotMatchRegularExpression('/^limit_conn_zone \$binary_remote_addr zone=funnypot_dl_all/m', $nginx, 'the global zone is keyed by a constant, not the client');
        self::assertMatchesRegularExpression('/^limit_req_zone \$binary_remote_addr zone=funnypot_dl_req:\d+m rate=6r\/m;$/m', $nginx, '6 starts per minute per source');
        // http-context directives sit outside every server block.
        self::assertLessThan(strpos($nginx, 'server {'), strpos($nginx, 'limit_conn_zone'));
    }

    public function test_download_location_bounds_workers_disk_and_egress(): void
    {
        $conf = (string) file_get_contents(self::root() . '/demo/funnypot-location.conf');
        $dl = self::directives(self::block($conf, 'location ^~ /__dl/'));

        self::assertContains('limit_conn funnypot_dl_ip 2;', $dl);
        self::assertContains('limit_conn funnypot_dl_all 4;', $dl);
        self::assertContains('limit_req zone=funnypot_dl_req burst=3 nodelay;', $dl);
        self::assertContains('limit_conn_status 429;', $dl);
        self::assertContains('limit_req_status 429;', $dl);
        self::assertContains('limit_rate 2m;', $dl);
        self::assertContains('fastcgi_max_temp_file_size 4m;', $dl);
        self::assertContains('error_page 429 = @funnypot_dl_throttled;', $dl);

        // The global cap never takes more than a quarter of the pool from the deception.
        $pool = (string) file_get_contents(self::root() . '/demo/fpm-pool.conf');
        self::assertSame(1, preg_match('/^pm\.max_children\s*=\s*(\d+)/m', $pool, $m));
        self::assertLessThanOrEqual(intdiv((int) $m[1], 4), 4, 'global download concurrency <= max_children / 4');

        // Every bait path is under the bounded prefix.
        foreach ([DownloadRouter::SW_PATH, DownloadRouter::MANIFEST_PATH, DownloadRouter::ZIP_PATH] as $path) {
            self::assertStringStartsWith('/__dl/', $path);
        }

        // Same front controller, byte-identical FastCGI wiring — the envelope never changes routing.
        $fastcgi = static fn (array $lines): array => array_values(array_filter($lines, static fn (string $l): bool => preg_match('/^(include fastcgi_params;|fastcgi_pass |fastcgi_param |fastcgi_read_timeout )/', $l) === 1));
        $root = self::directives(self::block($conf, 'location /'));
        self::assertSame($fastcgi($root), $fastcgi($dl));
        self::assertNotSame([], $fastcgi($root));
        self::assertSame($root, $fastcgi($root), 'location / carries no blanket limits');
        // No limit on the general honeypot location: the bound is route-local.
        self::assertSame([], preg_grep('/^limit_/', $root));
        // The bounded prefix precedes the catch-all in the file (readability; nginx picks ^~ regardless).
        self::assertLessThan(strpos($conf, "\nlocation / {"), strpos($conf, 'location ^~ /__dl/ {'));
    }

    public function test_throttle_response_is_controlled_and_fingerprint_clean(): void
    {
        $conf = (string) file_get_contents(self::root() . '/demo/funnypot-location.conf');
        $named = self::directives(self::block($conf, 'location @funnypot_dl_throttled'));
        self::assertContains('default_type text/plain;', $named);
        self::assertContains('add_header Retry-After 10 always;', $named);
        self::assertContains('add_header Cache-Control no-store always;', $named);
        $ret = array_values(preg_grep('/^return 429 "/', $named));
        self::assertCount(1, $ret, 'an explicit body, so the stock page is never used');
        self::assertSame(1, preg_match('/^return 429 "(.*)";$/', $ret[0], $m));
        $body = stripcslashes($m[1]);

        self::assertStringNotContainsStringIgnoringCase('nginx', $body);
        self::assertStringNotContainsStringIgnoringCase('<html', $body);
        self::assertLessThan(200, strlen($body));

        // Same leak-IN and leak-OUT scan the served surfaces get.
        $d = require self::root() . '/resources/app-fingerprint-denylist.php';
        foreach ((array) ($d['literals'] ?? []) as $needle) {
            if ($needle !== '') {
                self::assertStringNotContainsStringIgnoringCase($needle, $body, 'leak-IN literal in the 429 body');
            }
        }
        foreach ((array) ($d['patterns'] ?? []) as $pattern) {
            self::assertSame(0, @preg_match('~' . $pattern . '~i', $body), 'leak-IN pattern in the 429 body');
        }
        $own = '/(?<![a-zA-Z0-9])(' . implode('|', (array) ($d['own_vocabulary'] ?? [])) . ')(?![a-zA-Z0-9])/i';
        self::assertSame(0, preg_match($own, $body), 'own vocabulary in the 429 body');
    }
}

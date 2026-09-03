<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use PHPUnit\Framework\TestCase;

/**
 * FP-0250 §2.2/§4.1 — the authed dashboard shell makes no external load, carries a strict nonced CSP +
 * Referrer-Policy, and never exposes the CSRF token as a `window.*` global. Headers are asserted over a
 * REAL HTTP response (see {@see DashboardHttpServerTrait}) because under the phpunit CLI SAPI,
 * header()/headers_list() are no-ops for introspection — the only faithful way to prove a header was
 * actually emitted is to boot demo/index.php and read the wire.
 */
final class DashboardShellSecurityTest extends TestCase
{
    use DashboardHttpServerTrait;

    private const PASS = 'operator-secret-pw-9';

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open disabled — cannot spawn the built-in server');
        }
        if (PHP_BINARY === '' || !is_executable(PHP_BINARY)) {
            self::markTestSkipped('no usable PHP CLI binary to run the built-in server');
        }
    }

    protected function tearDown(): void
    {
        $this->dashboardCleanupTmpDirs();
    }

    public function test_full_flow_headers_nonce_csrf_and_no_external_urls(): void
    {
        $root = dirname(__DIR__, 3);
        $index = $root . '/demo/index.php';
        $data = $this->dashboardTempDir('fpshell_data');
        $docroot = $this->dashboardTempDir('fpshell_doc');
        $env = $this->dashboardBootEnv($data, [
            'FUNNYPOT_MODE' => 'public',
            'FUNNYPOT_PUBLIC_VIEW' => 'full',
            'FUNNYPOT_ADMIN_PASSWORD' => self::PASS,
            'FUNNYPOT_HIDE_MAIN' => '0',
        ]);
        [$proc, $pipes, $port] = $this->startDashboardServer($index, $docroot, $env);

        try {
            // --- log in, capture the session cookie ---
            [$loginStatus, $loginHeaders, $loginBody, $setCookies] = $this->dashboardHttpRequest(
                '127.0.0.1',
                $port,
                'POST',
                '/funnypot?admin=login',
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                'user=admin&pass=' . urlencode(self::PASS)
            );
            self::assertSame(200, $loginStatus);
            $json = json_decode($loginBody, true);
            self::assertTrue($json['ok'] ?? false, 'login must succeed: ' . $loginBody);
            self::assertNotEmpty($setCookies, 'a successful login must set the session cookie');
            unset($loginHeaders);
            $cookieHeader = $this->cookieHeaderFrom($setCookies);

            // --- authed GET / : the real shell ---
            [$authedStatus, $authedHeaders, $authedBody] = $this->dashboardHttpRequest(
                '127.0.0.1',
                $port,
                'GET',
                '/funnypot',
                ['Cookie' => $cookieHeader]
            );
            self::assertSame(200, $authedStatus);

            // No external URL anywhere via an actual load vector: no <link href=http(s)>, no
            // <script src=http(s)>, no CSS url(http(s)...), no @import. A URL sitting inertly inside a
            // vendored library's own comment text (e.g. uPlot's/Leaflet's GitHub/spec-doc attribution,
            // an XML namespace string) is not a network load and predates this ticket (uPlot) — the
            // load-bearing invariant this test pins is "nothing is FETCHED", which these patterns cover.
            self::assertStringNotContainsStringIgnoringCase('unpkg.com', $authedBody, 'no unpkg.com anywhere, load-bearing or not');
            self::assertStringNotContainsStringIgnoringCase('cartocdn', $authedBody, 'no cartocdn anywhere, load-bearing or not');
            self::assertDoesNotMatchRegularExpression('/<link[^>]+href=[\'"]https?:\/\//i', $authedBody);
            self::assertDoesNotMatchRegularExpression('/<script[^>]+src=[\'"]https?:\/\//i', $authedBody);
            self::assertDoesNotMatchRegularExpression('/url\(\s*[\'"]?https?:\/\//i', $authedBody);
            self::assertDoesNotMatchRegularExpression('/@import\s+[\'"]?https?:\/\//i', $authedBody);

            // --- CSP + Referrer-Policy + nonce agreement (the actual wire headers) ---
            self::assertArrayHasKey('content-security-policy', $authedHeaders);
            self::assertMatchesRegularExpression(
                "/script-src 'nonce-[0-9a-f]{32}'/",
                $authedHeaders['content-security-policy']
            );
            self::assertMatchesRegularExpression(
                "/style-src 'nonce-[0-9a-f]{32}'/",
                $authedHeaders['content-security-policy']
            );
            self::assertSame('no-referrer', $authedHeaders['referrer-policy'] ?? null);
            self::assertSame('nosniff', $authedHeaders['x-content-type-options'] ?? null);
            self::assertSame('DENY', $authedHeaders['x-frame-options'] ?? null);

            preg_match("/script-src 'nonce-([0-9a-f]{32})'/", $authedHeaders['content-security-policy'], $m);
            $headerNonce = $m[1];
            preg_match_all('/nonce="([0-9a-f]{32})"/', $authedBody, $mm);
            self::assertNotEmpty($mm[1], 'every inline <style>/<script> in the authed shell must carry a nonce attribute');
            $distinctTagNonces = array_unique($mm[1]);
            self::assertSame([$headerNonce], $distinctTagNonces, 'every tag nonce must equal the CSP header nonce, exactly');

            // --- CSRF token: never a window global; present exactly once as a <meta> tag ---
            self::assertStringNotContainsString('window.FP_CSRF', $authedBody, 'FP_CSRF must not be a JS global');
            self::assertSame(1, preg_match_all('/<meta name="fp-csrf" content="[0-9a-f]+">/', $authedBody, $mm2), 'exactly one fp-csrf meta tag');

            // --- unauthenticated GET / (public_view=full): no meta, no token bytes, still has the headers ---
            [$pubStatus, $pubHeaders, $pubBody] = $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', '/funnypot');
            self::assertSame(200, $pubStatus);
            // app.js itself contains the literal string "fp-csrf" (its meta-tag selector), so check
            // for the actual <meta ...> TAG, not the bare substring.
            self::assertDoesNotMatchRegularExpression('/<meta name="fp-csrf"/', $pubBody, 'no csrf meta for an unauthenticated visitor');
            self::assertStringNotContainsString('window.FP_CSRF', $pubBody);
            self::assertArrayHasKey('content-security-policy', $pubHeaders, 'CSP is emitted for the unauth full view too');
            self::assertSame('no-referrer', $pubHeaders['referrer-policy'] ?? null);

            // --- feed() carries Referrer-Policy on a real (non-404) response too ---
            [$feedStatus, $feedHeaders] = $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', '/funnypot?feed=1&after=0');
            self::assertSame(200, $feedStatus);
            self::assertSame('no-referrer', $feedHeaders['referrer-policy'] ?? null);
        } finally {
            $this->stopDashboardServer($proc, $pipes);
        }
    }

    /** Build a `Cookie:` request-header value from one or more raw Set-Cookie response lines. */
    private function cookieHeaderFrom(array $setCookies): string
    {
        $pairs = [];
        foreach ($setCookies as $line) {
            $first = explode(';', $line, 2)[0];
            if (trim($first) !== '') {
                $pairs[] = trim($first);
            }
        }

        return implode('; ', $pairs);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\Support\Chrome\GenericSkin;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\App\Render\SkinSet;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Support\Chrome\WordpressSkin;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The LLM responder pipeline end to end with an injected transport (no network): gate -> generate ->
 * sanitize -> cache -> response, with every decline/failure returning null (the plain 404).
 */
final class LlmFakeResponderTest extends TestCase
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

    private function dbPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fp_{$n}_" . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @return array{0:LlmFakeResponder,1:SqliteHitStore} */
    private function make(callable $transport): array
    {
        $store = new SqliteHitStore($this->dbPath('hits'));
        $responder = new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache($this->dbPath('cache')),
            new LlmClient('http://sidecar/completion', 1500, 320, null, $transport),
            new LlmOutputSanitizer(),
            $store,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"'),
            'v1',
            4,
        );

        return [$responder, $store];
    }

    /** Like make(), but the HTML profile carries the real skin renderer, so coherent-panel paths are
     *  detected (matchesProductSkin) and let through the lexical shed. */
    private function makeWithRenderer(callable $transport): array
    {
        $store = new SqliteHitStore($this->dbPath('hits'));
        $skins = new SkinSet(
            [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()],
            new GenericSkin()
        );
        $responder = new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache($this->dbPath('cache')),
            new LlmClient('http://sidecar/completion', 1500, 320, null, $transport),
            new LlmOutputSanitizer(),
            $store,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"', new PageShellRenderer($skins), 'root ::= "{"'),
            'v1',
            4,
            7,
            'a1',
        );

        return [$responder, $store];
    }

    public function test_panel_path_bypasses_lexical_shed_and_serves_200(): void
    {
        // /panel/hvac is a coherent-panel path (AdminLteSkin) the lexical classifier rates "not plausible"
        // and would shed — but every panel sub-path is navigable, so it must still render, with a 200. The
        // panel renders deterministically (empty slots), independent of the transport.
        [$r] = $this->makeWithRenderer(fn (): array => ['status' => 200, 'body' => json_encode(['heading' => 'HVAC'])]);
        $resp = $r->respond(new RequestContext('GET', '/panel/hvac'), '9.9.9.9');
        self::assertNotNull($resp, 'a panel sub-path must render even though the lexical gate would shed it');
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('alte-sidebar', $resp->body);
    }

    public function test_panel_dashboard_serves_200_not_401(): void
    {
        // The dashboard used to 401 (auth-looking keyword). As a coherent panel it now serves 200 so
        // deep navigation isn't broken by an auth wall mid-panel.
        [$r] = $this->makeWithRenderer(fn (): array => ['status' => 200, 'body' => json_encode(['heading' => 'Dashboard'])]);
        $resp = $r->respond(new RequestContext('GET', '/panel/dashboard'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
    }

    public function test_panel_serves_200_even_when_ip_is_bulk_scan_pinned(): void
    {
        // The deep panel is meant for hours of exploration: a human clicking a dense sidebar quickly
        // trips the velocity window and gets bulk-scan-pinned. A panel path must stay navigable anyway —
        // it is exempt from the gate entirely (deterministic + cached render, no model call). This is the
        // regression: pinned IPs were seeing the whole panel collapse to plain 404s.
        [$r, $store] = $this->makeWithRenderer(fn (): array => ['status' => 200, 'body' => json_encode(['heading' => 'HVAC'])]);
        $store->flagBulkScan('9.9.9.9', 24);
        $resp = $r->respond(new RequestContext('GET', '/panel/hvac'), '9.9.9.9');
        self::assertNotNull($resp, 'a bulk-scan-pinned IP must still be able to navigate the panel');
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('alte-sidebar', $resp->body);
    }

    public function test_pinned_ip_is_still_gated_on_a_non_panel_path(): void
    {
        // The panel exemption must not disarm the gate for everything: a plausible NON-panel path from a
        // bulk-scan-pinned IP is still declined to the plain 404 (anti-DoS/anti-enumeration intact).
        $calls = 0;
        [$r, $store] = $this->makeWithRenderer(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])];
        });
        $store->flagBulkScan('9.9.9.9', 24);
        self::assertNull($r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9'));
        self::assertSame(0, $calls, 'a pinned non-panel path must not reach generation');
    }

    private const GOOD_HTML =
        '<!doctype html><html><head><title>Sign in</title></head><body><h1>Sign in</h1>'
        . '<form method="post" action="/x"><input name="user"><input name="pass" type="password">'
        . '<button>Log in</button></form></body></html>';

    public function test_generates_sanitizes_caches_and_serves(): void
    {
        $calls = 0;
        [$r] = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])];
        });

        $resp = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('Sign in', $resp->body);
        self::assertSame(1, $calls);

        // second request for the same path is a cache hit — no new generation
        $resp2 = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($resp2);
        self::assertSame(1, $calls);
    }

    public function test_logs_the_served_response_body(): void
    {
        [$r, $store] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])]);
        $resp = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($resp);

        // The served fake must be logged with the exact body the attacker got. The request is a
        // bodyless GET, so any logged row carrying HTML is the llm-fake event.
        $rows = $store->delta(0)['rows'];
        $logged = array_filter($rows, static fn (array $row): bool => str_contains((string) ($row['body'] ?? ''), 'Sign in'));
        self::assertNotEmpty($logged, 'the served LLM response body should be logged');
    }

    public function test_gate_declines_probe_path_without_generating(): void
    {
        $calls = 0;
        [$r] = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => '{}'];
        });

        self::assertNull($r->respond(new RequestContext('GET', '/random9271.php'), '9.9.9.9'));
        self::assertSame(0, $calls);
    }

    public function test_sanitizer_rejection_returns_null(): void
    {
        $bad = '<html><body><script>alert(1)</script> padding to pass the min length check here</body></html>';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $bad])]);
        self::assertNull($r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9'));
    }

    public function test_client_failure_returns_null(): void
    {
        [$r] = $this->make(fn (): array => ['status' => 500, 'body' => '']);
        self::assertNull($r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9'));
    }

    public function test_auth_looking_path_gets_401(): void
    {
        $html = '<!doctype html><html><body><h1>Admin</h1><p>Authentication required to view this area.</p></body></html>';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $html])]);
        $resp = $r->respond(new RequestContext('GET', '/admin/settings.php'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame(401, $resp->status);
    }

    public function test_js_path_serves_javascript_not_html(): void
    {
        // The reported bug: a .js request got an HTML page at text/html. It must serve JavaScript.
        $js = 'var APP_CONFIG={"version":"1.0","apiBase":"/api/v1","debug":false,"buildId":"abc123ff"};';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $js])]);
        $resp = $r->respond(new RequestContext('GET', '/static/js/app.js'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame('application/javascript', $resp->headers['Content-Type']);
        self::assertStringNotContainsString('<html', $resp->body);
        self::assertStringContainsString('APP_CONFIG', $resp->body);
    }

    public function test_cache_hit_preserves_content_type(): void
    {
        // The latent bug: build() hardcoded text/html even on a cache hit, discarding the stored type.
        $calls = 0;
        $json = '{"users":[{"id":1,"name":"a.reyes","role":"admin"}],"total":1}';
        [$r] = $this->make(function () use (&$calls, $json): array {
            $calls++;

            return ['status' => 200, 'body' => json_encode(['content' => $json])];
        });

        $first = $r->respond(new RequestContext('GET', '/api/v2/report.json'), '9.9.9.9');
        self::assertNotNull($first);
        self::assertSame('application/json', $first->headers['Content-Type']);

        // Second request is a cache hit (no new generation) and MUST keep application/json.
        $second = $r->respond(new RequestContext('GET', '/api/v2/report.json'), '9.9.9.9');
        self::assertNotNull($second);
        self::assertSame(1, $calls);
        self::assertSame('application/json', $second->headers['Content-Type']);
    }

    public function test_unmapped_extension_falls_back_to_html(): void
    {
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])]);
        $resp = $r->respond(new RequestContext('GET', '/backup/keystore.pem'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame('text/html; charset=utf-8', $resp->headers['Content-Type']);
    }

    public function test_response_carries_a_per_response_request_id(): void
    {
        // Header parity with the template tier (ResponseSynthesizer), which stamps every response
        // with a random X-Request-Id: an LLM fake without one would be a header-distinct minority
        // among app-generated content. X-Powered-By is not asserted here — it's set globally by the
        // front controller (demo/index.php), outside LlmFakeResponder's own header set.
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])]);

        $first = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($first);
        self::assertArrayHasKey('X-Request-Id', $first->headers);
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $first->headers['X-Request-Id']);

        // Cache hit is a fresh HTTP response too — it must get its own X-Request-Id, not a value
        // frozen at cache-write time (a fixed id across many requests would itself be a tell).
        $second = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($second);
        self::assertArrayHasKey('X-Request-Id', $second->headers);
        self::assertNotSame($first->headers['X-Request-Id'], $second->headers['X-Request-Id']);
    }

    public function test_non_html_sanitizer_rejection_returns_null(): void
    {
        // A .js body carrying a runtime primitive is rejected → the plain 404 (parity with HTML).
        $badJs = 'var x=1; fetch("/y"); var padding_to_reach_the_minimum_length_here=2;';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $badJs])]);
        self::assertNull($r->respond(new RequestContext('GET', '/static/js/app.js'), '9.9.9.9'));
    }

    public function test_renderer_profile_turns_slot_json_into_a_styled_page(): void
    {
        $slots = json_encode(['content' => '{"app_name":"HR Portal","heading":"Users","table":{"cols":["User","Token"],"rows":[["m.hale","APITOKEN"]]}}']);
        $renderer = new \Funnypot\App\Render\PageShellRenderer(
            new \Funnypot\App\Render\SkinSet([], new \Funnypot\Support\Chrome\GenericSkin())
        );
        $store = new SqliteHitStore($this->dbPath('hits'));
        $r = new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache($this->dbPath('cache')),
            new LlmClient('http://sidecar/completion', 1500, 320, null, fn (): array => ['status' => 200, 'body' => $slots]),
            new LlmOutputSanitizer(),
            $store,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"', $renderer, 'root ::= "{"', 'Velthora'),
            'v1', 4, 12345, 'art1',
        );
        $resp = $r->respond(new RequestContext('GET', '/admin/settings.php'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame('text/html; charset=utf-8', $resp->headers['Content-Type']);
        self::assertStringStartsWith('<!doctype html>', $resp->body);
        self::assertStringContainsString('<style>', $resp->body);
        self::assertStringContainsString('HR Portal', $resp->body);
        self::assertStringNotContainsString('APITOKEN', $resp->body);   // marker substituted
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0250 §2.6/§2.8/§4.4 — the `?admin=login` oracle: unbranded form, a knock token gating both the GET
 * form and the POST action, per-IP rate-limiting of the GET, and every decoy 404 involved byte-identical
 * to the honeypot's own believable 404 with NO dashboard security headers (a 404 that uniquely carried
 * security headers would itself be a new, header-shaped oracle replacing the body-shaped one this fix
 * closes). Header-absence assertions go over the real wire (see DashboardHttpServerTrait) since the
 * phpunit CLI SAPI makes header()/headers_list() no-ops for introspection; body/unbranding/rate-limit
 * assertions use direct construction (the DashboardPublicViewTest idiom), which is equally faithful for
 * bytes that never depend on a real header.
 */
final class LoginFormOracleTest extends TestCase
{
    use DashboardHttpServerTrait;

    private const PASS = 'operator-secret-pw-7';

    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        putenv('FUNNYPOT_PUBLIC_VIEW');
        putenv('FUNNYPOT_ADMIN_KNOCK');
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
            @unlink(dirname($f) . '/config.gen');
        }
        $this->tmp = [];
        $this->dashboardCleanupTmpDirs();
        putenv('FUNNYPOT_PUBLIC_VIEW');
        putenv('FUNNYPOT_ADMIN_KNOCK');
        unset($_GET, $_POST, $_COOKIE[AdminAuth::COOKIE]);
        $_GET = [];
        $_POST = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_lfo_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function configFor(string $knock = '', string $publicView = 'none'): AppConfig
    {
        putenv('FUNNYPOT_ADMIN_KNOCK=' . $knock); // putenv('X=') sets an EMPTY value, not unset — matches "" default
        putenv('FUNNYPOT_PUBLIC_VIEW=' . $publicView);
        $c = AppConfig::fromEnv(sys_get_temp_dir());
        putenv('FUNNYPOT_ADMIN_KNOCK');
        putenv('FUNNYPOT_PUBLIC_VIEW');

        return $c;
    }

    private function controller(AppConfig $config, ?AdminAuth $auth): DashboardController
    {
        $hit = new SqliteHitStore($this->path('hit'));

        return new DashboardController(
            $hit,
            new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()),
            $config,
            dirname(__DIR__, 3) . '/demo/assets',
            null,
            null,
            $hit,
            $auth,
            null,
        );
    }

    private function freshAuth(): AdminAuth
    {
        unset($_COOKIE[AdminAuth::COOKIE]);

        $auth = new AdminAuth($this->path('auth'));
        $auth->createOrResetUser('admin', self::PASS);

        return $auth;
    }

    private function body(callable $fn): string
    {
        ob_start();
        @$fn();

        return (string) ob_get_clean();
    }

    private function believable404Body(): string
    {
        return $this->body(static fn () => HoneypotController::serveBelievable404());
    }

    // --- unbranding -----------------------------------------------------------------------------

    public function test_login_form_is_unbranded(): void
    {
        // A neutral $base ('/x') so window.FP_BASE (the routing path, unrelated to product branding —
        // in public mode it is literally FUNNYPOT_APP_PATH, operator-configurable, defaulting to
        // 'funnypot') can never be confused with the branded PRODUCT STRINGS this test targets.
        $config = $this->configFor('', 'none');
        $c = $this->controller($config, $this->freshAuth());
        $form = $this->body(fn () => $c->loginForm('/x'));

        self::assertStringNotContainsString('<title>funnypot</title>', $form, 'no branded <title>');
        self::assertStringNotContainsString('Welcome to', $form, 'no "Welcome to ..." branded heading');
        self::assertStringNotContainsString('&#127855;', $form, 'no cake emoji entity');
        self::assertStringNotContainsString('class=honey', $form, 'no honey class');
        self::assertStringNotContainsString('<span class=honey>', $form, 'no honey span');
        self::assertStringContainsString('<title>Sign in</title>', $form, 'a neutral title instead');
        self::assertStringContainsString('id=lf', $form, 'the form itself still renders');
    }

    // --- knock token ------------------------------------------------------------------------------

    public function test_knock_disabled_by_default_form_still_renders(): void
    {
        $config = $this->configFor('', 'none');
        self::assertSame('', $config->adminKnock);
        $c = $this->controller($config, $this->freshAuth());
        $_GET = [];
        $form = $this->body(fn () => $c->loginForm('/funnypot'));

        self::assertStringContainsString('id=lf', $form, 'compat: an unset knock leaves the form reachable exactly as before');
    }

    public function test_knock_wrong_or_missing_is_the_believable_404_bytes(): void
    {
        $config = $this->configFor('correct-knock-9f3a', 'none');
        $c = $this->controller($config, $this->freshAuth());
        $decoy = $this->believable404Body();

        foreach ([[], ['k' => 'wrong-token']] as $get) {
            $_GET = $get;
            $body = $this->body(fn () => $c->loginForm('/funnypot'));
            self::assertSame($decoy, $body, 'a missing/wrong knock must render the EXACT honeypot 404 bytes, not the login form');
            self::assertStringNotContainsString('id=lf', $body);
        }
    }

    public function test_knock_correct_renders_the_real_form(): void
    {
        $config = $this->configFor('correct-knock-9f3a', 'none');
        $c = $this->controller($config, $this->freshAuth());
        $_GET = ['k' => 'correct-knock-9f3a'];
        $form = $this->body(fn () => $c->loginForm('/funnypot'));

        self::assertStringContainsString('id=lf', $form, 'the right knock reaches the real form');
    }

    /**
     * The POST ?admin=login action requires the SAME knock (via admin('login') -> handleLogin()) — a
     * wrong/missing k on the credential POST must ALSO decoy, not just leak a JSON auth error.
     */
    public function test_knock_gates_the_post_login_action_too(): void
    {
        $config = $this->configFor('correct-knock-9f3a', 'none');
        $auth = $this->freshAuth();
        $c = $this->controller($config, $auth);
        $decoy = $this->believable404Body();

        $_GET = []; // no k
        $_POST = ['user' => 'admin', 'pass' => self::PASS];
        $body = $this->body(fn () => $c->admin('login'));
        self::assertSame($decoy, $body, 'a POST login with no knock must decoy, even with the CORRECT credentials');
        self::assertFalse($auth->check(), 'no session was minted — the credential verify never ran');

        $_GET = ['k' => 'correct-knock-9f3a'];
        $ok = json_decode($this->body(fn () => $c->admin('login')), true);
        self::assertTrue($ok['ok'] ?? false, 'the right knock + right credentials succeed');
    }

    // --- decoy header discipline (real wire — see class docblock) ---------------------------------

    public function test_decoy_404_carries_no_dashboard_headers(): void
    {
        $root = dirname(__DIR__, 3);
        $index = $root . '/demo/index.php';
        $data = $this->dashboardTempDir('fplfo_data');
        $docroot = $this->dashboardTempDir('fplfo_doc');
        $env = $this->dashboardBootEnv($data, [
            'FUNNYPOT_MODE' => 'public',
            'FUNNYPOT_PUBLIC_VIEW' => 'none',
            'FUNNYPOT_ADMIN_PASSWORD' => self::PASS,
            'FUNNYPOT_ADMIN_KNOCK' => 'wire-knock-4471',
            'FUNNYPOT_HIDE_MAIN' => '0',
        ]);
        [$proc, $pipes, $port] = $this->startDashboardServer($index, $docroot, $env);

        try {
            // Wrong knock -> the decoy 404.
            [$status, $headers, $body] = $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', '/funnypot?admin=login&k=nope');
            self::assertSame(404, $status);
            // PHP's own default_charset ini appends ";charset=UTF-8" (no space, uppercase) to a bare
            // `header('Content-Type: text/html')` over a real request — this is the SAME auto-appended
            // form the two pre-existing honeypot-miss call sites have always produced (unchanged by this
            // ticket); it is NOT the dashboard's own explicit `text/html; charset=utf-8` (space,
            // lowercase) — the two remain distinguishable from each other, but the decoy and a genuine
            // miss (asserted identical below) are not.
            self::assertStringStartsWith('text/html', (string) ($headers['content-type'] ?? ''));
            self::assertStringNotContainsString('; charset=utf-8', (string) ($headers['content-type'] ?? ''), 'must not be the DASHBOARD\'s own explicit charset form');
            self::assertArrayNotHasKey('content-security-policy', $headers);
            self::assertArrayNotHasKey('referrer-policy', $headers);
            self::assertArrayNotHasKey('x-frame-options', $headers);
            self::assertArrayNotHasKey('x-content-type-options', $headers);
            self::assertArrayNotHasKey('cache-control', $headers, 'no Cache-Control: no-store on the decoy — a 404 must not uniquely carry it');
            self::assertStringContainsString('<center>nginx</center>', $body);

            // A real (empty) probe of an unrelated path gets the byte-identical body/headers, so the
            // decoy really is indistinguishable from any other miss.
            [$missStatus, $missHeaders, $missBody] = $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', '/some/unrelated/probe');
            self::assertSame($status, $missStatus);
            self::assertSame($headers['content-type'] ?? null, $missHeaders['content-type'] ?? null);
            self::assertSame($body, $missBody, 'the knock-fail decoy and a genuine miss are byte-identical');
        } finally {
            $this->stopDashboardServer($proc, $pipes);
        }
    }

    // --- rate limit -------------------------------------------------------------------------------

    public function test_form_requests_are_rate_limited_per_ip(): void
    {
        $config = $this->configFor('', 'none');
        $auth = $this->freshAuth();
        $c = $this->controller($config, $auth);
        $decoy = $this->believable404Body();
        $ip = '203.0.113.44';
        $_SERVER['REMOTE_ADDR'] = $ip;
        $_GET = [];

        // AdminAuth's cap is 30 (per-IP 'form'+'fail' within the lockout window) — render past it.
        $lastBody = '';
        for ($i = 0; $i < 35; $i++) {
            $lastBody = $this->body(fn () => $c->loginForm('/funnypot'));
        }
        self::assertSame($decoy, $lastBody, 'past the cap, the form itself becomes the believable-404 decoy');

        // 'form' rows never count toward the credential lockout/backoff (only 'fail' does) — the SAME
        // username can still log in successfully once past the rate limit is irrelevant here.
        $attempts = $auth->attempts(200);
        $results = array_column($attempts, 'result');
        self::assertContains('form', $results, 'form renders are recorded under their own result type');
        self::assertNotContains('fail', $results, 'no credential attempt was made — only form renders happened');

        unset($_SERVER['REMOTE_ADDR']);
    }

    // --- the bare-GET (§1.6/§2.8) oracle, byte-identical across all three surfaces -----------------

    public function test_none_bare_get_404_is_byte_identical_to_the_honeypot_404_across_shell_feed_recording(): void
    {
        $config = $this->configFor('', 'none');
        $c = $this->controller($config, $this->freshAuth());
        $decoy = $this->believable404Body();

        self::assertSame($decoy, $this->body(fn () => $c->shell('/funnypot')));
        self::assertSame($decoy, $this->body(fn () => $c->feed()));
        self::assertSame($decoy, $this->body(fn () => $c->recording('anything')));
    }
}

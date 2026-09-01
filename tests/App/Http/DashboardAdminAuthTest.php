<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0242b — the upgraded admin gate on DashboardController (spec §7.7, plan T-AUTH-1/2). Every
 * mutating admin action must require a valid session AND a valid per-session CSRF token; an
 * unauthenticated caller, or a logged-in one without the CSRF token, must NOT be able to reach
 * ConfigStore::set(). Asserted on the JSON body (the CLI SAPI makes http_response_code unreadable —
 * DashboardAnalyticsTest idiom) AND on the store: a denied action leaves NO config row written.
 */
final class DashboardAdminAuthTest extends TestCase
{
    private const PASS = 'operator-secret-pw';

    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        // A stored '' or a set env would confuse the "no write" assertions; keep style env-unset.
        putenv('FUNNYPOT_STYLE');
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
                @unlink(dirname($f) . '/config.gen');
            }
        }
        $this->tmp = [];
        putenv('FUNNYPOT_STYLE');
        putenv('FUNNYPOT_ADMIN_PASSWORD');
        unset($_GET, $_POST, $_COOKIE[AdminAuth::COOKIE]);
        $_GET = [];
        $_POST = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function store(): ConfigStore
    {
        return new ConfigStore($this->path('cfg'));
    }

    private function auth(): AdminAuth
    {
        $auth = new AdminAuth($this->path('auth'));
        $auth->createOrResetUser('admin', self::PASS);

        return $auth;
    }

    private function controller(ConfigStore $cfg, ?AdminAuth $auth): DashboardController
    {
        $hit = new SqliteHitStore($this->path('hit'));

        return new DashboardController(
            $hit,
            new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()),
            AppConfig::fromEnv(sys_get_temp_dir()),
            sys_get_temp_dir(),
            null,
            null,
            $hit,
            $auth,
            $cfg,
        );
    }

    /** @return array<string,mixed>|null */
    private function call(DashboardController $c, string $action): ?array
    {
        ob_start();
        @$c->admin($action);

        return json_decode((string) ob_get_clean(), true);
    }

    // --- T-AUTH-1: unauthenticated mutating POST ⇒ denied, no write ---

    public function test_unauthenticated_config_set_is_denied_and_writes_nothing(): void
    {
        $cfg = $this->store();
        $auth = $this->auth();          // a user exists, but this request has NO session cookie
        unset($_COOKIE[AdminAuth::COOKIE]);
        $_POST = ['key' => 'style', 'value' => 'taunt'];

        $json = $this->call($this->controller($cfg, $auth), 'config-set');

        self::assertSame('forbidden', $json['error'] ?? null, 'no session ⇒ forbidden');
        self::assertNotSame(true, $json['ok'] ?? null);
        self::assertSame('realistic', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'), 'no config row may be written unauthenticated');
        self::assertSame([], $cfg->stored(), 'the override table stays empty');
    }

    public function test_unauthenticated_with_null_auth_is_fail_closed(): void
    {
        $cfg = $this->store();
        $_POST = ['key' => 'style', 'value' => 'taunt'];

        // No auth wired at all — the gate must still deny (fail-closed), never fall open.
        $json = $this->call($this->controller($cfg, null), 'config-set');

        self::assertSame('forbidden', $json['error'] ?? null);
        self::assertSame('realistic', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'));
    }

    // --- T-AUTH-2: a valid session but missing/wrong CSRF ⇒ denied; correct CSRF ⇒ the write lands ---

    public function test_missing_and_wrong_csrf_are_denied_then_correct_csrf_writes(): void
    {
        $cfg = $this->store();
        $auth = $this->auth();
        $res = $auth->login('admin', self::PASS, '203.0.113.5');
        self::assertTrue($res['ok']);
        $csrf = (string) $res['csrf'];
        $c = $this->controller($cfg, $auth);

        // (a) missing CSRF
        $_POST = ['key' => 'style', 'value' => 'taunt'];
        $json = $this->call($c, 'config-set');
        self::assertSame('bad csrf token', $json['error'] ?? null, 'a session alone is not enough');
        self::assertSame('realistic', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'), 'missing CSRF writes nothing');

        // (b) wrong CSRF
        $_POST = ['key' => 'style', 'value' => 'taunt', 'csrf' => 'deadbeef'];
        $json = $this->call($c, 'config-set');
        self::assertSame('bad csrf token', $json['error'] ?? null);
        self::assertSame('realistic', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'), 'wrong CSRF writes nothing');

        // (c) correct CSRF ⇒ the write lands
        $_POST = ['key' => 'style', 'value' => 'taunt', 'csrf' => $csrf];
        $json = $this->call($c, 'config-set');
        self::assertTrue($json['ok'] ?? false, 'a session + correct CSRF is accepted');
        self::assertSame('taunt', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'), 'the override is now stored');

        // The change is audited with the session user as actor.
        $audit = $cfg->audits(10);
        self::assertNotEmpty($audit);
        self::assertSame('style', $audit[0]['key']);
        self::assertSame('admin', $audit[0]['actor']);
    }

    public function test_empty_value_is_rejected_even_with_a_valid_session_and_csrf(): void
    {
        $cfg = $this->store();
        $auth = $this->auth();
        $res = $auth->login('admin', self::PASS, '203.0.113.5');
        $c = $this->controller($cfg, $auth);

        // An empty override would silently mask a set env var — config-set must reject it (fable#3).
        $_POST = ['key' => 'style', 'value' => '', 'csrf' => (string) $res['csrf']];
        $json = $this->call($c, 'config-set');
        self::assertNotSame(true, $json['ok'] ?? null, 'an empty value is rejected');
        self::assertStringContainsStringIgnoringCase('empty', (string) ($json['error'] ?? ''));
        self::assertSame([], $cfg->stored(), 'no empty override row was written');
    }

    public function test_config_reset_needs_csrf_too(): void
    {
        $cfg = $this->store();
        $auth = $this->auth();
        $res = $auth->login('admin', self::PASS, '203.0.113.5');
        $csrf = (string) $res['csrf'];
        $c = $this->controller($cfg, $auth);

        // Seed an override with a valid write.
        $_POST = ['key' => 'style', 'value' => 'taunt', 'csrf' => $csrf];
        self::assertTrue($this->call($c, 'config-set')['ok'] ?? false);
        self::assertSame('taunt', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'));

        // A reset without CSRF is denied — the override survives.
        $_POST = ['key' => 'style'];
        $json = $this->call($c, 'config-reset');
        self::assertSame('bad csrf token', $json['error'] ?? null);
        self::assertSame('taunt', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'), 'a CSRF-less reset changes nothing');

        // With CSRF the reset lands and the key falls back to the default.
        $_POST = ['key' => 'style', 'csrf' => $csrf];
        self::assertTrue($this->call($c, 'config-reset')['ok'] ?? false);
        self::assertSame('realistic', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'));
    }

    // --- reads need a session but not CSRF ---

    public function test_config_list_needs_a_session_but_no_csrf(): void
    {
        $cfg = $this->store();
        $auth = $this->auth();

        // Unauthenticated ⇒ forbidden.
        self::assertSame('forbidden', $this->call($this->controller($cfg, $auth), 'config-list')['error'] ?? null);

        // Authenticated, no CSRF in the body ⇒ the read still succeeds.
        $auth->login('admin', self::PASS, '203.0.113.5');
        $_POST = [];
        $json = $this->call($this->controller($cfg, $auth), 'config-list');
        self::assertTrue($json['ok'] ?? false, 'a read needs only a session');
        self::assertArrayHasKey('groups', $json);
    }

    // --- login lockout drives through admin('login') too (plan T-AUTH-3, controller surface) ---

    public function test_admin_login_action_locks_out_after_repeated_failures(): void
    {
        $cfg = $this->store();
        $auth = new AdminAuth($this->path('auth'), '/', false, 3, 900);
        $auth->createOrResetUser('admin', self::PASS);
        $c = $this->controller($cfg, $auth);
        $_SERVER['REMOTE_ADDR'] = '203.0.113.44';

        for ($i = 0; $i < 3; $i++) {
            $_POST = ['user' => 'admin', 'pass' => 'wrong'];
            self::assertNotSame(true, $this->call($c, 'login')['ok'] ?? null);
        }
        // Correct password now, but the IP is locked out.
        $_POST = ['user' => 'admin', 'pass' => self::PASS];
        $json = $this->call($c, 'login');
        self::assertNotSame(true, $json['ok'] ?? null, 'the correct password is denied inside the lockout window');
        self::assertStringContainsStringIgnoringCase('locked', (string) ($json['error'] ?? ''));
    }
}

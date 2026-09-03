<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Storage\HitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * The generic decoy home at / in public mode: a plausible sign-in page with NO funnypot branding, and
 * three bot-only lures (comment URL, invisible link, hidden form) that point at the /admin/root/* decoys
 * the router forwards to the honeypot. A credential POST is captured.
 */
final class HomeControllerTest extends TestCase
{
    private function controller(HitStore $store): HomeController
    {
        // A Geo over a missing db degrades to an empty lookup — the home page never needs real geo.
        $geo = new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());

        return new HomeController($store, $geo, AppConfig::fromEnv(sys_get_temp_dir()), sys_get_temp_dir());
    }

    private function render(callable $call): string
    {
        ob_start();
        // The controller sends a Content-Type header; under phpunit output has already started, so
        // header() warns. Suppress just that — we assert on the echoed HTML body.
        @$call();

        return (string) ob_get_clean();
    }

    public function test_home_is_a_generic_login_with_no_funnypot_branding(): void
    {
        $html = $this->render(fn () => $this->controller(new HomeSpy())->index());

        self::assertStringContainsString('Sign in', $html);
        self::assertStringContainsString("method=post action='/'", $html);
        self::assertStringNotContainsString('Welcome to', $html);
        self::assertStringNotContainsString('funnypot', strtolower($html), 'the decoy home must not leak funnypot branding');
    }

    public function test_home_plants_the_three_bot_lures(): void
    {
        $html = $this->render(fn () => $this->controller(new HomeSpy())->index());

        self::assertMatchesRegularExpression('#<!--[^>]*/admin/root/html#', $html, 'lure 1: URL in an HTML comment');
        self::assertStringContainsString("href='/admin/root/link'", $html, 'lure 2: invisible off-screen link');
        self::assertStringContainsString("action='/admin/root/post'", $html, 'lure 3: hidden form');
        self::assertStringContainsString('display:none', $html);
    }

    public function test_credential_post_is_captured_then_funnels_to_the_admin_panel(): void
    {
        $spy = new HomeSpy();
        $_POST = ['username' => 'root', 'password' => 'hunter2'];
        $html = $this->render(fn () => $this->controller($spy)->login('203.0.113.9'));
        $_POST = [];

        // The credentials are still captured (the intel is the point).
        self::assertCount(1, $spy->appended);
        self::assertSame('login', $spy->appended[0]['event']);
        self::assertStringContainsString('user=root', (string) $spy->appended[0]['body']);
        self::assertStringContainsString('pass=hunter2', (string) $spy->appended[0]['body']);

        // Then funnelled into the no-auth admin-panel decoy — not re-rendered with an inline error.
        self::assertStringContainsString('/admin/access-login', $html);
        self::assertStringNotContainsString('Invalid username or password', $html);
    }

    // --- FP-0295: the real operator login overlaid on the decoy ---

    /**
     * Build a HomeController with a REAL AdminAuth over a temp sqlite, an operator credential seeded,
     * and an AppConfig whose adminUser/funnypotPath are set via the environment fromEnv() reads.
     *
     * @return array{0:HomeController,1:AdminAuth,2:string} [controller, auth, dashboardPath]
     */
    private function overlay(HitStore $store, string $adminUser, string $seedPassword): array
    {
        $dir = sys_get_temp_dir() . '/fp-0295-' . uniqid();
        @mkdir($dir, 0777, true);
        putenv('FUNNYPOT_ADMIN_USER=' . $adminUser);
        putenv('FUNNYPOT_APP_PATH=ctrl');
        $config = AppConfig::fromEnv($dir);
        putenv('FUNNYPOT_ADMIN_USER');   // unset so other tests are unaffected
        putenv('FUNNYPOT_APP_PATH');

        $auth = new AdminAuth($dir . '/admin.sqlite');
        if ($adminUser !== '' && $seedPassword !== '') {
            $auth->createOrResetUser($adminUser, $seedPassword);
        }
        $geo = new \Geo($dir . '/no-geo');
        $home = new HomeController($store, $geo, $config, $dir, null, null, $auth);

        return [$home, $auth, $config->funnypotPath];
    }

    public function test_correct_operator_credentials_mint_a_real_session_and_redirect_to_the_dashboard(): void
    {
        $spy = new HomeSpy();
        [$home, $auth, $dash] = $this->overlay($spy, 'op-7f3a', 's3cret-pw');

        $_POST = ['username' => 'op-7f3a', 'password' => 's3cret-pw'];
        $html = $this->render(fn () => $home->login('198.51.100.7'));
        $_POST = [];

        // Redirects to the dashboard, NOT the decoy panel.
        self::assertStringContainsString('url=' . $dash, $html);
        self::assertStringNotContainsString('/admin/access-login', $html);
        // A real session was minted and is live (AdminAuth set $_COOKIE in-process for the same request).
        self::assertTrue($auth->check(), 'a successful operator login must mint a resolvable session');
        self::assertSame('op-7f3a', $auth->currentUser());
        // The operator password is NEVER written to the hit store — only AdminAuth's own audit records it.
        self::assertCount(0, $spy->appended, 'the real operator password must not land in the hit store');
        $attempts = $auth->attempts();
        self::assertCount(1, $attempts);
        self::assertSame('ok', $attempts[0]['result']);
        unset($_COOKIE[AdminAuth::COOKIE]);
    }

    public function test_correct_username_wrong_password_falls_through_to_the_decoy(): void
    {
        $spy = new HomeSpy();
        [$home, $auth] = $this->overlay($spy, 'op-7f3a', 's3cret-pw');

        $_POST = ['username' => 'op-7f3a', 'password' => 'wrong'];
        $html = $this->render(fn () => $home->login('198.51.100.8'));
        $_POST = [];

        // Byte-identical decoy: funnelled to the panel, creds captured.
        self::assertStringContainsString('/admin/access-login', $html);
        self::assertCount(1, $spy->appended);
        self::assertStringContainsString('user=op-7f3a', (string) $spy->appended[0]['body']);
        // AdminAuth WAS consulted (username matched) and recorded a failure.
        $attempts = $auth->attempts();
        self::assertCount(1, $attempts);
        self::assertSame('fail', $attempts[0]['result']);
    }

    public function test_non_matching_username_never_runs_argon2id(): void
    {
        $spy = new HomeSpy();
        [$home, $auth] = $this->overlay($spy, 'op-7f3a', 's3cret-pw');

        $_POST = ['username' => 'admin', 'password' => 'whatever'];
        $html = $this->render(fn () => $home->login('198.51.100.9'));
        $_POST = [];

        // Pure decoy, and — the load-bearing assertion — AdminAuth::login was NEVER called, so the
        // deliberately-slow Argon2id verify did not run: there is no login_attempts row at all.
        self::assertStringContainsString('/admin/access-login', $html);
        self::assertCount(1, $spy->appended);
        self::assertCount(0, $auth->attempts(), 'a non-matching username must not reach the Argon2id verify');
    }

    public function test_empty_operator_username_disables_the_overlay(): void
    {
        $spy = new HomeSpy();
        [$home, $auth] = $this->overlay($spy, '', '');

        // Even a blank-vs-blank username must not authenticate when the overlay is disabled.
        $_POST = ['username' => '', 'password' => ''];
        $html = $this->render(fn () => $home->login('198.51.100.10'));
        $_POST = [];

        self::assertStringContainsString('/admin/access-login', $html);
        self::assertCount(0, $auth->attempts(), 'the overlay must be inert when no operator username is set');
    }
}

/** Minimal HitStore recording appends; every other method inert. */
final class HomeSpy implements HitStore
{
    /** @var array<int,array<string,mixed>> */
    public array $appended = [];

    public function append(array $entry): void
    {
        $this->appended[] = $entry;
    }

    public function delta(int $cursor, array $filters = []): array
    {
        return ['cursor' => 0, 'reset' => false, 'rows' => []];
    }

    public function older(int $skip, array $filters = []): array
    {
        return ['rows' => [], 'more' => false];
    }

    public function stats(): array
    {
        return [];
    }

    public function widgets(): array
    {
        return [];
    }

    public function prune(int $keep): void
    {
    }

    public function clear(): void
    {
    }

    public function import(): int
    {
        return 0;
    }

    public function probeVelocity(string $ip): array
    {
        return ['recent' => 0, 'extended' => 0];
    }

    public function recentEventCount(string $ip, string $event, int $sinceSeconds): int
    {
        return 0;
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
    }

    public function isBulkFlagged(string $ip): bool
    {
        return false;
    }
}

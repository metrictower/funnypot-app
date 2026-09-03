<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Storage\HitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * The stealth-mode corporate front's /login and the FP-0295 real-operator-login overlaid on it: an
 * exact operator-username POST is verified with AdminAuth and, on success, redirects to the stealth
 * dashboard; every other credential is the byte-identical "invalid" re-render decoy.
 */
final class CorporateControllerTest extends TestCase
{
    private function render(callable $call): string
    {
        ob_start();
        @$call();

        return (string) ob_get_clean();
    }

    /**
     * @return array{0:CorporateController,1:AdminAuth,2:string} [controller, auth, dashboardPath]
     */
    private function overlay(HitStore $store, string $adminUser, string $seedPassword): array
    {
        $dir = sys_get_temp_dir() . '/fp-0295-corp-' . uniqid();
        @mkdir($dir, 0777, true);
        putenv('FUNNYPOT_ADMIN_USER=' . $adminUser);
        putenv('FUNNYPOT_DASHBOARD_PATH=/hidden-ops/');
        $config = AppConfig::fromEnv($dir);
        putenv('FUNNYPOT_ADMIN_USER');
        putenv('FUNNYPOT_DASHBOARD_PATH');

        $auth = new AdminAuth($dir . '/admin.sqlite');
        if ($adminUser !== '' && $seedPassword !== '') {
            $auth->createOrResetUser($adminUser, $seedPassword);
        }
        $geo = new \Geo($dir . '/no-geo');
        $corp = new CorporateController($store, $geo, $config, $dir, null, null, $auth);

        return [$corp, $auth, rtrim($config->dashboardPath, '/')];
    }

    public function test_get_renders_the_login_form(): void
    {
        $spy = new CorpHitSpy();
        [$corp] = $this->overlay($spy, 'op-9c2e', 'pw');
        $html = $this->render(fn () => $corp->login('GET', '203.0.113.1'));

        self::assertStringContainsString('Sign in', $html);
        self::assertCount(0, $spy->appended);
    }

    public function test_correct_operator_credentials_redirect_to_the_stealth_dashboard(): void
    {
        $spy = new CorpHitSpy();
        [$corp, $auth, $dash] = $this->overlay($spy, 'op-9c2e', 's3cret-pw');

        $_POST = ['username' => 'op-9c2e', 'password' => 's3cret-pw'];
        $html = $this->render(fn () => $corp->login('POST', '203.0.113.2'));
        $_POST = [];

        self::assertStringContainsString('url=' . $dash, $html);
        self::assertStringNotContainsString('Invalid username or password', $html);
        self::assertTrue($auth->check(), 'a successful operator login must mint a resolvable session');
        self::assertCount(0, $spy->appended, 'the real operator password must not land in the hit store');
        $attempts = $auth->attempts();
        self::assertCount(1, $attempts);
        self::assertSame('ok', $attempts[0]['result']);
        unset($_COOKIE[AdminAuth::COOKIE]);
    }

    public function test_correct_username_wrong_password_re_renders_the_invalid_decoy(): void
    {
        $spy = new CorpHitSpy();
        [$corp, $auth] = $this->overlay($spy, 'op-9c2e', 's3cret-pw');

        $_POST = ['username' => 'op-9c2e', 'password' => 'nope'];
        $html = $this->render(fn () => $corp->login('POST', '203.0.113.3'));
        $_POST = [];

        self::assertStringContainsString('Invalid username or password', $html);
        self::assertCount(1, $spy->appended);
        self::assertStringContainsString('user=op-9c2e', (string) $spy->appended[0]['body']);
        self::assertSame('fail', $auth->attempts()[0]['result'] ?? null);
    }

    public function test_non_matching_username_never_runs_argon2id(): void
    {
        $spy = new CorpHitSpy();
        [$corp, $auth] = $this->overlay($spy, 'op-9c2e', 's3cret-pw');

        $_POST = ['username' => 'admin', 'password' => 'whatever'];
        $html = $this->render(fn () => $corp->login('POST', '203.0.113.4'));
        $_POST = [];

        self::assertStringContainsString('Invalid username or password', $html);
        self::assertCount(1, $spy->appended);
        self::assertCount(0, $auth->attempts(), 'a non-matching username must not reach the Argon2id verify');
    }
}

/** Minimal HitStore recording appends; every other method inert. */
final class CorpHitSpy implements HitStore
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

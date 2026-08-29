<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

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

    public function test_credential_post_is_captured(): void
    {
        $spy = new HomeSpy();
        $_POST = ['username' => 'root', 'password' => 'hunter2'];
        $this->render(fn () => $this->controller($spy)->login('203.0.113.9'));
        $_POST = [];

        self::assertCount(1, $spy->appended);
        self::assertSame('login', $spy->appended[0]['event']);
        self::assertStringContainsString('user=root', (string) $spy->appended[0]['body']);
        self::assertStringContainsString('pass=hunter2', (string) $spy->appended[0]['body']);
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

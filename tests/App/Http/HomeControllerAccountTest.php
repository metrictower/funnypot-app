<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HomeController;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * The public `/` page with the account seam: unarmed every byte is as before; armed, a live session
 * gets the account home, the signed-out page gains exactly one sign-up link (its hidden links
 * untouched), a sign-in naming an account this source created signs in, and every other credential
 * takes the unchanged funnel, byte for byte.
 */
final class HomeControllerAccountTest extends TestCase
{
    private ?MintHarness $h = null;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite required');
        }
        $this->h = new MintHarness(true);
    }

    protected function tearDown(): void
    {
        $this->h?->cleanup();
        $_POST = [];
    }

    private function home(bool $armed): HomeController
    {
        return new HomeController($this->h->hits, new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()), AppConfig::fromEnv(sys_get_temp_dir()), sys_get_temp_dir(), null, null, null, $armed ? $this->h->front : null);
    }

    private static function render(callable $call): string
    {
        ob_start();
        @$call();

        return (string) ob_get_clean();
    }

    public function test_signed_out_page_is_todays_page_plus_one_sign_up_link(): void
    {
        $ctx = new RequestContext('GET', '/', '', []);
        $unarmed = self::render(fn () => $this->home(false)->index($ctx, MintHarness::IP));
        $legacy = self::render(fn () => $this->home(false)->index());
        self::assertSame($legacy, $unarmed, 'unarmed, the new arguments change nothing');
        $armed = self::render(fn () => $this->home(true)->index($ctx, MintHarness::IP));
        $link = "<p style='font-size:.85rem;margin:1rem 0 0'><a href='/join'>Create an account</a></p>";
        self::assertSame(1, substr_count($armed, $link));
        self::assertSame($unarmed, str_replace($link, '', $armed), 'the only difference is the sign-up link');
        foreach (['/admin/root/html', '/admin/root/link', '/admin/root/post'] as $lure) {
            self::assertStringContainsString($lure, $armed, 'the hidden links stay exactly as they were');
        }
    }

    public function test_a_live_session_gets_the_account_home_and_a_lapsed_one_the_sign_in_page(): void
    {
        $this->h->join();
        $cookie = 'session=' . $this->h->jars['default']['session'];
        $page = self::render(fn () => $this->home(true)->index(new RequestContext('GET', '/', '', ['Cookie' => $cookie]), MintHarness::IP));
        self::assertStringContainsString('Signed in as artex1', $page);
        self::assertStringNotContainsString('/admin/', $page);
        $this->h->now += 30000;
        $page = self::render(fn () => $this->home(true)->index(new RequestContext('GET', '/', '', ['Cookie' => $cookie]), MintHarness::IP));
        self::assertStringContainsString('<h1>Sign in</h1>', $page, 'an expired session reads as signed out');
    }

    public function test_sign_in_for_own_accounts_and_the_unchanged_funnel_for_everything_else(): void
    {
        $this->h->join();
        $funnel = function (bool $armed, string $user, string $pass, string $ip): string {
            $_POST = ['username' => $user, 'password' => $pass];

            return self::render(fn () => $this->home($armed)->login($ip, new RequestContext('POST', '/', '', [])));
        };
        foreach ([['admin', 'whatever', MintHarness::IP], ['someone', 'x', MintHarness::IP], ['artex1', 'Passw0rd!x', '45.79.200.9']] as [$u, $p, $ip]) {
            self::assertSame($funnel(false, $u, $p, $ip), $funnel(true, $u, $p, $ip), "{$u}@{$ip}: byte-identical to unarmed");
            self::assertStringContainsString('/admin/access-login', $funnel(true, $u, $p, $ip));
        }
        $wrong = $funnel(true, 'artex1', 'wrong-pass', MintHarness::IP);
        self::assertStringContainsString('Incorrect username or password.', $wrong);
        self::assertStringContainsString("<a href='/join'>Create an account</a>", $wrong);
        $ok = $funnel(true, 'artex1', 'Passw0rd!x', MintHarness::IP);
        self::assertStringContainsString('url=/', $ok);
        self::assertStringNotContainsString('/admin/access-login', $ok);
    }
}

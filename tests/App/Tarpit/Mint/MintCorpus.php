<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\Core\Honeypot;
use Funnypot\Tests\App\Identity\IdentityTestSupport;

/**
 * The request corpus the ownership and parity tests share: every owned route under its benign input
 * (the bodies the surface's own pages and API send), the attack-shaped inputs, and the paths that
 * must stay unowned. Benign free text avoids words core's CRS reads as shell verbs in a form value
 * (`export`, `python sdk`), a known false-positive class recorded in the ticket.
 */
final class MintCorpus
{
    public const F = ['Content-Type' => 'application/x-www-form-urlencoded'];
    public const J = ['Content-Type' => 'application/json'];
    public const CSRF = 'csrf_token=AAAAAAAAAAAAAAAAAAAAAAAAAAA';
    public const BEARER = 'pal_pat_0123456789abcdefABCDEF012345678';

    /** Owned paths the benign-input invariant exempts: core's /login-suffix oracle fires on any POST. */
    public const EXEMPT = ['POST /api/v2/auth/login', 'POST /v2/auth/login'];

    /** FP-0814's console grammar C (its spec §1.2): the three lure paths and any web-shell file name. */
    public const FP0814_CONSOLE_PATHS = ['/admin/root/html', '/admin/root/post', '/admin/root/link'];
    public const FP0814_SHELL_FILE = '~(?:^|/)(c99|wso|r57|b374k|shell|cmd|alfa|indoxploit)\.php$~i';

    public static function engine(): Honeypot
    {
        return Honeypot::default(IdentityTestSupport::coreConfigFactory()->build(AppConfig::fromEnv(sys_get_temp_dir()), EmulationPolicy::fromPackage(null), static fn (): string => 'x'));
    }

    public static function slug(): string
    {
        return \Funnypot\App\Tarpit\Mint\MintPersona::fromSeed(IdentityTestSupport::httpIdentity()->personaSeed())->slug;
    }

    /** @return list<string> one concrete path per owned route, both API spellings */
    public static function ownedPaths(string $slug): array
    {
        $paths = [
            '/join', '/signout', '/settings/profile', '/settings/security', '/settings/confirm', '/settings/tokens', '/settings/tokens/new',
            '/settings/tokens/12/delete', '/settings/applications', '/settings/applications/new', '/settings/applications/12',
            '/settings/applications/12/secrets', '/settings/applications/12/delete', '/login/oauth/authorize', '/login/oauth/access_token',
            '/orgs/' . $slug . '/sso', '/idp/' . $slug . '/signin', '/docs/api',
        ];
        foreach (['/api/v2/', '/v2/'] as $pre) {
            foreach (['user', 'user/orgs', 'user/orders', 'users', 'users/jdoe', 'orgs/' . $slug, 'orgs/' . $slug . '/members', 'orders', 'orders/10422', 'orders/exports', 'auth/login'] as $a) {
                $paths[] = $pre . $a;
            }
        }

        return $paths;
    }

    /**
     * Each owned route with the input the surface itself sends it.
     *
     * @return list<array{0:string,1:string,2:string,3:?string,4:array<string,string>}> [method, path, query, body, headers]
     */
    public static function benign(string $slug): array
    {
        $c = self::CSRF;
        $F = self::F;
        $B = ['Authorization' => 'Bearer ' . self::BEARER];
        $rows = [
            ['GET', '/join', '', null, []],
            ['POST', '/join', '', "{$c}&username=artex1&email=artex1%40example.com&password=Passw0rd%21x&password_confirmation=Passw0rd%21x", $F],
            ['GET', '/signout', '', null, []],
            ['POST', '/signout', '', $c, $F],
            ['GET', '/settings/profile', '', null, []],
            ['POST', '/settings/profile', '', "{$c}&name=Ar+Tex&bio=build%2Fci+owner%3A+team%40example.com%2C+v2.0-rc_1+%2B1%3Dok", $F],
            ['GET', '/settings/security', '', null, []],
            ['POST', '/settings/security', '', "{$c}&otp=123456", $F],
            ['GET', '/settings/confirm', '', null, []],
            ['POST', '/settings/confirm', '', "{$c}&password=Passw0rd%21x&otp=123456", $F],
            ['POST', '/settings/confirm', '', "{$c}&password=Passw0rd%21x&recovery_code=abcde-23456", $F],
            ['GET', '/settings/tokens', '', null, []],
            ['GET', '/settings/tokens/new', 'scopes=read%3Auser%2Corders%3Aread', null, []],
            ['POST', '/settings/tokens', '', "{$c}&note=deploy+key+for+ci%2Fcd%3A+build%40host%2B1%3Dok%2C+v2.0-rc_1&expiration=30&scopes%5B%5D=read%3Auser&scopes%5B%5D=orders%3Aread&scopes%5B%5D=orders%3Aexport", $F],
            ['POST', '/settings/tokens/12/delete', '', $c, $F],
            ['GET', '/settings/applications', '', null, []],
            ['GET', '/settings/applications/new', '', null, []],
            ['POST', '/settings/applications', '', "{$c}&name=my-app&homepage_url=https%3A%2F%2Fapp.example.com%2Fa%3Fb%3Dc%26d%3De&callback_url=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback%3Fx%3D1&description=build+bot+for+ci%2Fcd%3A+v2.0-rc_1", $F],
            ['GET', '/settings/applications/12', '', null, []],
            ['POST', '/settings/applications/12/secrets', '', $c, $F],
            ['POST', '/settings/applications/12/delete', '', $c, $F],
            ['GET', '/login/oauth/authorize', 'client_id=0123456789abcdef0123&redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback%3Fx%3D1&scope=read%3Auser&state=af0ifjsldkj', null, []],
            ['POST', '/login/oauth/authorize', '', "{$c}&authorization_request=ab12cd34ef56&authorize=1", $F],
            ['POST', '/login/oauth/authorize', '', "{$c}&authorization_request=ab12cd34ef56&deny=1", $F],
            ['POST', '/login/oauth/access_token', '', 'grant_type=authorization_code&code=0123456789abcdef0123&client_id=0123456789abcdef0123&client_secret=0123456789abcdef0123456789abcdef01234567&redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback%3Fx%3D1', $F],
            ['POST', '/login/oauth/access_token', '', 'grant_type=refresh_token&refresh_token=pal_ort_0123456789abcdefABCDEF012345678&client_id=0123456789abcdef0123&client_secret=0123456789abcdef0123456789abcdef01234567', $F],
            ['POST', '/login/oauth/access_token', '', '{"grant_type":"authorization_code","code":"0123456789abcdef0123","client_id":"0123456789abcdef0123","client_secret":"0123456789abcdef0123456789abcdef01234567"}', self::J],
            ['GET', '/orgs/' . $slug . '/sso', 'authorization_request=ab12cd34ef56', null, []],
            ['POST', '/orgs/' . $slug . '/sso', '', "{$c}&authorization_request=ab12cd34ef56", $F],
            ['GET', '/idp/' . $slug . '/signin', '', null, []],
            ['POST', '/idp/' . $slug . '/signin', '', "{$c}&username=artex1%40example.com&password=Passw0rd%21x", $F],
            ['GET', '/docs/api', '', null, []],
        ];
        foreach (['/api/v2/', '/v2/'] as $pre) {
            foreach (['user', 'user/orgs', 'user/orders', 'users', 'users/jdoe', 'orgs/' . $slug, 'orgs/' . $slug . '/members', 'orders', 'orders/10422'] as $a) {
                $rows[] = ['GET', $pre . $a, '', null, $B];
                $rows[] = ['GET', $pre . $a, 'access_token=' . self::BEARER, null, []];
                $rows[] = ['GET', $pre . $a, '', null, ['X-Api-Key' => self::BEARER]];
            }
            $rows[] = ['PATCH', $pre . 'user', '', '{"name":"Ar Tex","bio":"build/ci owner: team@example.com, v2.0-rc_1 +1=ok"}', $B + self::J];
            $rows[] = ['POST', $pre . 'orders/exports', '', '{"format":"csv","since":"2024-01-01"}', $B + self::J];
            $rows[] = ['POST', $pre . 'orders/exports', '', 'format=csv&since=2024-01-01', $B + $F];
            $rows[] = ['POST', $pre . 'auth/login', '', '{"username":"artex1","password":"Passw0rd!x"}', self::J];
        }

        return $rows;
    }

    /**
     * Attack-shaped inputs and the template family core reports for each on an owned path.
     *
     * @return array<string,array{0:string,1:string,2:?string,3:array<string,string>,4:string}> name => [method, query, body, headers, expected template]
     */
    public static function attacks(): array
    {
        return [
            'xss-q' => ['GET', 'state=%3Cscript%3Ealert(1)%3C%2Fscript%3E', null, [], 'attack-xss'],
            'xss-body' => ['POST', '', 'note=%3Cscript%3Ealert(1)%3C%2Fscript%3E', self::F, 'attack-xss'],
            'sqli-q' => ['GET', 'id=1%20union%20select%201,2--', null, [], 'attack-sqli'],
            'ssti-json' => ['PATCH', '', '{"name":"{{7*7}}"}', self::J, 'attack-ssti-numeric'],
            'lfi-q' => ['GET', 'page=..%2F..%2F..%2F..%2Fetc%2Fpasswd', null, [], 'attack-lfi-unix'],
            'rce-body' => ['POST', '', 'name=%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D', self::F, 'attack-crs-rce'],
            'cmdi-q' => ['GET', 'x=%3Bid', null, [], 'attack-cmdi-unix'],
            'cmd-body' => ['POST', '', 'note=x&cmd=id', self::F, 'attack-webshell-panel'],
            'command-q' => ['GET', 'command=ls', null, [], 'attack-webshell-panel'],
            'exec-body' => ['POST', '', 'exec=whoami', self::F, 'attack-webshell-panel'],
            'sleep-body' => ['POST', '', 'username=a%27+AND+SLEEP(3)--+', self::F, 'attack-sqli'],
        ];
    }

    /** @return list<string> paths that must never be owned, whatever core answers */
    public static function notOwned(): array
    {
        return [
            '/', '/api/v2', '/api/v2/', '/settings', '/logout', '/oauth/authorize', '/user/sign_up', '/users/sign_up', '/login', '/signup',
            '/register', '/dashboard', '/users', '/auth/login', '/orders/1', '/api/v2/info', '/api/v2/login', '/api/v2/customers',
            '/v2/x', '/v2', '/v2/_catalog', '/v2/api-docs', '/api/v2/users/backup.zip', '/api/v2/users/db.sql', '/api/v2/users/shell.php',
            '/api/v2/users/Shell.PHP', '/v2/users/cmd.Php', '/api/v2/backup.zip', '/api/v2/www.tar.gz', '/settings/applications/backup.zip',
            '/settings/tokens/1/delete.php', '/orgs/other/sso', '/idp/other/signin', '/idp/x/login', '/api/v2/orders/export',
            '/v2/orders/export', '/settings/cluster', '/settings/general', '/settings/plugins', '/admin/root/html', '/admin/access-login',
            '/settings/tokens/abc/delete', '/settings/applications/ab', '/api/v2/users/-x', '/api/v2/orders/abcdefghijklmnopqrstuvw',
            '/settings/applications/abcdefgh', '/api/v2/orders/' . str_repeat('1', 21), '/v2/orders/ABC123',
        ];
    }
}

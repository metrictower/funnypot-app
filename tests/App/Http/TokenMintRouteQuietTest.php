<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Mint\MintContext;
use Funnypot\App\Tarpit\Mint\MintKeys;
use Funnypot\App\Tarpit\Mint\MintPersona;
use Funnypot\App\Tarpit\Mint\MintRoutes;
use Funnypot\App\Tarpit\Mint\MintState;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Mint\MintCorpus;
use PHPUnit\Framework\TestCase;

/**
 * Every owned route, for several personas (their organisation slug, their member logins and ids the
 * surface really issues), sent the way an ordinary client sends it: a GET, and a POST with a benign form
 * body and with the same fields as JSON, each with the route's own field names and realistic values (and
 * a real access token on the API). None may read as an attack to core (no match, no attack tag) or to the
 * app's fall-through classifier, so a route name core keys on fails here. `/settings/confirm` was one: core
 * read any JSON body on it as XSS, so confirm-access lives at `/settings/reauth`. The only exception is the
 * recorded one: a POST to an `auth/login` path, which core's /login-suffix oracle claims.
 */
final class TokenMintRouteQuietTest extends TestCase
{
    /** Pattern routes, with the template each instantiates. */
    private const PATTERNS = [
        'token_delete' => '/settings/tokens/{id}/delete',
        'app_show' => '/settings/applications/{id}',
        'app_secret' => '/settings/applications/{id}/secrets',
        'app_delete' => '/settings/applications/{id}/delete',
        'sso' => '/orgs/{org}/sso',
        'idp' => '/idp/{org}/signin',
        'users_login' => 'users/{login}',
        'orgs_org' => 'orgs/{org}',
        'orgs_members' => 'orgs/{org}/members',
        'orders_id' => 'orders/{id}',
    ];

    private static ?Honeypot $engine = null;

    private static function engine(): Honeypot
    {
        return self::$engine ??= MintCorpus::engine();
    }

    /**
     * The fields each route's own form or API call carries, with realistic values.
     *
     * @param array<string,string> $v issued values
     * @return array<string,mixed>
     */
    private static function fields(string $route, array $v, MintPersona $p): array
    {
        $profile = ['name' => 'Ar Tex', 'bio' => 'Platform engineer, release tooling and on-call for the build farm.'];

        return match ($route) {
            'join' => ['username' => 'artex1', 'email' => 'artex1@example.com', 'password' => 'Passw0rd!x', 'password_confirmation' => 'Passw0rd!x'],
            'profile', 'user' => $profile,
            'security' => ['otp' => '482913'],
            'confirm' => ['password' => 'Passw0rd!x', 'otp' => '482913', 'recovery_code' => $v['recovery']],
            'tokens' => ['note' => 'deploy key for the release job', 'expiration' => '30', 'scopes' => ['read:user', 'orders:read']],
            'apps' => ['name' => 'release-notes', 'homepage_url' => 'https://app.example.com/', 'callback_url' => 'https://app.example.com/oauth/callback', 'description' => 'Posts release notes to the team channel'],
            'authorize' => ['authorization_request' => $v['request'], 'authorize' => '1'],
            'access_token' => ['grant_type' => 'authorization_code', 'code' => $v['code'], 'client_id' => $v['client'], 'client_secret' => $v['secret'], 'redirect_uri' => 'https://app.example.com/oauth/callback'],
            'sso' => ['authorization_request' => $v['request']],
            'idp' => ['username' => array_key_first($p->members) . '@' . $p->domain, 'password' => 'Passw0rd!x'],
            'orders_exports' => ['format' => 'csv', 'since' => '2024-01-01'],
            'auth_login' => ['username' => 'artex1', 'password' => 'Passw0rd!x'],
            default => ['note' => 'ok'],
        };
    }

    /** @return array{0:array<string,string>,1:MintPersona} values the surface issued for this persona */
    private static function issued(int $seed): array
    {
        $c = new MintContext(new MintKeys(hash('sha256', 'route-quiet|' . $seed, true)), MintPersona::fromSeed($seed), new TokenMintStore(sys_get_temp_dir() . '/unused-rq.sqlite'), static fn (): int => 1763800000);
        $c->issuingWith(IssuedValue::forEngine(self::engine(), new AttackClassifier()));
        $s = MintState::fresh(1763800000, substr(hash('sha256', 'e' . $seed), 0, 16));
        $pos = $s->addAccount('artex1', 'artex1@example.com', 'pw', 1763800000);
        $kref = substr(hash('sha256', 'k' . $seed, true), 0, 16);
        [, $pat] = $c->addToken($s, $pos, $kref, 'pat', 'ci', ['read:user'], 0, null, 1763800000);

        return [[
            'csrf' => $c->csrfToken('sid' . $seed, 'token_create', 0, 1763800000),
            'id' => $c->appPublicId($kref, $s, 1, 1),
            'order' => '10422',
            'client' => $c->clientId($kref, $s, 1, 1),
            'secret' => $c->clientSecret($kref, $s, 1, 1, 0),
            'code' => $c->oauthCode($kref, $s, 1, 1),
            'request' => $c->requestId($kref, $s, 1),
            'recovery' => $c->recoveryCodes($kref, $s, 1, 1)[0],
            'pat' => $pat,
        ], $c->persona];
    }

    /** @return list<array{0:string,1:string,2:bool}> [route id, path, is API] */
    private static function paths(MintPersona $p, array $v): array
    {
        $out = [];
        foreach (MintRoutes::EXACT as $path => [$route]) {
            $out[] = [$route, $path, false];
        }
        foreach (self::PATTERNS as $route => $tpl) {
            $api = !str_starts_with($tpl, '/');
            foreach ($route === 'users_login' ? array_keys($p->members) : [null] as $login) {
                $path = strtr($tpl, ['{id}' => $route === 'orders_id' ? $v['order'] : $v['id'], '{org}' => $p->slug, '{login}' => (string) $login]);
                if ($api) {
                    foreach (MintRoutes::API_PREFIXES as $prefix) {
                        $out[] = [$route, $prefix . $path, true];
                    }
                } else {
                    $out[] = [$route, $path, false];
                }
            }
        }
        foreach (MintRoutes::API_EXACT as $rest => $route) {
            foreach (MintRoutes::API_PREFIXES as $prefix) {
                $out[] = [$route, $prefix . $rest, true];
            }
        }

        return $out;
    }

    private static function trips(RequestContext $r): ?string
    {
        $d = self::engine()->detect($r);
        if ($d->matched || in_array('attack', $d->tags(), true)) {
            return implode(',', array_slice($d->templateIds(), 0, 3));
        }
        $class = (new AttackClassifier())->classify($r);

        return $class === null ? null : 'payload-' . $class;
    }

    public function test_every_owned_route_is_quiet_for_ordinary_get_form_and_json_requests(): void
    {
        $tripped = [];
        $covered = [];
        $requests = 0;
        for ($seed = 1; $seed <= 8; $seed++) {
            [$v, $p] = self::issued($seed);
            $r = new MintRoutes($p->slug);
            foreach (self::paths($p, $v) as [$route, $path, $api]) {
                $match = $r->match($path);
                self::assertNotNull($match, "{$path} is owned");
                self::assertSame($route, $match['route'], $path);
                $covered[$route] = true;
                $fields = self::fields($route, $v, $p) + ($api ? [] : ['csrf_token' => $v['csrf']]);
                $auth = $api ? ['Authorization' => 'Bearer ' . $v['pat']] : ['Cookie' => 'session=' . str_repeat('Q7', 30)];
                $sends = [
                    'GET' => new RequestContext('GET', $path, '', $auth),
                    'POST form' => new RequestContext('POST', $path, '', $auth + MintCorpus::F, http_build_query($fields)),
                    'POST JSON' => new RequestContext('POST', $path, '', $auth + MintCorpus::J, (string) json_encode($fields, JSON_UNESCAPED_SLASHES)),
                ];
                foreach ($sends as $how => $ctx) {
                    $requests++;
                    if ($how !== 'GET' && in_array('POST ' . $path, MintCorpus::EXEMPT, true)) {
                        continue;
                    }
                    if (($t = self::trips($ctx)) !== null) {
                        $tripped[] = "{$how} {$path} -> {$t}";
                    }
                }
            }
        }
        $all = array_merge(array_column(MintRoutes::EXACT, 0), array_values(MintRoutes::API_EXACT), array_keys(self::PATTERNS));
        self::assertSame([], array_values(array_diff($all, array_keys($covered))), 'every route is swept');
        self::assertGreaterThan(1000, $requests);
        self::assertSame([], array_values(array_unique($tripped)), 'these routes read as attacks for ordinary requests; rename them');
    }

    public function test_the_old_confirm_path_is_gone_and_would_trip(): void
    {
        self::assertFalse((new MintRoutes(MintCorpus::slug()))->owns('/settings/confirm'));
        self::assertNotNull(self::trips(new RequestContext('POST', '/settings/confirm', '', MintCorpus::J, '{"password":"Passw0rd!x"}')), 'why it was renamed');
        self::assertNull(self::trips(new RequestContext('POST', '/settings/reauth', '', MintCorpus::J, '{"password":"Passw0rd!x"}')));
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\AccountFront;
use Funnypot\App\Tarpit\Mint\MintPersona;
use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\App\Tarpit\Mint\Totp;
use Funnypot\Core\RequestContext;

/**
 * Walks the account surface for one persona seed through every page and answer kind it renders:
 * signed out and in, every form's success, validation and friction answers, the OAuth pages and
 * token endpoint, the API's walls and errors, SSO and the identity provider. Returns every plan, so a
 * test can check all of them (links, fingerprint) without a hand-kept list of pages going stale.
 */
final class MintCrawl
{
    public int $now = 1763800000;
    public TokenMintDecoy $decoy;
    public AccountFront $front;
    public MintPersona $persona;
    private string $dir;
    private ?string $cookie = null;

    /** @var list<array{0:string,1:MintPlan}> label => plan */
    public array $plans = [];

    public function __construct(public int $seed)
    {
        $this->dir = sys_get_temp_dir() . '/fp0815crawl_' . bin2hex(random_bytes(5));
        mkdir($this->dir, 0777, true);
        $this->decoy = TokenMintDecoy::build(MintHarness::KEY, $seed, new TokenMintStore($this->dir . '/tm.sqlite'), true, null, fn (): int => $this->now, static function (): void {
        });
        $this->front = new AccountFront($this->decoy->context());
        $this->persona = MintPersona::fromSeed($seed);
    }

    public function cleanup(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    public function send(string $method, string $path, string $query = '', ?array $fields = null, array $headers = [], ?string $raw = null, string $ip = '45.79.50.50'): MintPlan
    {
        $this->now += 3;
        if ($this->cookie !== null && !isset($headers['Cookie'])) {
            $headers['Cookie'] = 'session=' . $this->cookie;
        }
        $body = $raw ?? ($fields === null ? null : http_build_query($fields));
        if ($body !== null && !isset($headers['Content-Type'])) {
            $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        $p = $this->decoy->prepare(new RequestContext($method, $path, $query, $headers, $body), $ip);
        if ($p === null) {
            $e = $this->decoy->lastFault();
            throw new \RuntimeException("no answer for {$method} {$path}" . ($e ? ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() : ''));
        }
        foreach ($p->headers() as [$n, $v]) {
            if ($n === 'Set-Cookie' && preg_match('/\Asession=([^;]*)/', $v, $m) === 1) {
                $this->cookie = $m[1] === '' ? null : $m[1];
            }
        }
        $this->plans[] = [$method . ' ' . $path, $p];

        return $p;
    }

    private static function csrf(string $body, int $nth = 0): string
    {
        preg_match_all("/name=csrf_token value='([^']+)'/", $body, $m);

        return $m[1][$nth] ?? '';
    }

    private function signIn(): void
    {
        $r = $this->front->signIn(new RequestContext('POST', '/'), '45.79.50.50', 'artex1', 'Passw0rd!x');
        if (isset($r['cookie']) && preg_match('/\Asession=([^;]*)/', $r['cookie'], $m) === 1) {
            $this->cookie = $m[1];
        }
    }

    /** Retry a form past friction, keeping every answer it produced. */
    private function until(callable $attempt, callable $done, ?string $totp): MintPlan
    {
        for ($i = 0; $i < 60; $i++) {
            $this->now += 11;
            $p = $attempt();
            if ($done($p)) {
                return $p;
            }
            $loc = $p->header('Location');
            if ($loc === '/') {
                $this->signIn();
            } elseif ($loc === '/settings/confirm') {
                $page = $this->send('GET', '/settings/confirm');
                $f = ['csrf_token' => self::csrf($page->body), 'password' => 'Passw0rd!x'];
                if ($totp !== null) {
                    $this->now += 31;
                    $f['otp'] = Totp::code($totp, Totp::step($this->now));
                }
                $this->send('POST', '/settings/confirm', '', $f);
            } elseif ($p->status === 429) {
                $this->now += (int) ($p->header('Retry-After') ?? 60) + 1;
            }
        }
        throw new \RuntimeException('form never succeeded');
    }

    /** @return array{home:MintPlan} */
    public function run(): array
    {
        $slug = $this->persona->slug;
        // signed out
        foreach (['/join', '/idp/' . $slug . '/signin', '/docs/api', '/settings/tokens', '/settings/applications/abcdef012345', '/login/oauth/authorize', '/orgs/' . $slug . '/sso'] as $p) {
            $this->send('GET', $p);
        }
        foreach (['/api/v2/user', '/v2/users/nobody', '/api/v2/orders/12'] as $p) {
            $this->send('GET', $p);
            $this->send('GET', $p, '', null, ['Authorization' => 'Bearer ' . $this->persona->prefix . '_pat_' . str_repeat('A', 31)]);
        }
        $this->send('OPTIONS', '/settings/tokens');
        $this->send('PUT', '/api/v2/user', '', null, ['Content-Type' => 'application/json'], '{}');
        $this->send('DELETE', '/join');
        $this->send('POST', '/join', '', null, [], str_repeat('a', 17000));
        $this->send('POST', '/api/v2/user', '', null, ['Content-Type' => 'application/json'], str_repeat('a', 17000));
        foreach ([[], ['grant_type' => 'client_credentials'], ['grant_type' => 'password'], ['grant_type' => 'authorization_code', 'code' => str_repeat('0', 20)], ['grant_type' => 'refresh_token', 'refresh_token' => 'x']] as $f) {
            $this->send('POST', '/login/oauth/access_token', '', $f);
        }
        $this->send('POST', '/login/oauth/access_token', '', null, ['Content-Type' => 'application/json'], '[1]');
        $members = array_keys($this->persona->members);
        $this->send('POST', '/api/v2/auth/login', '', null, ['Content-Type' => 'application/json'], (string) json_encode(['username' => $members[0], 'password' => 'x']));
        $this->send('POST', '/v2/auth/login', '', null, ['Content-Type' => 'application/json'], '{}');
        $this->send('POST', '/v2/auth/login', '', null, ['Content-Type' => 'application/json'], '{"username":"nobody","password":"x"}');

        // sign-up
        $join = $this->send('GET', '/join');
        $this->send('POST', '/join', '', ['csrf_token' => 'bad']);
        $this->send('POST', '/join', '', ['csrf_token' => self::csrf($join->body), 'username' => '<x>', 'email' => 'bad', 'password' => 'short']);
        $this->send('POST', '/join', '', ['csrf_token' => self::csrf($join->body), 'username' => 'artex1', 'email' => 'a@example.com', 'password' => 'Passw0rd!x', 'password_confirmation' => 'Passw0rd!x']);
        $this->send('GET', '/join');
        $home = $this->front->home(new RequestContext('GET', '/', '', ['Cookie' => 'session=' . $this->cookie]), '45.79.50.50');

        // the API login and member reads
        $jwt = (string) (json_decode($this->send('POST', '/api/v2/auth/login', '', null, ['Content-Type' => 'application/json'], '{"username":"artex1","password":"Passw0rd!x"}')->body, true)['access_token'] ?? '');
        $this->send('POST', '/api/v2/auth/login', '', null, ['Content-Type' => 'application/json'], '{"username":"artex1","password":"wrong-one"}');
        foreach (['user', 'user/orgs', 'users/' . $members[0], 'users/artex1', 'users/nobody', 'orgs/' . $slug, 'orders'] as $a) {
            $this->send('GET', '/api/v2/' . $a, '', null, ['Authorization' => 'Bearer ' . $jwt]);
        }

        // profile, security, confirm
        $prof = $this->send('GET', '/settings/profile');
        $this->send('POST', '/settings/profile', '', ['csrf_token' => self::csrf($prof->body), 'name' => '<b>', 'bio' => str_repeat('a', 200)]);
        $this->send('POST', '/settings/profile', '', ['csrf_token' => self::csrf($prof->body), 'name' => 'Ar Tex', 'bio' => 'ci owner']);
        $this->send('POST', '/settings/profile', '', ['csrf_token' => 'stale']);
        $conf = $this->send('GET', '/settings/confirm');
        $this->send('POST', '/settings/confirm', '', ['csrf_token' => self::csrf($conf->body), 'password' => 'wrong-pass']);

        // tokens, through friction
        $new = $this->send('GET', '/settings/tokens/new', 'scopes=read:user,orders:read');
        $c = self::csrf($new->body);
        foreach ([['note' => '<script>', 'expiration' => '30', 'scopes' => ['read:user']], ['note' => 'n', 'expiration' => 'none', 'scopes' => ['read:user']], ['note' => 'n', 'expiration' => '30', 'scopes' => ['admin:org']], ['note' => 'n', 'expiration' => '30'], ['note' => 'n', 'expiration' => '30', 'scopes' => ['orders:read']]] as $f) {
            $this->send('POST', '/settings/tokens', '', ['csrf_token' => $c] + $f);
        }
        $mint = function (array $scopes, string $note): string {
            $this->until(function () use ($scopes, $note): MintPlan {
                $form = $this->send('GET', '/settings/tokens/new');

                return $this->send('POST', '/settings/tokens', '', ['csrf_token' => self::csrf($form->body), 'note' => $note . $this->now, 'expiration' => '30', 'scopes' => $scopes]);
            }, static fn (MintPlan $p): bool => $p->header('Location') === '/settings/tokens', $this->totp ?? null);
            $list = $this->send('GET', '/settings/tokens');
            preg_match('/([a-z]{2,4}_pat_[0-9A-Za-z]{31})/', $list->body, $m);

            return $m[1] ?? '';
        };
        $pat = $mint(['read:user'], 'ci ');
        foreach (['user', 'users', 'orders/9', 'user/orders', 'orgs/' . $slug . '/members'] as $a) {
            $this->send('GET', '/v2/' . $a, '', null, ['X-Api-Key' => $pat]);
        }
        $this->send('GET', '/api/v2/user', 'access_token=' . $pat);
        $this->send('PATCH', '/api/v2/user', '', null, ['Authorization' => 'Bearer ' . $pat, 'Content-Type' => 'application/json'], '{"name":"x"}');

        // two-factor, then a sensitive token, then the SSO wall and the identity provider
        $sec = $this->send('GET', '/settings/security');
        $this->send('POST', '/settings/security', '', ['csrf_token' => self::csrf($sec->body), 'otp' => '000000']);
        preg_match('/<p class=mono>([A-Z2-7]{32})<\/p>/', $sec->body, $sm);
        $this->totp = MintHarness::base32decode($sm[1]);
        $this->send('POST', '/settings/security', '', ['csrf_token' => self::csrf($sec->body), 'otp' => Totp::code($this->totp, Totp::step($this->now))]);
        $this->send('GET', '/settings/security');
        $orders = $mint(['orders:read', 'users:read'], 'orders ');
        $wall = $this->send('GET', '/api/v2/orders', '', null, ['Authorization' => 'Bearer ' . $orders]);
        $this->send('GET', '/api/v2/users', '', null, ['Authorization' => 'Bearer ' . $orders]);
        $url = (string) (json_decode($wall->body, true)['sso_url'] ?? '');
        $sso = $this->send('GET', '/orgs/' . $slug . '/sso', (string) parse_url($url, PHP_URL_QUERY));
        $this->send('POST', '/orgs/' . $slug . '/sso', '', ['csrf_token' => self::csrf($sso->body), 'authorization_request' => 'x']);
        $idp = $this->send('GET', '/idp/' . $slug . '/signin');
        for ($i = 0; $i < 6; $i++) {
            $this->send('POST', '/idp/' . $slug . '/signin', '', ['csrf_token' => self::csrf($idp->body), 'username' => $i % 2 === 0 ? 'artex1' : 'someone', 'password' => 'x']);
        }
        $this->send('POST', '/idp/' . $slug . '/signin', '', ['csrf_token' => 'x']);

        // OAuth apps, secrets, consent, codes, tokens, approval
        $appNew = $this->send('GET', '/settings/applications/new');
        $this->send('POST', '/settings/applications', '', ['csrf_token' => self::csrf($appNew->body), 'name' => '', 'homepage_url' => 'x', 'callback_url' => 'http://[::1]/cb', 'description' => '<b>']);
        $created = $this->until(function (): MintPlan {
            $form = $this->send('GET', '/settings/applications/new');

            return $this->send('POST', '/settings/applications', '', ['csrf_token' => self::csrf($form->body), 'name' => 'bot', 'homepage_url' => 'https://app.example.com', 'callback_url' => 'https://app.example.com/cb', 'description' => 'build bot']);
        }, static fn (MintPlan $p): bool => preg_match('~\A/settings/applications/[a-f0-9]{12}\z~', (string) $p->header('Location')) === 1, $this->totp);
        $page = (string) $created->header('Location');
        $this->send('GET', '/settings/applications');
        $this->until(function () use ($page): MintPlan {
            $show = $this->send('GET', $page);
            $r = $this->send('POST', $page . '/secrets', '', ['csrf_token' => self::csrf($show->body, 0)]);

            return $r->header('Location') === $page ? $this->send('GET', $page) : $r;
        }, static fn (MintPlan $p): bool => preg_match('~<p class=mono>[a-f0-9]{40}</p>~', $p->body) === 1, $this->totp);
        $show = $this->send('GET', $page);
        preg_match('~<p>Client ID</p><p class=mono>([a-f0-9]{20})</p>~', $show->body, $cm);
        $client = $cm[1];
        $this->send('GET', '/login/oauth/authorize', http_build_query(['client_id' => $client, 'redirect_uri' => 'https://evil.example/x']));
        $this->send('GET', '/login/oauth/authorize', http_build_query(['client_id' => str_repeat('0', 20)]));
        $codePage = $this->until(function () use ($client): MintPlan {
            $c = $this->send('GET', '/login/oauth/authorize', http_build_query(['client_id' => $client, 'scope' => 'read:user orders:read', 'state' => 'st-1']));
            preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $c->body, $m);

            return $this->send('POST', '/login/oauth/authorize', '', ['csrf_token' => self::csrf($c->body), 'authorization_request' => $m[1] ?? '', 'authorize' => '1']);
        }, static fn (MintPlan $p): bool => str_contains($p->body, 'Authorization code for'), $this->totp);
        $c = $this->send('GET', '/login/oauth/authorize', http_build_query(['client_id' => $client]));
        preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $c->body, $dm);
        $this->send('POST', '/login/oauth/authorize', '', ['csrf_token' => self::csrf($c->body), 'authorization_request' => $dm[1], 'deny' => '1']);
        $this->send('POST', '/login/oauth/authorize', '', ['csrf_token' => self::csrf($c->body), 'authorization_request' => 'ffffffffffff', 'authorize' => '1']);
        preg_match('~<p class=mono>([a-f0-9]{20})</p>~', $codePage->body, $code);
        $sp = $this->send('GET', $page);
        unset($sp);
        $secret = $this->lastSecret ?? '';
        foreach ($this->plans as [, $p]) {
            if (preg_match('~<p class=mono>([a-f0-9]{40})</p>~', $p->body, $m) === 1) {
                $secret = $m[1];
            }
        }
        $tok = json_decode($this->send('POST', '/login/oauth/access_token', '', ['grant_type' => 'authorization_code', 'code' => $code[1] ?? '', 'client_id' => $client, 'client_secret' => $secret])->body, true);
        $this->send('POST', '/login/oauth/access_token', '', ['grant_type' => 'refresh_token', 'refresh_token' => (string) ($tok['refresh_token'] ?? ''), 'client_id' => $client, 'client_secret' => str_repeat('0', 40)]);
        $this->send('POST', '/login/oauth/access_token', '', ['grant_type' => 'refresh_token', 'refresh_token' => (string) ($tok['refresh_token'] ?? ''), 'client_id' => $client, 'client_secret' => $secret, 'scope' => 'admin:org']);
        $this->send('POST', '/login/oauth/access_token', '', ['grant_type' => 'refresh_token', 'refresh_token' => (string) ($tok['refresh_token'] ?? ''), 'client_id' => $client, 'client_secret' => $secret]);
        $approval = $this->send('GET', '/api/v2/orders', '', null, ['Authorization' => 'Bearer ' . (string) ($tok['access_token'] ?? '')]);
        $aurl = (string) (json_decode($approval->body, true)['approval_url'] ?? '');
        $ap = $this->send('GET', '/orgs/' . $slug . '/sso', (string) parse_url($aurl, PHP_URL_QUERY));
        preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $ap->body, $am);
        $this->send('POST', '/orgs/' . $slug . '/sso', '', ['csrf_token' => self::csrf($ap->body), 'authorization_request' => $am[1] ?? '']);

        // deletes and sign-out
        $list = $this->send('GET', '/settings/tokens');
        if (preg_match("~/settings/tokens/([a-f0-9]{12})/delete'><input type=hidden name=csrf_token value='([^']+)'~", $list->body, $dl) === 1) {
            $this->send('POST', '/settings/tokens/' . $dl[1] . '/delete', '', ['csrf_token' => $dl[2]]);
            $this->send('GET', '/settings/tokens');
        }
        $this->send('POST', '/settings/tokens/abcdef012345/delete', '', ['csrf_token' => 'x']);
        $show = $this->send('GET', $page);
        if (preg_match_all("/name=csrf_token value='([^']+)'/", $show->body, $all) > 1) {
            $this->send('POST', $page . '/delete', '', ['csrf_token' => $all[1][1]]);
            $this->send('GET', '/settings/applications');
        }
        $this->send('GET', '/settings/applications/abcdef012345');
        $so = $this->send('GET', '/signout');
        $this->send('POST', '/signout', '', ['csrf_token' => self::csrf($so->body)]);

        return ['home' => $home];
    }

    private ?string $totp = null;
    private ?string $lastSecret = null;
}

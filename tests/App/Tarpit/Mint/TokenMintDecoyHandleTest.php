<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\Tests\App\Tarpit\Mint\MintCorpus;
use Funnypot\App\Tarpit\Mint\Totp;
use PHPUnit\Framework\TestCase;

/**
 * The account surface through the real HoneypotController::handle() and the real engine: the token
 * and OAuth journeys end at a wall, nothing reflects from a GET or into a header, nothing redirects
 * off-site, every answer is in the closed status/header sets, and the decoy never takes the fault
 * path on inputs alone.
 */
final class TokenMintDecoyHandleTest extends TestCase
{
    /** @var list<MintHarness> */
    private array $harnesses = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        $warnings = [];
        foreach ($this->harnesses as $h) {
            $warnings = array_merge($warnings, $h->warnings);
            $h->cleanup();
        }
        $this->harnesses = [];
        // Every test doubles as a no-warnings test: a notice on this surface is a bug.
        self::assertSame([], $warnings, 'PHP warnings or notices while handling');
    }

    private function h(bool $armed = true, array $opts = []): MintHarness
    {
        return $this->harnesses[] = new MintHarness($armed, $opts);
    }

    private static function json(array $r): array
    {
        return (array) json_decode($r['body'], true);
    }

    // --- 1. personal access token journey ----------------------------------------------------------

    public function test_pat_journey_ends_at_the_sso_wall_and_the_idp_never_signs_in(): void
    {
        $h = $this->h();
        $h->join();
        $home = $h->front->home(new \Funnypot\Core\RequestContext('GET', '/', '', ['Cookie' => 'session=' . $h->jars['default']['session']]), MintHarness::IP);
        self::assertNotNull($home);
        self::assertStringContainsString('Signed in as artex1', $home->body);

        $tok = $h->mint(['read:user']);
        self::assertMatchesRegularExpression('/\A[a-z]{2,4}_pat_[0-9A-Za-z]{31}\z/', $tok);

        $me = $h->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $tok]);
        self::assertSame(200, $me['status']);
        self::assertSame('member', self::json($me)['role']);
        self::assertSame('artex1', self::json($me)['login']);
        self::assertTrue($me['plan']->served);

        $orders = $h->get('/api/v2/orders', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $tok]);
        self::assertSame(403, $orders['status']);
        self::assertSame(['orders:read'], self::json($orders)['required_scopes']);

        // orders:read is sensitive: refused without 2FA.
        $form = $h->get('/settings/tokens/new');
        $no2fa = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => 'orders', 'expiration' => '30', 'scopes' => ['orders:read']]);
        self::assertSame(422, $no2fa['status']);
        self::assertStringContainsString('Enable two-factor authentication', $no2fa['body']);

        [$secret, $codes] = $h->enable2fa();
        self::assertCount(10, $codes);

        // The next mint asks for confirm-access; a single-use recovery code passes it once.
        $h->now += 40;
        $form = $h->get('/settings/tokens/new');
        $needs = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => 'orders', 'expiration' => '30', 'scopes' => ['orders:read']]);
        self::assertSame('/settings/confirm', $needs['plan']->header('Location'));
        $page = $h->get('/settings/confirm');
        $ok = $h->post('/settings/confirm', ['csrf_token' => MintHarness::csrf($page['body']), 'password' => 'Passw0rd!x', 'recovery_code' => $codes[0]]);
        self::assertSame(303, $ok['status']);
        self::assertSame('/settings/tokens', $ok['plan']->header('Location'));
        $h->now += 1000; // let the confirm window lapse
        $page = $h->get('/settings/confirm');
        $reuse = $h->post('/settings/confirm', ['csrf_token' => MintHarness::csrf($page['body']), 'password' => 'Passw0rd!x', 'recovery_code' => $codes[0]]);
        self::assertSame(422, $reuse['status'], 'a recovery code works once');
        $ok = $h->confirm('default', MintHarness::IP, 'Passw0rd!x', $secret);
        self::assertSame(303, $ok['status'], 'a computed TOTP passes confirm');

        $orderTok = $h->mint(['orders:read'], 'orders');
        $wall = $h->get('/api/v2/orders', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $orderTok]);
        self::assertSame(403, $wall['status']);
        $body = self::json($wall);
        self::assertStringContainsString('single sign-on', $body['message']);
        self::assertMatchesRegularExpression('~\A/orgs/' . $h->persona->slug . '/sso\?authorization_request=[a-f0-9]{12}\z~', $body['sso_url']);
        self::assertSame('required; url=' . $body['sso_url'], $wall['plan']->header('X-SSO'));
        $one = $h->get('/v2/orders/10422', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $orderTok]);
        $none = $h->get('/v2/orders/99999', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $orderTok]);
        self::assertSame($one['body'], $none['body'], 'the wall comes before any existence check');
        self::assertFalse($one['plan']->served);

        // SSO page -> IdP, which never signs in.
        parse_str((string) parse_url($body['sso_url'], PHP_URL_QUERY), $q);
        $sso = $h->get('/orgs/' . $h->persona->slug . '/sso', 'authorization_request=' . $q['authorization_request']);
        self::assertSame(200, $sso['status']);
        $to = $h->post('/orgs/' . $h->persona->slug . '/sso', ['csrf_token' => MintHarness::csrf($sso['body']), 'authorization_request' => $q['authorization_request']]);
        self::assertSame('/idp/' . $h->persona->slug . '/signin', $to['plan']->header('Location'));
        $idp = $h->get('/idp/' . $h->persona->slug . '/signin');
        $answers = [];
        for ($i = 0; $i < 6; $i++) {
            $r = $h->post('/idp/' . $h->persona->slug . '/signin', ['csrf_token' => MintHarness::csrf($idp['body']), 'username' => 'artex1', 'password' => 'Passw0rd!x']);
            $answers[] = str_contains($r['body'], 'assigned to this application') ? 'unassigned' : (str_contains($r['body'], 'Too many') ? 'locked' : 'other');
        }
        self::assertSame(['unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'locked'], $answers);
        $idp2 = $h->get('/idp/' . $h->persona->slug . '/signin', '', 'other', '45.79.12.99');
        $other = $h->post('/idp/' . $h->persona->slug . '/signin', ['csrf_token' => MintHarness::csrf($idp2['body']), 'username' => 'someone', 'password' => 'x'], 'other', '45.79.12.99');
        self::assertStringContainsString('Invalid username or password', $other['body']);
        self::assertSame(0, $h->decoy->faults());
    }

    // --- helpers -----------------------------------------------------------------------------------

    /** Register an app and generate its client secret through the forms. @return array{id:string,client:string,secret:string} */
    private function app(MintHarness $h, string $name = 'ci-bot', string $callback = 'https://app.example.com/oauth/callback?x=1'): array
    {
        $created = $h->until(function () use ($h, $name, $callback): array {
            $form = $h->get('/settings/applications/new');

            return $h->post('/settings/applications', ['csrf_token' => MintHarness::csrf($form['body']), 'name' => $name, 'homepage_url' => 'https://app.example.com', 'callback_url' => $callback, 'description' => 'build bot']);
        }, static fn (array $r): bool => preg_match('~\A/settings/applications/[a-f0-9]{12}\z~', (string) $r['plan']?->header('Location')) === 1);
        $page = (string) $created['plan']->header('Location');
        $id = substr($page, strlen('/settings/applications/'));
        $show = $h->get($page);
        preg_match('~<p>Client ID</p><p class=mono>([a-f0-9]{20})</p>~', $show['body'], $m);
        $client = $m[1];
        $secretPage = $h->until(function () use ($h, $page): array {
            $show = $h->get($page);
            $r = $h->post($page . '/secrets', ['csrf_token' => MintHarness::csrf(substr($show['body'], (int) strpos($show['body'], '/secrets')))]);

            return ($r['plan']?->header('Location') === $page) ? $h->get($page) : $r;
        }, static fn (array $r): bool => preg_match('~<p class=mono>([a-f0-9]{40})</p>~', $r['body']) === 1);
        preg_match('~<p class=mono>([a-f0-9]{40})</p>~', $secretPage['body'], $sm);

        return ['id' => $id, 'client' => $client, 'secret' => $sm[1], 'page' => $page];
    }

    /** Authorize an app for $scope through the consent form; returns the consent POST answer. */
    private function consent(MintHarness $h, string $client, string $scope, string $state, string $redirect = 'https://app.example.com/oauth/callback?x=1'): array
    {
        return $h->until(function () use ($h, $client, $scope, $state, $redirect): array {
            $q = http_build_query(['client_id' => $client, 'redirect_uri' => $redirect, 'scope' => $scope, 'state' => $state]);
            $page = $h->get('/login/oauth/authorize', $q);
            preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $page['body'], $m);

            return $h->post('/login/oauth/authorize', ['csrf_token' => MintHarness::csrf($page['body']), 'authorization_request' => $m[1] ?? '', 'authorize' => '1']);
        }, static fn (array $r): bool => ($r['status'] ?? 0) === 200 && str_contains($r['body'], 'Authorization code for'));
    }

    private function tokenPost(MintHarness $h, array $fields, string $ip = MintHarness::IP): array
    {
        return $h->request('POST', '/login/oauth/access_token', '', http_build_query($fields), [], $ip);
    }

    // --- 2. OAuth journey ----------------------------------------------------------------------------

    public function test_oauth_journey_completes_on_own_pages_and_tokens_are_single_use(): void
    {
        $h = $this->h();
        $h->join();
        $app = $this->app($h);

        $q = http_build_query(['client_id' => $app['client'], 'redirect_uri' => 'https://app.example.com/oauth/callback?x=1', 'scope' => 'read:user', 'state' => 'STATEcanary9']);
        $consentPage = $h->get('/login/oauth/authorize', $q);
        self::assertSame(200, $consentPage['status']);
        self::assertStringNotContainsString('STATEcanary9', $consentPage['body'], 'state never appears in a GET answer');

        $code = $this->consent($h, $app['client'], 'read:user', 'STATEcanary9');
        self::assertNull($code['plan']->header('Location'), 'no redirect anywhere, let alone to the callback');
        self::assertStringContainsString('State: <span class=mono>STATEcanary9</span>', $code['body']);
        foreach ($code['plan']->headers() as [$n, $v]) {
            self::assertStringNotContainsString('STATEcanary9', $v, "no state in header {$n}");
        }
        self::assertStringNotContainsString('href="https://app.example.com', $code['body']);
        preg_match('~<p class=mono>([a-f0-9]{20})</p>~', $code['body'], $m);
        $authCode = $m[1];

        $ex = $this->tokenPost($h, ['grant_type' => 'authorization_code', 'code' => $authCode, 'client_id' => $app['client'], 'client_secret' => $app['secret'], 'redirect_uri' => 'https://app.example.com/oauth/callback?x=1']);
        self::assertSame(200, $ex['status']);
        $tok = self::json($ex);
        self::assertSame('bearer', $tok['token_type']);
        self::assertMatchesRegularExpression('/\A[a-z]{2,4}_oat_/', $tok['access_token']);
        self::assertMatchesRegularExpression('/\A[a-z]{2,4}_ort_/', $tok['refresh_token']);
        self::assertSame('invalid_grant', self::json($this->tokenPost($h, ['grant_type' => 'authorization_code', 'code' => $authCode, 'client_id' => $app['client'], 'client_secret' => $app['secret']]))['error'], 'a code works once');

        $me = $h->get('/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'token ' . $tok['access_token']]);
        self::assertSame(200, $me['status']);

        $ref = $this->tokenPost($h, ['grant_type' => 'refresh_token', 'refresh_token' => $tok['refresh_token'], 'client_id' => $app['client'], 'client_secret' => $app['secret']]);
        self::assertSame(200, $ref['status']);
        $tok2 = self::json($ref);
        self::assertNotSame($tok['refresh_token'], $tok2['refresh_token']);
        self::assertSame('invalid_grant', self::json($this->tokenPost($h, ['grant_type' => 'refresh_token', 'refresh_token' => $tok['refresh_token'], 'client_id' => $app['client'], 'client_secret' => $app['secret']]))['error'], 'the old refresh token is spent');
        self::assertSame('invalid_scope', self::json($this->tokenPost($h, ['grant_type' => 'refresh_token', 'refresh_token' => $tok2['refresh_token'], 'client_id' => $app['client'], 'client_secret' => $app['secret'], 'scope' => 'orders:read']))['error']);
        self::assertSame('unauthorized_client', self::json($this->tokenPost($h, ['grant_type' => 'client_credentials', 'client_id' => $app['client'], 'client_secret' => $app['secret']]))['error']);
        self::assertSame('unsupported_grant_type', self::json($this->tokenPost($h, ['grant_type' => 'password', 'username' => 'artex1', 'password' => 'Passw0rd!x']))['error']);
        $badClient = $this->tokenPost($h, ['grant_type' => 'refresh_token', 'refresh_token' => $tok2['refresh_token'], 'client_id' => $app['client'], 'client_secret' => str_repeat('0', 40)]);
        self::assertSame(401, $badClient['status']);
        self::assertSame('invalid_client', self::json($badClient)['error']);
        self::assertFalse($badClient['main']['served'], 'a failed client authentication is a 401 like any other');

        // An OAuth token with an organisation-data scope ends at owner approval, pending forever.
        $h->enable2fa();
        $code2 = $this->consent($h, $app['client'], 'orders:read', 'abc');
        preg_match('~<p class=mono>([a-f0-9]{20})</p>~', $code2['body'], $m2);
        $tok3 = self::json($this->tokenPost($h, ['grant_type' => 'authorization_code', 'code' => $m2[1], 'client_id' => $app['client'], 'client_secret' => $app['secret']]));
        $wall = $h->get('/api/v2/orders', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $tok3['access_token']]);
        self::assertSame(403, $wall['status']);
        $wb = self::json($wall);
        self::assertStringContainsString('An owner must approve ci-bot', $wb['message']);
        $sso = $h->get('/orgs/' . $h->persona->slug . '/sso', (string) parse_url($wb['approval_url'], PHP_URL_QUERY));
        self::assertStringContainsString('Request organization approval', $sso['body']);
        preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $sso['body'], $rq);
        $requested = $h->post('/orgs/' . $h->persona->slug . '/sso', ['csrf_token' => MintHarness::csrf($sso['body']), 'authorization_request' => $rq[1]]);
        self::assertStringContainsString('Approval requested', $requested['body']);
        $again = $h->get('/api/v2/orders', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $tok3['access_token']]);
        self::assertSame(403, $again['status'], 'approval stays pending');

        // Deny renders its own page.
        $page = $h->get('/login/oauth/authorize', http_build_query(['client_id' => $app['client'], 'scope' => 'read:user']));
        preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $page['body'], $dm);
        $deny = $h->post('/login/oauth/authorize', ['csrf_token' => MintHarness::csrf($page['body']), 'authorization_request' => $dm[1], 'deny' => '1']);
        self::assertSame(200, $deny['status']);
        self::assertStringContainsString('denied ci-bot access', $deny['body']);
        self::assertNull($deny['plan']->header('Location'));
        self::assertSame(0, $h->decoy->faults());
    }

    // --- 3. JWT login and persona members ----------------------------------------------------------

    public function test_jwt_login_and_persona_member_answers(): void
    {
        $h = $this->h();
        $h->join();
        $login = $h->request('POST', '/api/v2/auth/login', '', '{"username":"artex1","password":"Passw0rd!x"}', ['Content-Type' => 'application/json']);
        self::assertSame(200, $login['status']);
        $jwt = self::json($login)['access_token'];
        self::assertSame(2, substr_count($jwt, '.'));
        $payload = json_decode((string) base64_decode(strtr(explode('.', $jwt)[1], '-_', '+/')), true);
        self::assertSame(['exp', 'iat', 'jti', 'scope', 'sid', 'sub'], (static function (array $k): array {
            sort($k);

            return $k;
        })(array_keys($payload)), 'only ordinary claims; the routing facts sit in one opaque sid');
        self::assertSame(200, $h->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $jwt])['status']);

        // Re-signed with the persona's published JWT secret: rejected like any forgery.
        $persona = \Funnypot\Core\Support\PersonaIdentity::fromSeed(\Funnypot\Tests\App\Identity\IdentityTestSupport::httpIdentity()->personaSeed());
        [, $payload] = explode('.', $jwt);
        $claims = json_decode((string) base64_decode(strtr($payload, '-_', '+/')), true);
        $forged = \Funnypot\App\Tarpit\Mint\JwtCodec::encode($claims, (string) $persona->field('secret.jwt'));
        $r = $h->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $forged]);
        self::assertSame(401, $r['status']);
        self::assertSame('The credentials are invalid or have expired.', self::json($r)['message']);

        $admin = (string) $persona->field('user.admin.username');
        $answers = [];
        foreach ([(string) $persona->field('user.admin.password'), 'wrong-password', ''] as $pw) {
            $a = $h->request('POST', '/v2/auth/login', '', (string) json_encode(['username' => $admin, 'password' => $pw]), ['Content-Type' => 'application/json']);
            self::assertSame(403, $a['status']);
            $answers[] = $a['body'];
        }
        self::assertCount(1, array_unique($answers), 'the leaked password is neither confirmed nor refuted');
        self::assertSame(400, $h->request('POST', '/api/v2/auth/login', '', '{"username":"artex1"}', ['Content-Type' => 'application/json'])['status']);
        self::assertSame(401, $h->request('POST', '/api/v2/auth/login', '', '{"username":"artex1","password":"nope-nope"}', ['Content-Type' => 'application/json'])['status']);
    }

    // --- 4. mass assignment --------------------------------------------------------------------------

    public function test_patch_user_ignores_role_and_admin_fields(): void
    {
        $h = $this->h();
        $h->join();
        $tok = $h->mint(['read:user', 'user:write']);
        $r = $h->request('PATCH', '/api/v2/user', '', '{"name":"Ar Tex","role":"owner","is_admin":true,"site_admin":true}', ['Authorization' => 'Bearer ' . $tok, 'Content-Type' => 'application/json']);
        self::assertSame(200, $r['status']);
        $p = self::json($r);
        self::assertSame('Ar Tex', $p['name']);
        self::assertSame('member', $p['role']);
        self::assertArrayNotHasKey('is_admin', $p);
        self::assertSame('member', self::json($h->get('/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $tok]))['role']);
        $confused = $h->request('PATCH', '/api/v2/user', '', '{"name":["x"],"bio":{"a":1}}', ['Authorization' => 'Bearer ' . $tok, 'Content-Type' => 'application/json']);
        self::assertSame('Ar Tex', self::json($confused)['name'], 'a non-string field reads as missing');
    }

    // --- 5. reflection canaries ----------------------------------------------------------------------

    public function test_nothing_reflects_from_a_get_or_a_path_and_post_echoes_are_charset_gated(): void
    {
        $h = $this->h();
        $h->join();
        $tok = $h->mint(['read:user']);
        $auth = ['Authorization' => 'Bearer ' . $tok];
        $slug = $h->persona->slug;
        $q = 'FPMINTQcanary';
        $query = http_build_query(['description' => $q, 'scopes' => $q, 'client_id' => $q, 'redirect_uri' => $q, 'scope' => $q, 'state' => $q, 'authorization_request' => $q]);
        $paths = [
            '/join', '/signout', '/settings/profile', '/settings/security', '/settings/confirm', '/settings/tokens', '/settings/tokens/new',
            '/settings/applications', '/settings/applications/new', '/settings/applications/fpmintcanary7q', '/login/oauth/authorize',
            '/orgs/' . $slug . '/sso', '/idp/' . $slug . '/signin', '/docs/api',
            '/api/v2/user', '/v2/users/FpMintCanary7Q', '/api/v2/users/FpMintCanary7Q', '/api/v2/orders/fpmintcanary7q', '/v2/orgs/' . $slug,
        ];
        foreach ($paths as $p) {
            $r = $h->get($p, $query, 'default', MintHarness::IP, $auth);
            self::assertNotNull($r['plan'], "the surface answered {$p}");
            foreach (['FPMINTQcanary', 'fpmintcanary7q', 'FpMintCanary7Q'] as $c) {
                self::assertStringNotContainsStringIgnoringCase($c, $r['body'], "{$p} reflected {$c}");
                foreach ($r['plan']->headers() as [$n, $v]) {
                    self::assertStringNotContainsStringIgnoringCase($c, $v, "{$p} header {$n}");
                }
            }
        }
        $turns = (int) $h->store->db()->query("SELECT COUNT(*) FROM mint_turns")->fetchColumn();
        self::assertGreaterThanOrEqual(count($paths), $turns, 'every request was answered and attributed by the surface');

        // A POST re-render echoes only a value that passes its charset, escaped; markup is refused.
        $form = $h->get('/settings/tokens/new');
        $bad = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => '<script>alert(1)</script>', 'expiration' => '30', 'scopes' => ['read:user']]);
        self::assertSame(422, $bad['status']);
        self::assertStringNotContainsString('<script>alert(1)', $bad['body']);
        self::assertStringNotContainsString('alert(1)', $bad['body']);
        $ok = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => 'FPMINTPOSTnote', 'expiration' => 'none', 'scopes' => ['read:user']]);
        self::assertSame(422, $ok['status']);
        self::assertStringContainsString("value='FPMINTPOSTnote'", $ok['body'], 'a clean POST value is re-filled');
    }

    public function test_control_characters_never_reach_the_stored_row(): void
    {
        $h = $this->h();
        $h->join();
        $tok = $h->mint(['read:user', 'user:write']);
        $page = $h->get('/settings/profile');
        $r = $h->post('/settings/profile', ['csrf_token' => MintHarness::csrf($page['body']), 'name' => str_repeat("\0", 160), 'bio' => "\t\r\n\x0B"]);
        self::assertSame(422, $r['status']);
        self::assertStringNotContainsString("\0", $r['body']);
        $api = $h->request('PATCH', '/api/v2/user', '', '{"bio":"\u0000\u0000\u0000\n"}', ['Authorization' => 'Bearer ' . $tok, 'Content-Type' => 'application/json']);
        self::assertSame(422, $api['status']);
        $form = $h->get('/settings/applications/new');
        $app = $h->post('/settings/applications', ['csrf_token' => MintHarness::csrf($form['body']), 'name' => 'ctl', 'homepage_url' => 'https://a.example.com', 'callback_url' => 'https://a.example.com/cb', 'description' => str_repeat("\0", 200)]);
        self::assertSame(422, $app['status']);
        foreach ($h->store->db()->query('SELECT state FROM mint_state')->fetchAll(\PDO::FETCH_COLUMN) as $json) {
            self::assertStringNotContainsString('\\u', (string) $json, 'no stored character needs a JSON escape');
        }
    }

    /** The nav a page shows: the signed-in one has Sign out, the signed-out one Sign in. */
    private static function nav(string $body): string
    {
        $in = str_contains($body, "<a href='/signout'>Sign out</a>");
        $out = str_contains($body, "<a href='/'>Sign in</a>");
        self::assertNotSame($in, $out, 'exactly one nav');

        return $in ? 'in' : 'out';
    }

    public function test_the_nav_always_matches_the_live_session(): void
    {
        $h = $this->h();
        $h->join();
        self::assertSame('in', self::nav($h->get('/docs/api')['body']));
        self::assertSame('in', self::nav($h->request('PUT', '/settings/tokens', '', '{}', ['Content-Type' => 'application/json'])['body']), 'a signed-in 405');
        self::assertSame('in', self::nav($h->request('POST', '/settings/profile', '', str_repeat('a', 17000))['body']), 'a signed-in 413');

        // Signing out where the client keeps its cookie: every page now reads as signed out.
        $kept = $h->jars['default']['session'];
        $so = $h->get('/signout');
        $h->post('/signout', ['csrf_token' => MintHarness::csrf($so['body'])]);
        $h->jars['default']['session'] = $kept;
        self::assertSame(303, $h->get('/settings/tokens')['status']);
        self::assertSame('out', self::nav($h->get('/docs/api')['body']), 'docs after the session died');
        self::assertSame('out', self::nav($h->request('PUT', '/settings/tokens', '', '{}', ['Content-Type' => 'application/json'])['body']));
        self::assertSame('out', self::nav($h->request('POST', '/join', '', str_repeat('a', 17000))['body']));

        // A signed-out source over its hourly units gets the throttle page with the signed-out nav.
        $ip = '45.89.0.1';
        $idp = $h->get('/idp/' . $h->persona->slug . '/signin', '', 'idp', $ip);
        $throttled = null;
        for ($i = 0; $i < 520 && $throttled === null; $i++) {
            $r = $h->post('/idp/' . $h->persona->slug . '/signin', ['csrf_token' => MintHarness::csrf($idp['body']), 'username' => 'x', 'password' => 'y'], 'idp', $ip);
            if ($r['status'] === 429) {
                $throttled = $r;
            }
        }
        self::assertNotNull($throttled, 'the unit ledger shed the source');
        self::assertSame('out', self::nav($throttled['body']));
    }

    // --- 6. content type and status table ------------------------------------------------------------

    public function test_status_and_content_type_table(): void
    {
        $h = $this->h();
        $slug = $h->persona->slug;
        $html = ['/join', '/settings/tokens', '/settings/applications/abcdef123456', '/orgs/' . $slug . '/sso', '/idp/' . $slug . '/signin', '/docs/api'];
        $json = ['/api/v2/user', '/v2/users', '/api/v2/orders/12', '/v2/orgs/' . $slug . '/members'];
        foreach ($html as $p) {
            $r = $h->get($p);
            self::assertContains($r['status'], [200, 303], $p);
            self::assertSame(MintPlan::HTML, $r['plan']->header('Content-Type'), $p);
            $head = $h->request('HEAD', $p);
            self::assertSame($r['status'], $head['status']);
            self::assertSame('', $head['body'], "HEAD {$p} has no body");
            $opt = $h->request('OPTIONS', $p);
            self::assertSame(204, $opt['status']);
            self::assertNotNull($opt['plan']->header('Allow'));
            $put = $h->request('PUT', $p, '', '{}', ['Content-Type' => 'application/json']);
            self::assertSame(405, $put['status'], "PUT {$p}");
            self::assertStringContainsString('GET', (string) $put['plan']->header('Allow'));
        }
        foreach ($json as $p) {
            $r = $h->get($p);
            self::assertSame(401, $r['status'], $p);
            self::assertSame(MintPlan::JSON, $r['plan']->header('Content-Type'), $p);
            self::assertSame('nosniff', $r['plan']->header('X-Content-Type-Options'));
            self::assertSame('no-store', $r['plan']->header('Cache-Control'));
            self::assertSame(405, $h->request('DELETE', $p)['status']);
        }
        self::assertSame(MintPlan::JSON, $this->tokenPost($h, [])['plan']->header('Content-Type'));
        self::assertSame(413, $h->request('POST', '/join', '', str_repeat('a', 17000))['status']);
    }

    /** Every answer is in the closed status and header sets, and every redirect stays on-site. */
    private static function assertClosed(MintPlan $p, string $slug, string $what): void
    {
        self::assertContains($p->status, MintPlan::STATUSES, $what);
        self::assertLessThan(500, $p->status, $what);
        foreach ($p->headers() as [$n, $v]) {
            self::assertContains($n, MintPlan::HEADER_NAMES, "{$what} header {$n}");
            if ($n === 'Location') {
                self::assertTrue(
                    in_array($v, ['/', '/settings/confirm', '/settings/tokens', '/settings/applications', '/settings/security', '/idp/' . $slug . '/signin'], true)
                    || preg_match('~\A/settings/applications/[a-f0-9]{12}\z~', $v) === 1,
                    "{$what} Location {$v}"
                );
            }
            if ($n === 'X-SSO') {
                self::assertMatchesRegularExpression('~\Arequired; url=/orgs/' . preg_quote($slug, '~') . '/sso\?authorization_request=[a-f0-9]{12}\z~', $v, $what);
            }
        }
        self::assertDoesNotMatchRegularExpression('~<meta[^>]+refresh|window\.location|location\.href~i', $p->body, "{$what} navigates");
    }

    // --- 7. fuzz -------------------------------------------------------------------------------------

    public function test_fuzz_stays_in_the_closed_sets_with_no_fault_and_no_warning(): void
    {
        $h = $this->h();
        $h->join();
        $tok = $h->mint(['read:user']);
        $slug = $h->persona->slug;
        $session = $h->jars['default']['session'];
        mt_srand(815);
        $paths = \Funnypot\Tests\App\Tarpit\Mint\MintCorpus::ownedPaths($slug);
        $methods = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'];
        $cookies = [null, 'session=' . $session, 'session=' . substr($session, 0, -2) . 'AA', 'session=' . str_repeat('A', 60), 'session=x', str_repeat('a=b; ', 900)];
        $auths = [[], ['Authorization' => 'Bearer ' . $tok], ['Authorization' => 'Bearer ' . str_repeat('A', 5000)], ['Authorization' => 'Bearer a.b.c'],
            ['Authorization' => 'Bearer ' . substr($tok, 0, -1) . 'Q'], ['X-Api-Key' => $tok], ['Authorization' => 'Basic Zm9vOmJhcg=='], ['Authorization' => str_repeat('x', 300)]];
        // Inputs cheap for the engine go through handle(); the few the engine itself spends seconds on
        // (huge pair counts, brace floods) are run through the surface's own prepare() below.
        $bodies = [
            null,
            'csrf_token=AAAAAAAAAAAAAAAAAAAAAAAAAAA&note=x&scopes%5B%5D=read%3Auser&expiration=30',
            str_repeat('a=1&', 120),
            'note%5B%5D=x&scopes=read%3Auser&scopes%5Ba%5D%5Bb%5D=c&csrf_token%5B%5D=y&expiration%5B%5D=30',
            '[1,2,3]',
            '{"name":["a"],"bio":{"x":1},"username":5,"password":true}',
            '{"a":{"b":{"c":{"d":{"e":1}}}}}',
            str_repeat('{', 40),
            'grant_type%5B%5D=authorization_code&code%5B%5D=x&client_id=' . str_repeat('9', 2000),
            'username=' . str_repeat('a', 1500) . '&password=x',
            "\x00\xff\xfe" . str_repeat("\x80", 500),
            'authorization_request=ab12cd34ef56&authorize=1&deny=1&csrf_token=' . str_repeat('A', 27),
        ];
        $queries = ['', 'scopes=a,b,read:user', 'client_id=' . str_repeat('a', 20) . '&state=%3Cscript%3E', str_repeat('x=1&', 90), 'access_token=' . $tok, 'authorization_request=../../etc/passwd'];
        for ($i = 0; $i < 2000; $i++) {
            $path = $paths[mt_rand(0, count($paths) - 1)];
            $method = $methods[mt_rand(0, count($methods) - 1)];
            $headers = $auths[mt_rand(0, count($auths) - 1)];
            $cookie = $cookies[mt_rand(0, count($cookies) - 1)];
            if ($cookie !== null) {
                $headers['Cookie'] = $cookie;
            }
            $body = in_array($method, ['GET', 'HEAD', 'OPTIONS'], true) ? null : $bodies[mt_rand(0, count($bodies) - 1)];
            if ($body !== null) {
                $headers['Content-Type'] = mt_rand(0, 1) === 1 ? 'application/json' : 'application/x-www-form-urlencoded';
            }
            $h->now += mt_rand(0, 90);
            $r = $h->request($method, $path, $queries[mt_rand(0, count($queries) - 1)], $body, $headers, '45.79.' . mt_rand(1, 3) . '.9', 'fuzz');
            self::assertNotNull($r['plan'], "{$method} {$path} was answered");
            self::assertClosed($r['plan'], $slug, "#{$i} {$method} {$path}");
        }
        $heavy = [
            ['POST', str_repeat('a=1&', 4000), ''], ['POST', str_repeat('{', 3000), ''], ['POST', 'username=' . str_repeat('a', 9000) . '&password=x', ''],
            ['GET', null, str_repeat('x=1&', 3000)], ['POST', str_repeat('scopes%5B%5D=read%3Auser&', 700), ''], ['POST', str_repeat('A', 20000), ''],
        ];
        set_error_handler(static function (int $no, string $msg): bool {
            if ((error_reporting() & $no) === 0) {
                return true;
            }
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            foreach ($paths as $path) {
                foreach ($heavy as [$m, $b, $q]) {
                    foreach (['application/json', 'application/x-www-form-urlencoded'] as $ct) {
                        $p = $h->decoy->prepare(new \Funnypot\Core\RequestContext($m, $path, $q, ['Content-Type' => $ct, 'Cookie' => 'session=' . $session], $b), '45.79.4.9');
                        self::assertNotNull($p, "{$m} {$path} heavy input");
                        self::assertClosed($p, $slug, "heavy {$m} {$path}");
                    }
                }
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame(0, $h->decoy->faults());
    }

    public function test_a_non_store_fault_before_commit_serves_todays_answer_and_changes_nothing(): void
    {
        $stage = null;
        $h = $this->h(true, ['storeFaults' => function (string $s) use (&$stage): void {
            if ($s === $stage) {
                throw new \RuntimeException('renderer bug FPFAULTCANARY');
            }
        }]);
        $log = $h->dir . '/php-error.log';
        $prevLog = ini_set('error_log', $log);
        $h->join();
        $before = $h->store->db()->query('SELECT state FROM mint_state')->fetchAll(\PDO::FETCH_COLUMN);
        $form = $h->get('/settings/tokens/new');
        $stage = 'write';
        $h->allowFaults = true;
        $r = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => 'x', 'expiration' => '30', 'scopes' => ['read:user']]);
        $stage = null;
        ini_set('error_log', (string) $prevLog);
        $logged = (string) @file_get_contents($log);
        self::assertStringContainsString('code=token-mint-fault', $logged, 'the operator gets a signal');
        self::assertStringContainsString('RuntimeException', $logged);
        self::assertStringNotContainsString('FPFAULTCANARY', $logged, 'never the message');
        self::assertStringNotContainsString('note=x', $logged, 'never request bytes');
        self::assertNull($r['plan'], 'the surface stepped aside');
        self::assertStringContainsString('<center><h1>404 Not Found</h1></center>', $r['body'], "today's believable 404");
        self::assertSame(1, $h->decoy->faults());
        self::assertSame($before, $h->store->db()->query('SELECT state FROM mint_state')->fetchAll(\PDO::FETCH_COLUMN), 'rolled back');
    }

    // --- 8. deterministic work-unit budget ---------------------------------------------------------

    public function test_the_unit_budget_sheds_at_the_same_request_whatever_the_clock_or_store_speed(): void
    {
        $indexes = [];
        foreach (['fast' => [0, false], 'slow' => [2, false], 'sleeping store' => [0, true]] as $case => [$step, $sleep]) {
            $h = $this->h(true, $sleep ? ['storeFaults' => static function (string $s): void {
                if ($s === 'begin') {
                    usleep(300);
                }
            }] : []);
            $h->now = 1763798400; // an hour boundary, so the slow clock stays in one bucket
            $h->join();
            $shed = null;
            for ($i = 0; $i < 1600; $i++) {
                $h->now += $step;
                $r = $h->get('/settings/tokens');
                if ($r['status'] === 429) {
                    $shed = $i;
                    self::assertSame((string) (3600 - ($h->now % 3600)), $r['plan']->header('Retry-After'), $case);
                    break;
                }
            }
            $indexes[$case] = $shed;
        }
        self::assertNotNull($indexes['fast']);
        self::assertSame(1, count(array_unique($indexes)), 'shed index per clock: ' . json_encode($indexes));
        self::assertSame(1500 - 3, $indexes['fast'], 'the sign-up POST cost 3 units, then one per page');
        $clockReads = 0;
        foreach (glob(dirname(__DIR__, 4) . '/src/App/Tarpit/Mint/*.php') ?: [] as $f) {
            $src = (string) file_get_contents($f);
            self::assertStringNotContainsString('TarpitBudget', $src, basename($f) . ' takes no tarpit slot');
            self::assertDoesNotMatchRegularExpression('/hrtime|microtime|usleep|\bsleep\(/', $src, basename($f) . ' reads no wall clock');
            $clockReads += preg_match_all('/\btime\(\)/', $src);
        }
        self::assertSame(1, $clockReads, 'the only clock is the injectable default in TokenMintDecoy::build()');
    }

    // --- 9. write caps -------------------------------------------------------------------------------

    public function test_past_the_source_write_cap_forms_throttle_and_api_reads_still_answer(): void
    {
        $h = $this->h(true, ['storeLimits' => ['source_writes_hr' => 40]]);
        $h->join();
        $tok = $h->mint(['read:user']);
        $capped = false;
        for ($i = 0; $i < 60 && !$capped; $i++) {
            $page = $h->get('/settings/profile');
            $r = $h->post('/settings/profile', ['csrf_token' => MintHarness::csrf($page['body']), 'name' => 'n' . $i]);
            $capped = $r['status'] === 429;
        }
        self::assertTrue($capped, 'the cap was reached');
        $form = $h->get('/settings/tokens/new');
        $mint = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => 'after cap', 'expiration' => '30', 'scopes' => ['read:user']]);
        self::assertSame(429, $mint['status']);
        self::assertNotNull($mint['plan']->header('Retry-After'));
        $api = $h->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $tok]);
        self::assertSame(200, $api['status'], 'reads answer from loaded state');
    }

    // --- 11. cross-IP continuity ---------------------------------------------------------------------

    public function test_a_session_and_a_token_work_from_another_ip_but_a_password_sign_in_does_not(): void
    {
        $h = $this->h();
        $h->join();
        $tok = $h->mint(['read:user']);
        $b = '45.79.200.7';
        self::assertSame(200, $h->get('/settings/tokens', '', 'default', $b)['status']);
        self::assertSame(200, $h->get('/api/v2/user', '', 'default', $b, ['Authorization' => 'Bearer ' . $tok])['status']);
        self::assertNull($h->front->signIn(new \Funnypot\Core\RequestContext('POST', '/'), $b, 'artex1', 'Passw0rd!x'), 'another source takes the funnel');
        self::assertArrayHasKey('cookie', (array) $h->front->signIn(new \Funnypot\Core\RequestContext('POST', '/'), MintHarness::IP, 'artex1', 'Passw0rd!x'));
        self::assertSame(['error' => 'signin_wrong'], $h->front->signIn(new \Funnypot\Core\RequestContext('POST', '/'), MintHarness::IP, 'artex1', 'wrong-password'));
    }

    // --- 12. detection and report parity -------------------------------------------------------------

    public function test_rows_and_reports_match_the_unarmed_host_for_every_corpus_case(): void
    {
        $slug = \Funnypot\Tests\App\Tarpit\Mint\MintCorpus::slug();
        $cases = [];
        foreach (\Funnypot\Tests\App\Tarpit\Mint\MintCorpus::benign($slug) as $c) {
            $cases[] = $c;
        }
        foreach (\Funnypot\Tests\App\Tarpit\Mint\MintCorpus::ownedPaths($slug) as $p) {
            foreach (\Funnypot\Tests\App\Tarpit\Mint\MintCorpus::attacks() as [$m, $q, $b, $hd]) {
                $cases[] = [$m, $p, $q, $b, $hd];
            }
        }
        $armed = $this->h();
        $unarmed = $this->h(false);
        $armed->join('parity', 'Passw0rd!x', 'default', '45.80.0.1');
        foreach ($cases as $i => [$m, $p, $q, $b, $hd]) {
            $ip = '45.' . (81 + intdiv($i, 250)) . '.' . intdiv($i % 250, 1) . '.' . (1 + $i % 200);
            $ra = $armed->request($m, $p, $q, $b, $hd, $ip);
            $ru = $unarmed->request($m, $p, $q, $b, $hd, $ip);
            self::assertNotNull($ra['plan'], "armed answered {$m} {$p}");
            self::assertNotNull($ra['main'], "armed wrote its main row for {$m} {$p}");
            self::assertNotNull($ru['main'], "unarmed wrote its main row for {$m} {$p}");
            self::assertSame($ip, $ra['main']['ip']);
            $strip = static function (?array $row): array {
                unset($row['ts'], $row['served'], $row['id']);

                return (array) $row;
            };
            self::assertSame($strip($ru['main']), $strip($ra['main']), "main row for {$m} {$p} {$q}");
            // Unserved: every 401, and on an id-bearing path any answer that returns no object.
            $st = $ra['plan']->status;
            $outcome = $ra['plan']->turn['outcome'] ?? '';
            $idPath = (bool) ((new \Funnypot\App\Tarpit\Mint\MintRoutes($slug))->match($p)['pattern'] ?? false);
            $hidden = $st === 401 || ($idPath && (in_array($st, [204, 403, 404, 405, 413, 429], true)
                || ($st === 422 && $outcome === 'csrf') || ($st === 303 && $outcome === 'no_session')));
            self::assertSame(!$hidden, $ra['plan']->served, "served flag for {$st} {$m} {$p}");
        }
        $norm = static fn (array $r): array => ['abuse' => $r['abuse'], 'ti' => $r['ti']];
        self::assertSame($norm($unarmed->reports()), $norm($armed->reports()), 'identical report queues');
        self::assertNotEmpty($armed->reports()['abuse'], 'sanity: attacks were reported');

        // An XSS note on the mint form, from a signed-in account: the charset error, and the same row and report.
        $armed->now += 10;
        $form = $armed->get('/settings/tokens/new', '', 'default', '45.80.0.1');
        $xss = $armed->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => '<script>alert(1)</script>', 'expiration' => '30', 'scopes' => ['read:user']], 'default', '45.80.0.1');
        self::assertSame(422, $xss['status']);
        self::assertStringContainsString('Note may only contain', html_entity_decode($xss['body']));
        self::assertTrue((bool) $xss['main']['matched']);
        self::assertContains('attack-xss', $xss['main']['templates']);
    }

    // --- 13. fail closed -----------------------------------------------------------------------------

    public function test_every_state_creating_route_fails_closed_in_each_store_failure_mode(): void
    {
        $mode = null;
        $h = $this->h(true, ['storeFaults' => function (string $s) use (&$mode): void {
            if ($mode === 'commit' && $s === 'commit') {
                throw new \PDOException('disk I/O error');
            }
        }]);
        $h->join();
        $app = $this->app($h);
        $code = $this->consent($h, $app['client'], 'read:user', 'st1');
        preg_match('~<p class=mono>([a-f0-9]{20})</p>~', $code['body'], $cm);
        $ex = self::json($this->tokenPost($h, ['grant_type' => 'authorization_code', 'code' => $cm[1], 'client_id' => $app['client'], 'client_secret' => $app['secret']]));
        $code2 = $this->consent($h, $app['client'], 'read:user', 'st2');
        preg_match('~<p class=mono>([a-f0-9]{20})</p>~', $code2['body'], $cm2);
        $h->now += 1000;

        // Each route: [prepare (its form GETs, run before the failure starts), act (the state-creating request)].
        $routes = [
            'mint' => [fn (): array => ['c' => MintHarness::csrf($h->get('/settings/tokens/new')['body'])],
                fn (array $d): array => $h->post('/settings/tokens', ['csrf_token' => $d['c'], 'note' => 'failmint', 'expiration' => '30', 'scopes' => ['read:user']])],
            'app' => [fn (): array => ['c' => MintHarness::csrf($h->get('/settings/applications/new')['body'])],
                fn (array $d): array => $h->post('/settings/applications', ['csrf_token' => $d['c'], 'name' => 'fail-app', 'homepage_url' => 'https://a.example.com', 'callback_url' => 'https://a.example.com/cb'])],
            'secret' => [function () use ($h, $app): array {
                $f = $h->get($app['page']);

                return ['c' => MintHarness::csrf(substr($f['body'], (int) strpos($f['body'], '/secrets')))];
            }, fn (array $d): array => $h->post($app['page'] . '/secrets', ['csrf_token' => $d['c']])],
            'code' => [function () use ($h, $app): array {
                $page = $h->get('/login/oauth/authorize', http_build_query(['client_id' => $app['client'], 'scope' => 'read:user', 'state' => 'zz']));
                preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $page['body'], $m);

                return ['c' => MintHarness::csrf($page['body']), 'r' => $m[1] ?? ''];
            }, fn (array $d): array => $h->post('/login/oauth/authorize', ['csrf_token' => $d['c'], 'authorization_request' => $d['r'], 'authorize' => '1'])],
            'exchange' => [fn (): array => [], fn (array $d): array => $this->tokenPost($h, ['grant_type' => 'authorization_code', 'code' => $cm2[1], 'client_id' => $app['client'], 'client_secret' => $app['secret']])],
            'refresh' => [fn (): array => [], fn (array $d): array => $this->tokenPost($h, ['grant_type' => 'refresh_token', 'refresh_token' => $ex['refresh_token'], 'client_id' => $app['client'], 'client_secret' => $app['secret']])],
            'join' => [fn (): array => ['c' => MintHarness::csrf($h->get('/join', '', 'joiner', '45.79.77.7')['body'])],
                fn (array $d): array => $h->post('/join', ['csrf_token' => $d['c'], 'username' => 'newbie', 'email' => 'n@example.com', 'password' => 'Passw0rd!x', 'password_confirmation' => 'Passw0rd!x'], 'joiner', '45.79.77.7')],
            'signin' => [fn (): array => [], fn (array $d): array => ['plan' => null, 'status' => null, 'body' => '', 'signin' => $h->front->signIn(new \Funnypot\Core\RequestContext('POST', '/'), MintHarness::IP, 'artex1', 'Passw0rd!x')]],
            'twofa' => [function () use ($h): array {
                $page = $h->get('/settings/security');
                preg_match('/<p class=mono>([A-Z2-7]{32})<\/p>/', $page['body'], $m);

                return ['c' => MintHarness::csrf($page['body']), 'otp' => Totp::code(MintHarness::base32decode($m[1]), Totp::step($h->now))];
            }, fn (array $d): array => $h->post('/settings/security', ['csrf_token' => $d['c'], 'otp' => $d['otp']])],
            'confirm' => [fn (): array => ['c' => MintHarness::csrf($h->get('/settings/confirm')['body'])],
                fn (array $d): array => $h->post('/settings/confirm', ['csrf_token' => $d['c'], 'password' => 'Passw0rd!x'])],
        ];
        $snapshot = static function (MintHarness $h): string {
            $db = new \PDO('sqlite:' . $h->dir . '/token-mint.sqlite');

            return json_encode([
                $db->query('SELECT k, state FROM mint_state ORDER BY k')->fetchAll(\PDO::FETCH_ASSOC),
                $db->query('SELECT h, used FROM mint_codes ORDER BY h')->fetchAll(\PDO::FETCH_ASSOC),
                $db->query('SELECT h, used FROM mint_refresh ORDER BY h')->fetchAll(\PDO::FETCH_ASSOC),
            ]);
        };
        $cookieBefore = $h->jars['default']['session'];
        foreach (['commit', 'locked', 'unopenable'] as $m) {
            foreach ($routes as $name => [$prepare, $act]) {
                $h->now += 3;
                $h->jars['default']['session'] = $cookieBefore;
                $data = $prepare();
                $before = $snapshot($h);
                $lock = null;
                $real = $h->store;
                if ($m === 'commit') {
                    $mode = 'commit';
                } elseif ($m === 'locked') {
                    $lock = new \PDO('sqlite:' . $h->dir . '/token-mint.sqlite');
                    $lock->exec('BEGIN IMMEDIATE');
                } else {
                    @mkdir($h->dir . '/blocked', 0500);
                    $h->swapStore(new \Funnypot\App\Storage\TokenMintStore($h->dir . '/blocked/sub/token-mint.sqlite'));
                }
                try {
                    $r = $act($data);
                } finally {
                    $mode = null;
                    $lock?->exec('ROLLBACK');
                    if ($m === 'unopenable') {
                        $h->swapStore($real);
                    }
                }
                $what = "{$name} under {$m}";
                if ($name === 'signin') {
                    $res = $r['signin'];
                    self::assertArrayNotHasKey('cookie', (array) $res, $what);
                    self::assertTrue($res === null || $res === ['error' => 'signin_failed'], $what . ' ' . json_encode($res));
                } else {
                    $plan = $r['plan'];
                    self::assertNotNull($plan, "{$what}: never today's 404, an LLM page or a core body");
                    $ok = $name === 'exchange' || $name === 'refresh' ? [400, 429] : [422, 429, 303];
                    self::assertContains($plan->status, $ok, $what);
                    self::assertDoesNotMatchRegularExpression('/[a-z]{2,4}_(?:pat|oat|ort)_[0-9A-Za-z]{31}/', $r['body'], $what);
                    self::assertDoesNotMatchRegularExpression('~<p class=mono>[a-f0-9]{20,40}</p>~', $r['body'], $what);
                    self::assertDoesNotMatchRegularExpression('~<p class=mono>[a-z2-7]{5}-~', $r['body'], $what);
                    self::assertStringNotContainsString('Authorization code for', $r['body'], $what);
                    foreach ($plan->headers() as [$hn, $hv]) {
                        self::assertFalse($hn === 'Set-Cookie' && preg_match('/\Asession=[A-Za-z0-9_-]+/', $hv) === 1, "{$what} set a session");
                    }
                    if ($plan->status === 303) {
                        self::assertSame('/', $plan->header('Location'), "{$what}: only the no-session answer redirects (the store could not read the session)");
                    }
                }
                self::assertSame($before, $snapshot($h), "{$what} changed stored state");
            }
        }
        self::assertSame(0, $h->decoy->faults());
    }

    // --- 15. OpenAPI contract ------------------------------------------------------------------------

    public function test_the_api_answers_the_contract_core_documents(): void
    {
        $hp = MintCorpus::engine();
        $ops = [];
        $schemes = [];
        foreach (['/openapi.json', '/swagger.json', '/v2/api-docs'] as $doc) {
            $r = $hp->respond(new \Funnypot\Core\RequestContext('GET', $doc, '', ['User-Agent' => 'curl/8']));
            self::assertNotNull($r, $doc);
            $spec = json_decode($r->body, true);
            self::assertIsArray($spec, $doc);
            $base = isset($spec['servers'][0]['url']) ? (string) parse_url($spec['servers'][0]['url'], PHP_URL_PATH) : (string) ($spec['basePath'] ?? '');
            self::assertSame('/v2', rtrim($base, '/'), "{$doc} documents the /v2 base path");
            foreach ((array) $spec['paths'] as $path => $methods) {
                foreach ((array) $methods as $m => $op) {
                    $ops[strtoupper($m) . ' ' . $path] = array_map('intval', array_keys((array) ($op['responses'] ?? [])));
                }
            }
            $schemes += (array) ($spec['components']['securitySchemes'] ?? $spec['securityDefinitions'] ?? []);
        }
        self::assertArrayHasKey('GET /users', $ops);
        self::assertArrayHasKey('POST /auth/login', $ops);
        self::assertArrayHasKey('GET /orders/{id}', $ops);
        self::assertNotEmpty($schemes);
        $index = $hp->respond(new \Funnypot\Core\RequestContext('GET', '/api/v2', '', ['User-Agent' => 'curl/8']));
        preg_match_all('~/api/v2/(users|orders|auth/login)~', (string) $index?->body, $listed);
        self::assertNotEmpty($listed[1], 'the /api/v2 index advertises its operations');

        $h = $this->h();
        $h->join();
        $tok = $h->mint(['read:user']);
        $docs = $h->get('/docs/api');
        foreach (array_keys($ops) as $op) {
            [$m, $path] = explode(' ', $op, 2);
            $concrete = str_replace('{id}', '10422', $path);
            foreach (['/api/v2', '/v2'] as $pre) {
                self::assertTrue($h->decoy->owns($pre . $concrete), "{$pre}{$concrete} is answered");
            }
            self::assertStringContainsString('/v2/' . ltrim($path, '/'), $docs['body'], "/docs/api lists {$op}");
            if ($m === 'GET') {
                $bodies = [];
                foreach (['/api/v2', '/v2'] as $pre) {
                    foreach ([['Authorization' => 'Bearer ' . $tok], ['X-Api-Key' => $tok]] as $auth) {
                        $r = $h->get($pre . $concrete, '', 'default', MintHarness::IP, $auth);
                        self::assertContains($r['status'], array_merge($ops[$op], [401, 403, 429]), "{$pre}{$concrete}");
                        self::assertNotSame(401, $r['status'], 'both documented schemes authenticate');
                        $bodies[] = $r['body'];
                    }
                }
                self::assertCount(1, array_unique($bodies), "{$op}: byte-identical under both spellings and both schemes");
            }
        }
        foreach (['/api/v2', '/v2'] as $pre) {
            $ok = $h->request('POST', $pre . '/auth/login', '', '{"username":"artex1","password":"Passw0rd!x"}', ['Content-Type' => 'application/json']);
            self::assertSame(200, $ok['status']);
            self::assertSame('bearer', self::json($ok)['token_type']);
            self::assertCount(3, explode('.', self::json($ok)['access_token']));
            self::assertSame(400, $h->request('POST', $pre . '/auth/login', '', '{}', ['Content-Type' => 'application/json'])['status']);
            self::assertSame(401, $h->request('POST', $pre . '/auth/login', '', '{"username":"artex1","password":"nope-nope"}', ['Content-Type' => 'application/json'])['status']);
        }
    }

    // --- 16. IDOR ------------------------------------------------------------------------------------

    public function test_another_accounts_ids_answer_exactly_like_nonexistent_ones(): void
    {
        $h = $this->h();
        $h->join('alice', 'Passw0rd!x', 'a');
        $tokA = $h->mint(['read:user'], 'ci token', 'a', MintHarness::IP, 'Passw0rd!x', 'alice');
        $listA = $h->get('/settings/tokens', '', 'a');
        preg_match("~/settings/tokens/([a-f0-9]{12})/delete~", $listA['body'], $tm);
        $tokenId = $tm[1];
        $h->join('bob', 'Passw0rd!x', 'b');
        $h->join('carol', 'Passw0rd!x', 'c', '45.79.99.99');
        $ghost = 'abcdef012345';
        foreach (['b' => MintHarness::IP, 'c' => '45.79.99.99'] as $jar => $ip) {
            $a = $h->post('/settings/tokens/' . $tokenId . '/delete', ['csrf_token' => $this->deleteCsrf($h, $jar, $ip)], $jar, $ip);
            $n = $h->post('/settings/tokens/' . $ghost . '/delete', ['csrf_token' => $this->deleteCsrf($h, $jar, $ip)], $jar, $ip);
            self::assertSame([$n['status'], $n['plan']->headers(), $n['body']], [$a['status'], $a['plan']->headers(), $a['body']], "token id via {$jar}");
            self::assertSame(404, $a['status']);
            self::assertFalse($a['plan']->served);
        }
        self::assertSame(200, $h->get('/api/v2/user', '', 'a', MintHarness::IP, ['Authorization' => 'Bearer ' . $tokA])['status'], "alice's token survived");

        $appA = $this->appFor($h, 'a', 'alice');
        foreach (['b' => MintHarness::IP, 'c' => '45.79.99.99'] as $jar => $ip) {
            $x = $h->get('/settings/applications/' . $appA['id'], '', $jar, $ip);
            $y = $h->get('/settings/applications/' . $ghost, '', $jar, $ip);
            self::assertSame([$y['status'], $y['body']], [$x['status'], $x['body']], "app page via {$jar}");
            $auth = $h->get('/login/oauth/authorize', http_build_query(['client_id' => $appA['client'], 'scope' => 'read:user']), $jar, $ip);
            $none = $h->get('/login/oauth/authorize', http_build_query(['client_id' => str_repeat('0', 20), 'scope' => 'read:user']), $jar, $ip);
            self::assertSame([$none['status'], $none['body']], [$auth['status'], $auth['body']], "client id via {$jar}");
            $ex = $this->tokenPost($h, ['grant_type' => 'authorization_code', 'code' => $appA['code'], 'client_id' => str_repeat('0', 20), 'client_secret' => 'x'], $ip);
            $exNone = $this->tokenPost($h, ['grant_type' => 'authorization_code', 'code' => str_repeat('0', 20), 'client_id' => str_repeat('0', 20), 'client_secret' => 'x'], $ip);
            self::assertSame([$exNone['status'], $exNone['body']], [$ex['status'], $ex['body']], 'a code issued to another client reads as nonexistent');
            $sso = $h->get('/orgs/' . $h->persona->slug . '/sso', 'authorization_request=' . $appA['request'], $jar, $ip);
            $ssoNone = $h->get('/orgs/' . $h->persona->slug . '/sso', 'authorization_request=' . $ghost, $jar, $ip);
            self::assertSame(
                preg_replace("~value='[^']+'~", '', $ssoNone['body']),
                preg_replace("~value='[^']+'~", '', $sso['body']),
                "request id via {$jar}"
            );
        }
    }

    /** A valid delete-form token for the jar's account (an account without tokens shows no delete form). */
    private function deleteCsrf(MintHarness $h, string $jar, string $ip): string
    {
        $ctx = $h->decoy->context();
        $sess = $ctx->sessions->parse((string) $h->jars[$jar]['session'], $h->now);
        $s = $h->store->load(bin2hex($sess['kref']));

        return $ctx->csrfToken($sess['sid'], 'token_delete', (int) $s->d['a'][$s->accountPos($sess['acct'])]['ce'], $h->now);
    }

    /** @return array{id:string,client:string,code:string,request:string} */
    private function appFor(MintHarness $h, string $jar, string $user): array
    {
        $created = $h->until(function () use ($h, $jar): array {
            $form = $h->get('/settings/applications/new', '', $jar);

            return $h->post('/settings/applications', ['csrf_token' => MintHarness::csrf($form['body']), 'name' => 'alice-app', 'homepage_url' => 'https://a.example.com', 'callback_url' => 'https://a.example.com/cb'], $jar);
        }, static fn (array $r): bool => preg_match('~\A/settings/applications/[a-f0-9]{12}\z~', (string) $r['plan']?->header('Location')) === 1, $jar);
        $page = (string) $created['plan']->header('Location');
        $show = $h->get($page, '', $jar);
        preg_match('~<p>Client ID</p><p class=mono>([a-f0-9]{20})</p>~', $show['body'], $cm);
        $consent = $h->get('/login/oauth/authorize', http_build_query(['client_id' => $cm[1], 'scope' => 'read:user']), $jar);
        preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $consent['body'], $rq);
        $code = $h->until(function () use ($h, $jar, $cm): array {
            $c = $h->get('/login/oauth/authorize', http_build_query(['client_id' => $cm[1], 'scope' => 'read:user']), $jar);
            preg_match("~name=authorization_request value='([a-f0-9]{12})'~", $c['body'], $m);

            return $h->post('/login/oauth/authorize', ['csrf_token' => MintHarness::csrf($c['body']), 'authorization_request' => $m[1], 'authorize' => '1'], $jar);
        }, static fn (array $r): bool => str_contains($r['body'], 'Authorization code for'), $jar);
        preg_match('~<p class=mono>([a-f0-9]{20})</p>~', $code['body'], $cd);

        return ['id' => substr($page, strlen('/settings/applications/')), 'client' => $cm[1], 'code' => $cd[1], 'request' => $rq[1]];
    }

    // --- 17. siblings unchanged ----------------------------------------------------------------------

    public function test_sibling_paths_and_the_velocity_window_are_unchanged(): void
    {
        foreach ([null, 'llm'] as $llm) {
            $opts = $llm === null ? [] : ['llm' => 200];
            $armed = $this->h(true, $opts);
            $unarmed = $this->h(false, $opts);
            foreach (['/api/v2/backup.zip', '/api/v2/users/backup.zip', '/api/v2/www.tar.gz', '/api/v2/customers', '/api/v2/info', '/v2/x', '/api/v2'] as $i => $p) {
                $ip = '45.82.' . ($llm === null ? 1 : 2) . '.' . (10 + $i);
                $a = $armed->get($p, '', 'default', $ip);
                $u = $unarmed->get($p, '', 'default', $ip);
                self::assertNull($a['plan'], "{$p} is not the surface's");
                self::assertSame($u['body'], $a['body'], "{$p} body");
                $strip = static fn (array $rows): array => array_map(static function (array $r): array {
                    unset($r['ts'], $r['id']);

                    return $r;
                }, $rows);
                self::assertNotSame([], $u['rows'], "{$p} wrote rows");
                self::assertSame($strip($u['rows']), $strip($a['rows']), "{$p} rows");
            }
        }

        // Velocity, by construction: with the LLM off every unarmed miss is an unserved 404.
        $armed = $this->h();
        $unarmed = $this->h(false);
        $armed->join('velo', 'Passw0rd!x', 'default', '45.83.0.1');
        $read = $armed->mint(['read:user'], 'v', 'default', '45.83.0.1', 'Passw0rd!x', 'velo');
        $armed->enable2fa('default', '45.83.0.1');
        $orders = $armed->mint(['orders:read'], 'o', 'default', '45.83.0.1', 'Passw0rd!x', 'velo');
        $sprays = [
            'wordlist' => fn (int $i): string => '/api/v2/word' . $i,
            'users' => fn (int $i): string => '/api/v2/users/nobody' . $i,
            'orders' => fn (int $i): string => '/api/v2/orders/' . (20000 + $i),
            'app pages' => fn (int $i): string => '/settings/applications/' . sprintf('%012x', 0xabc000 + $i),
        ];
        $n = 0;
        foreach ($sprays as $name => $path) {
            foreach (['none' => [], 'read' => ['Authorization' => 'Bearer ' . $read], 'orders' => ['Authorization' => 'Bearer ' . $orders]] as $cred => $auth) {
                $ip = '45.84.' . intdiv($n, 200) . '.' . (1 + $n % 200);
                $n++;
                for ($i = 0; $i < 40; $i++) {
                    $armed->get($path($i), '', 'nojar', $ip, $auth);
                    $unarmed->get($path($i), '', 'nojar', $ip, $auth);
                }
                self::assertSame($unarmed->hits->probeVelocity($ip), $armed->hits->probeVelocity($ip), "{$name} spray with {$cred}");
                self::assertGreaterThan(0, $armed->hits->probeVelocity($ip)['recent'], "{$name} with {$cred} counts");
            }
        }
        $ctl = '45.85.0.1';
        for ($i = 0; $i < 40; $i++) {
            $r = $armed->get('/api/v2/user', '', 'nojar', $ctl, ['Authorization' => 'Bearer ' . $read]);
            self::assertTrue($r['main']['served']);
        }
        self::assertSame(['recent' => 0, 'extended' => 0], $armed->hits->probeVelocity($ctl), 'served answers do not count');
    }

    public function test_non_get_sprays_on_id_paths_count_like_misses(): void
    {
        $armed = $this->h();
        $unarmed = $this->h(false);
        $armed->join('velo2', 'Passw0rd!x', 'default', '45.87.0.1');
        // The oversized leg runs six requests, enough to pass the five-path window: the engine itself
        // spends about a third of a second on each 16 KB body, so forty would dominate the file.
        $legs = [
            'PUT users' => ['PUT', fn (int $i): string => '/api/v2/users/nobody' . $i, '{}', ['Content-Type' => 'application/json'], 'nojar', 40],
            'DELETE users' => ['DELETE', fn (int $i): string => '/v2/users/nobody' . $i, null, [], 'nojar', 40],
            'POST users' => ['POST', fn (int $i): string => '/api/v2/users/nobody' . $i, 'a=1', [], 'nojar', 40],
            'OPTIONS users' => ['OPTIONS', fn (int $i): string => '/api/v2/users/nobody' . $i, null, [], 'nojar', 40],
            'POST orders' => ['POST', fn (int $i): string => '/api/v2/orders/' . (500 + $i), 'a=1', [], 'nojar', 40],
            'csrf delete' => ['POST', fn (int $i): string => '/settings/tokens/' . sprintf('%012x', 0xbee000 + $i) . '/delete', 'csrf_token=x', [], 'default', 40],
            'oversized' => ['POST', fn (int $i): string => '/settings/applications/' . sprintf('%012x', 0xcab000 + $i) . '/secrets', str_repeat('a', 16385), [], 'nojar', 6],
        ];
        $n = 0;
        foreach ($legs as $name => [$m, $path, $body, $hd, $jar, $count]) {
            $ip = $jar === 'default' ? '45.87.0.1' : '45.88.0.' . (++$n);
            $before = $armed->hits->probeVelocity($ip);
            for ($i = 0; $i < $count; $i++) {
                $a = $armed->request($m, $path($i), '', $body, $hd, $ip, $jar);
                self::assertNotNull($a['plan'], "{$name} is answered by the surface");
                self::assertFalse($a['main']['served'], "{$name}: {$a['plan']->status} discloses nothing");
                $unarmed->request($m, $path($i), '', $body, $hd, $ip, $jar);
            }
            if ($jar === 'nojar') {
                self::assertSame($unarmed->hits->probeVelocity($ip), $armed->hits->probeVelocity($ip), $name);
                self::assertSame($count, $armed->hits->probeVelocity($ip)['recent'], "{$name} counts every request");
            } else {
                self::assertGreaterThan($before['recent'], $armed->hits->probeVelocity($ip)['recent'], "{$name} counts toward the window");
            }
        }
    }

    public function test_replayed_own_forms_never_pin_but_a_blind_non_get_spray_does(): void
    {
        $llm = ['llm' => 500, 'probeGate' => true];

        // An account scrapes its six delete forms, signs in again (a new session, so every scraped token
        // is stale) and replays them: six 422s to forms we signed, which is use of our own pages.
        $h = $this->h(true, $llm + ['friction' => false]);
        $ip = '45.90.0.1';
        $h->join('replay', 'Passw0rd!x', 'default', $ip);
        for ($i = 0; $i < 6; $i++) {
            $h->mint(['read:user'], 'r' . $i, 'default', $ip, 'Passw0rd!x', 'replay');
        }
        $list = $h->get('/settings/tokens', '', 'default', $ip);
        preg_match_all("~/settings/tokens/([a-f0-9]{12})/delete'><input type=hidden name=csrf_token value='([^']+)'~", $list['body'], $forms, PREG_SET_ORDER);
        self::assertCount(6, $forms);
        $h->signIn('replay', 'Passw0rd!x', 'default', $ip);
        foreach ($forms as [, $id, $csrf]) {
            $r = $h->post('/settings/tokens/' . $id . '/delete', ['csrf_token' => $csrf], 'default', $ip);
            self::assertSame(422, $r['status']);
            self::assertStringContainsString('This form has expired', $r['body'], 'the answer is unchanged');
            self::assertTrue($r['main']['served'], 'a stale form of ours does not count');
        }
        self::assertFalse($h->hits->isBulkFlagged($ip), 'replaying our own forms never pins');
        self::assertSame(0, $h->hits->probeVelocity($ip)['recent']);

        // A blind PUT/DELETE spray carries no token of ours: it pins at the same request as unarmed.
        $pinAt = function (bool $armed, string $sprayIp) use ($llm): ?int {
            $s = $this->h($armed, $llm);
            for ($i = 0; $i < 12; $i++) {
                $s->request($i % 2 === 0 ? 'PUT' : 'DELETE', '/api/v2/users/blind' . $i, '', $i % 2 === 0 ? 'csrf_token=' . str_repeat('A', 36) : null, [], $sprayIp, 'nojar');
                if ($s->hits->isBulkFlagged($sprayIp)) {
                    return $i;
                }
            }

            return null;
        };
        $armedAt = $pinAt(true, '45.90.1.1');
        self::assertNotNull($armedAt, 'a blind spray still pins');
        self::assertSame($pinAt(false, '45.90.1.2'), $armedAt, 'at the unarmed index');
    }

    // --- 18. timing parity ---------------------------------------------------------------------------

    public function test_the_serve_delay_is_paid_exactly_when_the_unarmed_branch_would_pay_it(): void
    {
        $cases = [
            'null-core GET' => ['GET', '/settings/tokens', '', null, []],
            'null-core API' => ['GET', '/api/v2/user', '', null, []],
            'xss note' => ['POST', '/settings/tokens', '', 'note=%3Cscript%3Ealert(1)%3C%2Fscript%3E', MintCorpus::F],
            'cpsrvd login' => ['POST', '/api/v2/auth/login', '', '{"username":"a","password":"b"}', MintCorpus::J],
        ];
        foreach ($cases as $name => [$m, $p, $q, $b, $hd]) {
            $a = $this->h();
            $u = $this->h(false);
            $a->request($m, $p, $q, $b, $hd);
            $u->request($m, $p, $q, $b, $hd);
            self::assertSame($u->delays, $a->delays, $name);
            self::assertSame(in_array($name, ['xss note', 'cpsrvd login'], true) ? 0 : 1, $a->delays, "{$name}: the engine already slept for a matched request");
        }
    }

    // --- 19. SleepDecoy ------------------------------------------------------------------------------

    public function test_a_sleep_probe_on_a_form_field_is_delayed_like_any_field_and_answered_unchanged(): void
    {
        $run = function (bool $decoyOn, array $notes): array {
            $sleeps = [];
            $config = \Funnypot\App\Config\AppConfig::fromEnv(sys_get_temp_dir());
            $config->sleepDecoy = $decoyOn;
            $config->sleepPerReqCapMs = 2000;
            $budget = new \Funnypot\App\Storage\TarpitBudget(sys_get_temp_dir() . '/fp0815sd_' . bin2hex(random_bytes(5)) . '.sqlite', true, 8, 4, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, static fn (): int => 1_000_000, 0, static function (int $ms) use (&$sleeps): void {
                $sleeps[] = $ms;
            });
            $h = $this->h(true, ['sleepDecoy' => new \Funnypot\App\Http\SleepDecoy($budget, $config, new \Funnypot\App\ThreatIntel\AttackClassifier(), static fn (int $c): int => $c)]);
            $h->join();
            $out = [];
            foreach ($notes as $note) {
                $form = $h->get('/settings/tokens/new');
                $before = count($sleeps);
                $r = $h->post('/settings/tokens', ['csrf_token' => MintHarness::csrf($form['body']), 'note' => $note, 'expiration' => '30', 'scopes' => ['read:user']]);
                $out[] = ['status' => $r['status'], 'body' => preg_replace("~value='[^']+'~", '', $r['body']), 'slept' => array_slice($sleeps, $before)];
            }
            $other = $h->post('/contact.php', ['note' => $notes[0]]);
            $state = $h->store->db()->query('SELECT state FROM mint_state')->fetchAll(\PDO::FETCH_COLUMN);

            return ['answers' => $out, 'offPath' => array_slice($sleeps, -1), 'state' => $state, 'h' => $h];
        };
        $notes = ["x' AND SLEEP(3)-- ", "1' AND IF(SUBSTRING(a,1,1)='a',SLEEP(3),0)-- ", "1' AND IF(SUBSTRING(a,1,1)='b',SLEEP(3),0)-- "];
        $on = $run(true, $notes);
        $off = $run(false, $notes);
        foreach ($on['answers'] as $i => $a) {
            self::assertSame(422, $a['status']);
            self::assertStringContainsString('Note may only contain', html_entity_decode($a['body']), 'the charset error, nothing data-bearing');
            self::assertSame($off['answers'][$i]['body'], $a['body'], 'byte-identical with and without the delay');
            self::assertSame([], $off['answers'][$i]['slept']);
            self::assertNotEmpty($a['slept'], 'delayed like any field');
            self::assertSame($on['offPath'], $a['slept'], 'the same delay as the same payload on a path the surface does not own');
        }
        self::assertSame($on['answers'][1]['slept'], $on['answers'][2]['slept'], 'an extraction guess pair times identically');
        $strip = static fn (array $rows): array => array_map(static fn (string $j): string => (string) preg_replace('/"e":"[0-9a-f]{16}"/', '', $j), $rows);
        self::assertSame($strip($off['state']), $strip($on['state']), 'the stored state, and so the picker inputs, never see the delay');
    }

    // --- 20. spray pin -------------------------------------------------------------------------------

    public function test_a_spray_of_non_disclosing_answers_pins_at_the_unarmed_index(): void
    {
        $paths = [];
        for ($i = 0; $i < 4; $i++) {
            $paths[] = '/api/v2/users/nobody' . $i;
            $paths[] = '/api/v2/orders/' . (300 + $i);
            $paths[] = '/settings/applications/' . sprintf('%012x', 0xfed000 + $i);
        }
        $pinAt = function (bool $armed, string $ip, array $opts) use ($paths): ?int {
            $h = $this->h($armed, $opts);
            foreach ($paths as $i => $p) {
                $h->get($p, '', 'nojar', $ip);
                if ($h->hits->isBulkFlagged($ip)) {
                    return $i;
                }
            }

            return null;
        };
        $llm = ['llm' => 500, 'probeGate' => true];
        $armedAt = $pinAt(true, '45.86.0.1', $llm);
        $unarmedAt = $pinAt(false, '45.86.0.2', $llm);
        self::assertNotNull($unarmedAt, 'sanity: the unarmed spray pins');
        self::assertSame($unarmedAt, $armedAt, 'the same request index');

        $few = $this->h(true, $llm);
        foreach (array_slice($paths, 0, 4) as $p) {
            $few->get($p, '', 'nojar', '45.86.0.3');
        }
        self::assertFalse($few->hits->isBulkFlagged('45.86.0.3'), 'fewer misses set no pin');
        self::assertNull($pinAt(true, '45.86.0.4', $llm + ['allowIps' => ['45.86.0.4']]), 'an allowlisted IP is never pinned');
        self::assertNull($pinAt(true, '45.86.0.5', []), 'LLM off: nothing pins armed');

        // An engine match never reaches the miss path, so armed or not it never pins.
        foreach ([true, false] as $armedRun) {
            $m = $this->h($armedRun, $llm);
            $ip = $armedRun ? '45.86.1.1' : '45.86.1.2';
            foreach (array_slice($paths, 0, 5) as $p) {
                $m->get($p, '', 'nojar', $ip);
            }
            self::assertFalse($m->hits->isBulkFlagged($ip), 'five misses are not yet a scan');
            $m->get('/api/v2/users/zed', 'id=1%20union%20select%201,2--', 'nojar', $ip);
            self::assertFalse($m->hits->isBulkFlagged($ip), ($armedRun ? 'armed' : 'unarmed') . ': a matched request does not pin');
        }
        self::assertNull($pinAt(false, '45.86.0.6', []), 'LLM off: nothing pins unarmed');

        $h = $this->h(true, $llm);
        $before = $h->get('/api/v2/users/zed', '', 'nojar', '45.86.0.7');
        foreach ($paths as $p) {
            $h->get($p, '', 'nojar', '45.86.0.7');
        }
        self::assertTrue($h->hits->isBulkFlagged('45.86.0.7'));
        $after = $h->get('/api/v2/users/zed', '', 'nojar', '45.86.0.7');
        self::assertSame($before['body'], $after['body'], 'a pin never changes the surface\'s answers');
    }
}

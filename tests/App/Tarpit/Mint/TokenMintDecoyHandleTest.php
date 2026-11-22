<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\MintPlan;
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
        self::assertSame(200, $h->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $jwt])['status']);

        // Re-signed with the persona's published JWT secret: rejected like any forgery.
        $persona = \Funnypot\Core\Support\PersonaIdentity::fromSeed(\Funnypot\Tests\App\Identity\IdentityTestSupport::httpIdentity()->personaSeed());
        [, $payload] = explode('.', $jwt);
        $claims = json_decode((string) base64_decode(strtr($payload, '-_', '+/')), true);
        $forged = \Funnypot\App\Tarpit\Mint\JwtCodec::encode($claims, (string) $persona->field('secret.jwt'));
        $r = $h->get('/api/v2/user', '', 'default', MintHarness::IP, ['Authorization' => 'Bearer ' . $forged]);
        self::assertSame(401, $r['status']);
        self::assertSame('Bad credentials', self::json($r)['message']);

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
}

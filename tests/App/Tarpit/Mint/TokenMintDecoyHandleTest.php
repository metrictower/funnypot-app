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
        foreach ($this->harnesses as $h) {
            $h->cleanup();
        }
        $this->harnesses = [];
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
}

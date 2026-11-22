<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\AuthzPolicy;
use Funnypot\App\Tarpit\Mint\MintRoutes;
use Funnypot\App\Tarpit\Mint\ScopeSet;
use PHPUnit\Framework\TestCase;

final class AuthzPolicyTest extends TestCase
{
    public function test_the_full_matrix_never_grants_organisation_data(): void
    {
        $kinds = ['pat', 'oat', 'jwt'];
        $scopeSets = [[], ['read:user'], array_keys(ScopeSet::ALL)];
        foreach (AuthzPolicy::ENDPOINTS as $ep => $methods) {
            foreach (array_keys($methods) as $m) {
                self::assertSame('auth', AuthzPolicy::decide($ep, $m, null)['decision']);
                self::assertSame(401, AuthzPolicy::decide($ep, $m, ['kind' => 'bad', 'scopes' => []])['status']);
                foreach ($kinds as $k) {
                    foreach ($scopeSets as $scopes) {
                        $d = AuthzPolicy::decide($ep, $m, ['kind' => $k, 'scopes' => $scopes]);
                        [$need, $walled] = $methods[$m];
                        if ($need !== null && !in_array($need, $scopes, true)) {
                            self::assertSame(['decision' => 'scope', 'status' => 403, 'required' => [$need]], $d, "{$ep} {$m} {$k}");
                        } elseif ($walled) {
                            self::assertSame($k === 'oat' ? 'approval' : 'sso', $d['decision'], "{$ep} {$m} {$k}");
                            self::assertSame(403, $d['status']);
                        } else {
                            self::assertSame('ok', $d['decision'], "{$ep} {$m} {$k}");
                        }
                        // The member's own order list is the one org-scoped read that answers (always empty).
                        if ($ep !== 'user_orders' && in_array($need, ScopeSet::ORG_DATA, true)) {
                            self::assertNotSame('ok', $d['decision'], "{$ep} never answers organisation data");
                        }
                    }
                }
            }
        }
        self::assertSame(405, AuthzPolicy::decide('user', 'DELETE', ['kind' => 'pat', 'scopes' => []])['status']);
        self::assertSame('ok', AuthzPolicy::decide('user', 'HEAD', ['kind' => 'pat', 'scopes' => []])['decision'], 'HEAD reads like GET');
    }

    public function test_both_spellings_reach_the_same_endpoint(): void
    {
        $r = new MintRoutes('palvora');
        foreach (['user', 'user/orgs', 'user/orders', 'users', 'users/jdoe', 'orgs/palvora', 'orgs/palvora/members', 'orders', 'orders/10422', 'orders/exports', 'auth/login'] as $tail) {
            $a = $r->match('/api/v2/' . $tail);
            $b = $r->match('/v2/' . $tail);
            self::assertNotNull($a, $tail);
            self::assertSame($a, $b, "{$tail}: one endpoint under both spellings");
        }
    }

    public function test_the_wall_comes_before_any_object_lookup(): void
    {
        $orders = ['kind' => 'pat', 'scopes' => ['orders:read']];
        self::assertSame(AuthzPolicy::decide('orders_id', 'GET', $orders), AuthzPolicy::decide('orders', 'GET', $orders));
        self::assertSame('sso', AuthzPolicy::decide('orders_id', 'GET', $orders)['decision']);
        self::assertSame('sso', AuthzPolicy::decide('users', 'GET', ['kind' => 'jwt', 'scopes' => ['users:read']])['decision']);
        self::assertSame('ok', AuthzPolicy::decide('users_login', 'GET', ['kind' => 'jwt', 'scopes' => ['read:user']])['decision'], 'a public profile takes any credential');
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * Who may call what on the member API. The account is a member of the persona's organisation, never
 * an owner: its own profile and the organisation's public face are readable, and everything that is
 * organisation data sits behind single sign-on (personal tokens) or owner approval (OAuth tokens).
 * Authentication is decided first and the wall before any existence check, so an id never leaks
 * whether it exists. The same table answers both API spellings.
 */
final class AuthzPolicy
{
    /** endpoint => method => [required scope or null for any credential, behind the org wall] */
    public const ENDPOINTS = [
        'user' => ['GET' => [null, false], 'PATCH' => ['user:write', false]],
        'user_orgs' => ['GET' => ['read:org', false]],
        'user_orders' => ['GET' => ['orders:read', false]],
        'users' => ['GET' => ['users:read', true]],
        'users_login' => ['GET' => [null, false]],
        'orgs_org' => ['GET' => ['read:org', false]],
        'orgs_members' => ['GET' => ['users:read', true]],
        'orders' => ['GET' => ['orders:read', true]],
        'orders_id' => ['GET' => ['orders:read', true]],
        'orders_exports' => ['POST' => ['orders:export', true]],
    ];

    /**
     * @param array{kind:string,scopes:list<string>}|null $cred null = no credential presented;
     *        kind 'bad' = a credential that does not verify
     * @return array{decision:string,status:int,required:list<string>}
     *         decision ∈ ok | auth | bad_credentials | scope | sso | approval | method
     */
    public static function decide(string $endpoint, string $method, ?array $cred): array
    {
        $rule = self::ENDPOINTS[$endpoint][$method === 'HEAD' ? 'GET' : $method] ?? null;
        if ($rule === null) {
            return ['decision' => 'method', 'status' => 405, 'required' => []];
        }
        if ($cred === null) {
            return ['decision' => 'auth', 'status' => 401, 'required' => []];
        }
        if ($cred['kind'] === 'bad') {
            return ['decision' => 'bad_credentials', 'status' => 401, 'required' => []];
        }
        [$scope, $walled] = $rule;
        if ($scope !== null && !in_array($scope, $cred['scopes'], true)) {
            return ['decision' => 'scope', 'status' => 403, 'required' => [$scope]];
        }
        if ($walled) {
            return ['decision' => $cred['kind'] === 'oat' ? 'approval' : 'sso', 'status' => 403, 'required' => $scope === null ? [] : [$scope]];
        }

        return ['decision' => 'ok', 'status' => 200, 'required' => []];
    }

    /** @return list<string> the methods an endpoint answers, for Allow */
    public static function methods(string $endpoint): array
    {
        $m = array_keys(self::ENDPOINTS[$endpoint] ?? []);
        if (in_array('GET', $m, true)) {
            $m[] = 'HEAD';
        }

        return $m;
    }
}

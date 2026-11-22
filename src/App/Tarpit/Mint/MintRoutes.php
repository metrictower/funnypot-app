<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\App\Http\HoneypotController;

/**
 * The closed set of paths the account surface owns. Ownership is a function of the path alone (never
 * of the method, the body or the engine's answer), so it is known before any serve decision.
 *
 * Exact routes match after stripping one trailing slash; the few patterns take bounded segments:
 * `{org}` is only the persona's organisation slug, `{login}` a username-shaped segment, `{id}` a
 * lowercase alphanumeric segment of 1–20 characters with at least one digit (so a letter-only word such
 * as `export` is never an id). A segment ending in `.php` (any case) never matches a pattern, and no
 * path a backup-archive or text decoy would serve is ever owned, so those keep their answers.
 */
final class MintRoutes
{
    public const LOGIN = '[A-Za-z0-9][A-Za-z0-9_.-]{0,38}';
    /** Any 1–20 character lowercase id holding a digit: every length answers alike, words never match. */
    public const ID = '(?=[a-z0-9]{0,19}[0-9])[a-z0-9]{1,20}';

    /** path => [route id, methods] */
    public const EXACT = [
        '/join' => ['join', ['GET', 'POST']],
        '/signout' => ['signout', ['GET', 'POST']],
        '/settings/profile' => ['profile', ['GET', 'POST']],
        '/settings/security' => ['security', ['GET', 'POST']],
        '/settings/confirm' => ['confirm', ['GET', 'POST']],
        '/settings/tokens' => ['tokens', ['GET', 'POST']],
        '/settings/tokens/new' => ['token_new', ['GET']],
        '/settings/applications' => ['apps', ['GET', 'POST']],
        '/settings/applications/new' => ['app_new', ['GET']],
        '/login/oauth/authorize' => ['authorize', ['GET', 'POST']],
        '/login/oauth/access_token' => ['access_token', ['POST']],
        '/docs/api' => ['docs', ['GET']],
    ];

    /** API path under both spellings => [endpoint id] (methods come from AuthzPolicy) */
    public const API_EXACT = [
        'user' => 'user',
        'user/orgs' => 'user_orgs',
        'user/orders' => 'user_orders',
        'users' => 'users',
        'orders' => 'orders',
        'orders/exports' => 'orders_exports',
        'auth/login' => 'auth_login',
    ];

    public const API_PREFIXES = ['/api/v2/', '/v2/'];

    public function __construct(private string $orgSlug)
    {
    }

    public static function normalise(string $path): string
    {
        $hash = strpos($path, '#');
        if ($hash !== false) {
            $path = substr($path, 0, $hash);
        }
        if (strlen($path) > 1 && substr($path, -1) === '/') {
            $path = substr($path, 0, -1);
        }

        return $path;
    }

    public function owns(string $path): bool
    {
        return $this->match($path) !== null;
    }

    /**
     * @return array{route:string,methods:list<string>,params:array<string,string>,api:bool,pattern:bool}|null
     */
    public function match(string $rawPath): ?array
    {
        if (strlen($rawPath) > 200 || HoneypotController::decoyForPath($rawPath) !== null) {
            return null;
        }
        $path = self::normalise($rawPath);
        if (isset(self::EXACT[$path])) {
            return ['route' => self::EXACT[$path][0], 'methods' => self::EXACT[$path][1], 'params' => [], 'api' => false, 'pattern' => false];
        }
        foreach (self::API_PREFIXES as $prefix) {
            if (strncmp($path, $prefix, strlen($prefix)) === 0) {
                return $this->api(substr($path, strlen($prefix)));
            }
        }
        if (preg_match('~\.php\z~i', $path) === 1) {
            return null;
        }
        $org = preg_quote($this->orgSlug, '~');
        $patterns = [
            '~\A/settings/tokens/(' . self::ID . ')/delete\z~' => ['token_delete', ['POST']],
            '~\A/settings/applications/(' . self::ID . ')\z~' => ['app_show', ['GET']],
            '~\A/settings/applications/(' . self::ID . ')/secrets\z~' => ['app_secret', ['POST']],
            '~\A/settings/applications/(' . self::ID . ')/delete\z~' => ['app_delete', ['POST']],
            '~\A/orgs/(' . $org . ')/sso\z~' => ['sso', ['GET', 'POST']],
            '~\A/idp/(' . $org . ')/signin\z~' => ['idp', ['GET', 'POST']],
        ];
        foreach ($patterns as $re => [$route, $methods]) {
            if (preg_match($re, $path, $m) === 1) {
                return ['route' => $route, 'methods' => $methods, 'params' => ['id' => $m[1]], 'api' => false, 'pattern' => true];
            }
        }

        return null;
    }

    /** @return array{route:string,methods:list<string>,params:array<string,string>,api:bool,pattern:bool}|null */
    private function api(string $rest): ?array
    {
        if (isset(self::API_EXACT[$rest])) {
            $ep = self::API_EXACT[$rest];
            $methods = $ep === 'auth_login' ? ['POST'] : AuthzPolicy::methods($ep);

            return ['route' => $ep, 'methods' => array_values(array_diff($methods, ['HEAD'])), 'params' => [], 'api' => true, 'pattern' => false];
        }
        if (preg_match('~\.php\z~i', $rest) === 1) {
            return null;
        }
        $org = preg_quote($this->orgSlug, '~');
        $patterns = [
            '~\Ausers/(' . self::LOGIN . ')\z~' => 'users_login',
            '~\Aorgs/(' . $org . ')\z~' => 'orgs_org',
            '~\Aorgs/(' . $org . ')/members\z~' => 'orgs_members',
            '~\Aorders/(' . self::ID . ')\z~' => 'orders_id',
        ];
        foreach ($patterns as $re => $ep) {
            if (preg_match($re, $rest, $m) === 1) {
                return ['route' => $ep, 'methods' => array_values(array_diff(AuthzPolicy::methods($ep), ['HEAD'])), 'params' => ['id' => $m[1]], 'api' => true, 'pattern' => true];
            }
        }

        return null;
    }
}

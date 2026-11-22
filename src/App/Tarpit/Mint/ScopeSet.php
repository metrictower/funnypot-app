<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * The closed set of token scopes. Requested scopes are matched against it and never echoed; an
 * unknown name is simply not a scope.
 */
final class ScopeSet
{
    /** scope => description shown on the forms */
    public const ALL = [
        'read:user' => 'Read your profile',
        'user:write' => 'Update your profile',
        'read:org' => 'Read organization membership',
        'users:read' => 'Read organization members',
        'orders:read' => 'Read orders',
        'orders:export' => 'Export orders',
        'admin:org' => 'Manage the organization',
    ];

    /** Scopes that need two-factor authentication and a fresh confirm-access window to grant. */
    public const SENSITIVE = ['users:read', 'orders:read', 'orders:export'];

    /** Scopes behind the organization's single sign-on. */
    public const ORG_DATA = ['users:read', 'orders:read', 'orders:export'];

    public static function known(string $scope): bool
    {
        return isset(self::ALL[$scope]);
    }

    /**
     * Normalise a list to known scopes, sorted and unique. Unknown names are dropped.
     *
     * @param list<string> $scopes
     * @return list<string>
     */
    public static function normalise(array $scopes): array
    {
        $out = [];
        foreach ($scopes as $s) {
            if (self::known($s)) {
                $out[$s] = true;
            }
        }
        $names = array_keys($out);
        sort($names);

        return $names;
    }

    /** @param list<string> $scopes */
    public static function anySensitive(array $scopes): bool
    {
        return array_intersect($scopes, self::SENSITIVE) !== [];
    }

    /**
     * Split an OAuth `scope` parameter (space or comma separated) into known scopes.
     *
     * @return list<string>
     */
    public static function parseParam(string $param): array
    {
        $parts = preg_split('/[\s,]+/', substr($param, 0, 256), 16) ?: [];

        return self::normalise(array_values(array_filter($parts, static fn ($p): bool => $p !== '')));
    }
}

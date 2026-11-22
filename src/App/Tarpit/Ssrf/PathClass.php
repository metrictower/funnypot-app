<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * The coarse kind of path a fetch asked for. Answers depend on the class, never on the path's bytes,
 * so nothing a visitor types can reach a rendered body.
 */
enum PathClass: string
{
    case Root = 'root';
    case Health = 'health';
    case Metrics = 'metrics';
    case Api = 'api';
    case Admin = 'admin';
    case Git = 'git';
    case Token = 'token';
    case Meta = 'meta';
    case Verify = 'verify';
    case Other = 'other';

    public static function of(string $path): self
    {
        $p = strtolower(substr($path, 0, 512));
        if ($p === '' || $p === '/') {
            return self::Root;
        }
        if (str_contains($p, '/.verify-')) {
            return self::Verify;
        }
        if ($p === '/latest/api/token' || $p === '/latest/api/token/') {
            return self::Token;
        }
        if (str_starts_with($p, '/latest/') || str_starts_with($p, '/computemetadata') || str_starts_with($p, '/metadata')) {
            return self::Meta;
        }
        if (str_contains($p, '.git') || str_contains($p, '/info/refs')) {
            return self::Git;
        }
        foreach (['/health', '/status', '/ping', '/ready', '/live'] as $h) {
            if (str_starts_with($p, $h)) {
                return self::Health;
            }
        }
        if (str_starts_with($p, '/metrics')) {
            return self::Metrics;
        }
        foreach (['/api', '/v1', '/v2', '/v3', '/graphql'] as $a) {
            if (str_starts_with($p, $a)) {
                return self::Api;
            }
        }
        foreach (['/admin', '/login', '/console', '/dashboard', '/ui', '/manage'] as $a) {
            if (str_starts_with($p, $a)) {
                return self::Admin;
            }
        }

        return self::Other;
    }
}

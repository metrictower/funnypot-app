<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * A parsed fetch URL. `host` is the canonical form the network is keyed on: a lowercase name without a
 * trailing dot, a dotted IPv4 address whatever spelling it was written in, or a bracketed IPv6
 * address. `hostRaw` is the authority's host exactly as written, which only the naive create-time
 * denylist reads.
 */
final class Target
{
    public function __construct(
        public readonly string $scheme,
        public readonly string $hostRaw,
        public readonly string $host,
        public readonly string $kind,
        public readonly ?int $ipv4,
        public readonly ?string $ipv6,
        public readonly int $port,
        public readonly string $path,
        public readonly string $query,
        public readonly ?string $user,
        public readonly ?string $pass,
    ) {
    }

    public function hostPort(): string
    {
        return $this->host . ':' . $this->port;
    }

    public function hasUserinfo(): bool
    {
        return $this->user !== null;
    }

    public static function dotted(int $ip): string
    {
        return (($ip >> 24) & 255) . '.' . (($ip >> 16) & 255) . '.' . (($ip >> 8) & 255) . '.' . ($ip & 255);
    }
}

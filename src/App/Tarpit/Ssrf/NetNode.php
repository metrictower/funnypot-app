<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * One host on the fake internal network, as a directory knows it. `key` seeds everything the host
 * answers, so a host reached by its name and by its address answers alike. `state` is how the host
 * itself behaves: live (open ports answer, others refuse), refused, timeout, no_route, or transient
 * (a name the resolver cannot answer yet).
 */
final class NetNode
{
    public const KINDS = ['http_api', 'admin_ui', 'metrics', 'registry', 'db', 'cache', 'ssh', 'sts', 'payments'];
    public const STATES = ['live', 'refused', 'timeout', 'no_route', 'transient'];

    /** @param list<int> $ports */
    public function __construct(
        public readonly string $key,
        public readonly string $kind,
        public readonly string $host,
        public readonly array $ports,
        public readonly string $state = 'live',
    ) {
        if (!in_array($kind, self::KINDS, true) || !in_array($state, self::STATES, true)) {
            throw new \LogicException('node outside the closed sets');
        }
    }

    public static function transient(string $host): self
    {
        return new self('transient', 'http_api', $host, [], 'transient');
    }

    /** The first open port, for a listing that names the host. */
    public function primaryPort(): int
    {
        return $this->ports[0] ?? 80;
    }
}

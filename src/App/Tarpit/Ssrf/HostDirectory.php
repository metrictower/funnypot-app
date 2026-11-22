<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * A source of internal hosts: the fake network's own generated hosts, or the hosts another surface has
 * already leaked (settings.py, the fleet console, the infra wiki, the credential gateways). Providers
 * are pure; lookups never resolve anything for real.
 */
interface HostDirectory
{
    /** The node at a canonical name or dotted IPv4 address, or null when this provider has none. */
    public function lookup(string $host): ?NetNode;

    /**
     * Up to $n "host:port" strings this provider leaks, chosen by $label, so a listing that names them
     * is the same on every view.
     *
     * @return list<string>
     */
    public function sample(string $label, int $n): array;
}

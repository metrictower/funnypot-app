<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\Core\Support\PersonaIdentity;

/**
 * The fake internal network as a fetch worker sees it: the egress policy first, then the internal
 * resolver (the providers in order, then the generated subnet). Pure: the same target from the same
 * source with the same role always resolves the same way, and nothing is looked up for real.
 */
final class Network
{
    public function __construct(
        private EgressPolicy $policy,
        private DirectoryChain $providers,
        private InternalNet $generated,
        private CredentialEndpoints $credentials,
        private bool $credPointers,
    ) {
    }

    /**
     * The deploy's network: settings.py's hosts, the fleet, any extra provider (the infra wiki once it
     * is wired), the credential gateways, then the generated subnet. Region and domain are the persona's.
     *
     * @param list<HostDirectory> $extra
     */
    public static function build(SsrfKeys $keys, int $personaSeed, int $capBytes, KeyIndexView $index, bool $credPointers, array $extra = []): self
    {
        $persona = PersonaIdentity::fromSeed($personaSeed);
        $region = (string) ($persona->field('cloud.aws.region') ?: 'us-east-1');
        $domain = strtolower((string) ($persona->field('company.domain') ?: 'internal.example'));
        $credentials = new CredentialEndpoints($region);
        $providers = new DirectoryChain([
            new ConfigDumpHosts(new ConfigDump($personaSeed), $domain, $region, self::sections($capBytes), $index),
            new FleetHosts($personaSeed),
            ...$extra,
            $credentials,
        ]);

        return new self(
            new EgressPolicy($domain),
            $providers,
            new InternalNet($keys->key('netname'), InternalNet::octet($keys->key('subnet')), $region),
            $credentials,
            $credPointers,
        );
    }

    /** The settings.py sections a cap can serve, as an upper bound. */
    public static function sections(int $capBytes): int
    {
        return (int) ceil(max(0, $capBytes) / ConfigDump::MIN_SECTION_BYTES);
    }

    public function generated(): InternalNet
    {
        return $this->generated;
    }

    public function credentials(): CredentialEndpoints
    {
        return $this->credentials;
    }

    public function credPointers(): bool
    {
        return $this->credPointers;
    }

    /** Every directory, providers first, the generated subnet last. */
    public function directory(): DirectoryChain
    {
        return $this->providers->with($this->generated);
    }

    public function providers(): DirectoryChain
    {
        return $this->providers;
    }

    public function resolve(Target $t, string $sourceIp, Role $role, bool $denylist = false): Resolution
    {
        $egress = $this->policy->classify($t, $sourceIp, $role, $denylist);
        $simple = [
            'denylisted' => 'validation', 'loopback' => 'loopback', 'metadata' => 'metadata', 'proxied' => 'proxy_denied',
            'code_host' => 'code_host', 'unroutable' => 'unroutable', 'source' => 'timeout', 'private_other' => 'timeout',
        ];
        if ($egress === 'loopback' && !in_array($t->port, NodeAnswers::LOOPBACK_PORTS, true)) {
            return new Resolution($egress, 'refused', null, $t->port);
        }
        if (isset($simple[$egress])) {
            return new Resolution($egress, $simple[$egress], null, $t->port);
        }
        $node = $this->directory()->lookup($t->host);
        if ($node === null) {
            return $egress === 'internal'
                ? new Resolution($egress, 'nxdomain', null, $t->port)
                : new Resolution('private_other', 'timeout', null, $t->port);
        }
        $class = $egress === 'internal' ? 'internal' : (str_starts_with($node->key, 'g') ? 'generated' : 'leaked');

        return new Resolution($class, match ($node->state) {
            'live' => in_array($t->port, $node->ports, true) ? 'open' : 'refused',
            'refused' => 'refused',
            'no_route' => 'no_route',
            'transient' => 'dns_transient',
            default => 'timeout',
        }, $node, $t->port);
    }
}

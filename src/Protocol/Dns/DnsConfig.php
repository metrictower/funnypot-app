<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dns;

/**
 * Configuration/persona for the DNS honeypot (FP-0182, port 53 udp+tcp).
 *
 * Every value is cosmetic persona — a plausible BIND identity, a deterministic canary AXFR zone, and the
 * response mode. All persona values are derived from the install persona material (stable per install,
 * different across installs) so a replayed probe is byte-stable and no fleet-wide literal is served.
 * Nothing here resolves, opens a socket, or participates in amplification.
 */
final class DnsConfig
{
    public const MODE_MIRROR = 'mirror';     // answer A queries with the requester's own IP ("uno reverse")
    public const MODE_HONEYPOT = 'honeypot'; // answer with the box's own IP (pull deeper into the trap)
    public const MODE_SINKHOLE = 'sinkhole'; // known miner/C2 names -> 127.0.0.1, else the base mode

    public function __construct(
        public string $mode = self::MODE_MIRROR,
        public string $selfIp = '203.0.113.1',       // box's advertised IP (honeypot mode)
        public string $bindVersion = '9.18.18',      // persona BIND version (NOT a fleet literal)
        public string $bindHostname = 'ns1.internal',
        public string $serverId = 'ns1',
        public string $zoneApex = 'corp.internal',
        /** @var array<string,string> lowercased name => canary IPv4 (deterministic per seed) */
        public array $axfrZone = [],
        /** @var array<string,string> lowercased known-bad name => sinkhole IPv4 */
        public array $sinkhole = []
    ) {
    }

    public static function fromEnv(string $installPersonaMaterial): self
    {
        $mode = \strtolower((string) (\getenv('FUNNYPOT_DNS_MODE') ?: self::MODE_MIRROR));
        if (!\in_array($mode, [self::MODE_MIRROR, self::MODE_HONEYPOT, self::MODE_SINKHOLE], true)) {
            $mode = self::MODE_MIRROR;
        }
        $selfIp = \getenv('FUNNYPOT_DNS_SELF_IP') ?: '203.0.113.1';

        $seed = \getenv('FUNNYPOT_DNS_SEED') ?: $installPersonaMaterial;

        // Persona BIND version from a seeded pool (deterministic — mirrors MssqlConfig::deriveSeeded*).
        $versions = ['9.16.48', '9.18.18', '9.18.24', '9.20.0', '9.11.37'];
        $bindVersion = $versions[\crc32('bind:' . $seed) % \count($versions)];

        $hostPool = ['ns1.internal', 'ns1.corp.internal', 'dns01.internal', 'resolver.internal'];
        $bindHostname = $hostPool[\crc32('host:' . $seed) % \count($hostPool)];
        $serverId = \explode('.', $bindHostname)[0];

        $apexPool = ['corp.internal', 'internal.corp', 'ad.corp', 'lan.corp'];
        $zoneApex = $apexPool[\crc32('apex:' . $seed) % \count($apexPool)];

        return new self(
            mode: $mode,
            selfIp: $selfIp,
            bindVersion: $bindVersion,
            bindHostname: $bindHostname,
            serverId: $serverId,
            zoneApex: $zoneApex,
            axfrZone: self::deriveZone($seed, $zoneApex),
            sinkhole: self::knownBad()
        );
    }

    /** The persona BIND version TXT answer (CHAOS version.bind). */
    public function versionBind(): string
    {
        return $this->bindVersion;
    }

    /**
     * Deterministic canary AXFR zone — believable internal hostnames with seeded private IPs, so a
     * later intrusion against one of them correlates back to the zone-transfer recon.
     *
     * @return array<string,string>
     */
    private static function deriveZone(string $seed, string $apex): array
    {
        $hosts = ['vpn-gateway', 'db-cluster-master', 'gitlab-runner-secrets', 'ceo-laptop-rdp', 'backup-nas', 'jenkins-ci'];
        $zone = [];
        $i = 0;
        foreach ($hosts as $h) {
            // Private-range canary IP derived from the seed + host, deterministic.
            $n = \crc32($h . ':' . $seed);
            $ip = '10.' . (($n >> 16) & 0xFF) . '.' . (($n >> 8) & 0xFF) . '.' . (($n & 0xFF) | 1);
            $zone[$h . '.' . $apex] = $ip;
            if (++$i >= 6) {
                break;
            }
        }

        return $zone;
    }

    /**
     * Known cryptominer-pool / C2 names sinkholed to loopback. Durable facts (public pool hostnames),
     * not scanner signatures.
     *
     * @return array<string,string>
     */
    private static function knownBad(): array
    {
        return [
            'pool.supportxmr.com' => '127.0.0.1',
            'xmr.pool.minergate.com' => '127.0.0.1',
            'pool.hashvault.pro' => '127.0.0.1',
        ];
    }
}

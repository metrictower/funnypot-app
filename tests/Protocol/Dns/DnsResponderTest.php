<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Dns;

use Funnypot\Protocol\Dns\DnsConfig;
use Funnypot\Protocol\Dns\DnsMessage;
use Funnypot\Protocol\Dns\DnsQuery;
use Funnypot\Protocol\Dns\DnsResponder;
use PHPUnit\Framework\TestCase;

/**
 * FP-0182 Phase 2+3: the responder's anti-amplification clamp (THE invariant), the mirror/honeypot/
 * sinkhole modes, BIND CHAOS, and the AXFR zone — transport-aware.
 */
final class DnsResponderTest extends TestCase
{
    private function cfg(string $mode = DnsConfig::MODE_MIRROR): DnsConfig
    {
        return new DnsConfig(
            mode: $mode,
            selfIp: '198.51.100.9',
            bindVersion: '9.18.18',
            bindHostname: 'ns1.internal',
            serverId: 'ns1',
            zoneApex: 'corp.internal',
            axfrZone: ['vpn-gateway.corp.internal' => '10.8.0.1', 'db-master.corp.internal' => '10.9.0.2'],
            sinkhole: ['pool.supportxmr.com' => '127.0.0.1']
        );
    }

    /** Build the on-wire query bytes (so requestLen is realistic). */
    private static function wire(string $name, int $qtype = DnsMessage::TYPE_A, int $qclass = DnsMessage::CLASS_IN, bool $edns = false): string
    {
        $arcount = $edns ? "\x00\x01" : "\x00\x00";
        $w = "\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00" . $arcount;
        $w .= DnsMessage::encodeName($name)
            . \chr(($qtype >> 8) & 0xFF) . \chr($qtype & 0xFF)
            . \chr(($qclass >> 8) & 0xFF) . \chr($qclass & 0xFF);
        if ($edns) {
            $w .= "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"; // OPT, 4096
        }

        return $w;
    }

    private function query(string $name, int $qtype = DnsMessage::TYPE_A, int $qclass = DnsMessage::CLASS_IN, bool $edns = false): DnsQuery
    {
        return DnsMessage::decodeQuery(self::wire($name, $qtype, $qclass, $edns));
    }

    /**
     * THE decisive invariant: over UDP, reply bytes never exceed request bytes — for EVERY vector.
     */
    public function test_udp_reply_never_exceeds_request_for_every_vector(): void
    {
        $vectors = [
            ['isc.org', DnsMessage::TYPE_ANY, DnsMessage::CLASS_IN, true],   // amplification ANY+EDNS
            ['example.com', DnsMessage::TYPE_TXT, DnsMessage::CLASS_IN, false],
            ['', DnsMessage::TYPE_NS, DnsMessage::CLASS_IN, false],          // root-zone
            ['example.com', DnsMessage::TYPE_A, DnsMessage::CLASS_IN, false], // mirror A
            ['version.bind', DnsMessage::TYPE_TXT, DnsMessage::CLASS_CH, false], // CHAOS
            ['corp.internal', DnsMessage::TYPE_AXFR, DnsMessage::CLASS_IN, false], // AXFR over UDP
        ];
        foreach ($vectors as [$name, $type, $class, $edns]) {
            $wire = self::wire($name, $type, $class, $edns);
            $q = DnsMessage::decodeQuery($wire);
            $r = DnsResponder::respond($q, '192.0.2.44', \strlen($wire), DnsResponder::TRANSPORT_UDP, $this->cfg());
            self::assertLessThanOrEqual(
                \strlen($wire),
                \strlen($r['bytes']),
                "amplification: {$name}/{$type} reply must be <= request"
            );
            self::assertFalse($r['reportable'], 'every UDP event is non-reportable (spoofable source)');
        }
    }

    public function test_mirror_over_tcp_packs_peer_ip(): void
    {
        $q = $this->query('target.example');
        $r = DnsResponder::respond($q, '203.0.113.77', 40, DnsResponder::TRANSPORT_TCP, $this->cfg(DnsConfig::MODE_MIRROR));
        self::assertSame('dns_mirror', $r['event']);
        self::assertTrue($r['reportable']);
        self::assertStringContainsString(DnsMessage::rdataA('203.0.113.77'), $r['bytes'], 'answer carries the requester IP');
    }

    public function test_same_a_query_over_udp_is_truncated(): void
    {
        $wire = self::wire('target.example');
        $q = DnsMessage::decodeQuery($wire);
        $r = DnsResponder::respond($q, '203.0.113.77', \strlen($wire), DnsResponder::TRANSPORT_UDP, $this->cfg());
        self::assertSame(0x02, \ord($r['bytes'][2]) & 0x02, 'TC=1 over UDP (retry-to-TCP), not the full mirror answer');
        self::assertLessThanOrEqual(\strlen($wire), \strlen($r['bytes']));
    }

    public function test_honeypot_mode_packs_box_ip_over_tcp(): void
    {
        $q = $this->query('anything.test');
        $r = DnsResponder::respond($q, '1.2.3.4', 40, DnsResponder::TRANSPORT_TCP, $this->cfg(DnsConfig::MODE_HONEYPOT));
        self::assertSame('dns_honeypot', $r['event']);
        self::assertStringContainsString(DnsMessage::rdataA('198.51.100.9'), $r['bytes']);
    }

    public function test_sinkhole_maps_known_pool_to_loopback(): void
    {
        $q = $this->query('pool.supportxmr.com');
        $r = DnsResponder::respond($q, '9.9.9.9', 60, DnsResponder::TRANSPORT_TCP, $this->cfg(DnsConfig::MODE_SINKHOLE));
        self::assertSame('dns_sinkhole', $r['event']);
        self::assertStringContainsString(DnsMessage::rdataA('127.0.0.1'), $r['bytes']);
    }

    public function test_chaos_version_bind_over_tcp(): void
    {
        $q = $this->query('version.bind', DnsMessage::TYPE_TXT, DnsMessage::CLASS_CH);
        $r = DnsResponder::respond($q, '9.9.9.9', 40, DnsResponder::TRANSPORT_TCP, $this->cfg());
        self::assertSame('dns_chaos', $r['event']);
        self::assertStringContainsString('9.18.18', $r['bytes']);
    }

    public function test_axfr_over_tcp_streams_zone_with_canaries(): void
    {
        $q = $this->query('corp.internal', DnsMessage::TYPE_AXFR);
        $r = DnsResponder::respond($q, '9.9.9.9', 40, DnsResponder::TRANSPORT_TCP, $this->cfg());
        self::assertSame('dns_axfr', $r['event']);
        self::assertStringContainsString(DnsMessage::rdataA('10.8.0.1'), $r['bytes'], 'canary A record present');
        // SOA appears twice (bracketing) — a hallmark of a complete AXFR.
        self::assertGreaterThanOrEqual(2, \substr_count($r['bytes'], "\x00\x06\x00\x01"), 'SOA type brackets the zone');
    }

    public function test_axfr_over_udp_is_refused_never_the_zone(): void
    {
        $wire = self::wire('corp.internal', DnsMessage::TYPE_AXFR);
        $q = DnsMessage::decodeQuery($wire);
        $r = DnsResponder::respond($q, '9.9.9.9', \strlen($wire), DnsResponder::TRANSPORT_UDP, $this->cfg());
        self::assertSame('dns_axfr', $r['event']);
        self::assertFalse($r['reportable']);
        self::assertStringNotContainsString(DnsMessage::rdataA('10.8.0.1'), $r['bytes'], 'zone NEVER streamed over UDP');
        self::assertLessThanOrEqual(\strlen($wire), \strlen($r['bytes']));
    }
}

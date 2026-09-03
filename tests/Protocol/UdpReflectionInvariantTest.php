<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol;

use Funnypot\Protocol\Bacnet\BacnetConfig;
use Funnypot\Protocol\Bacnet\BacnetServer;
use Funnypot\Protocol\Bacnet\BacnetSession;
use Funnypot\Protocol\Coap\CoapConfig;
use Funnypot\Protocol\Coap\CoapServer;
use Funnypot\Protocol\Coap\CoapSession;
use Funnypot\Protocol\Ipmi\IpmiConfig;
use Funnypot\Protocol\Ipmi\IpmiServer;
use Funnypot\Protocol\Ipmi\IpmiSession;
use Funnypot\Protocol\Ntp\NtpConfig;
use Funnypot\Protocol\Ntp\NtpServer;
use Funnypot\Protocol\Ntp\NtpSession;
use Funnypot\Protocol\Snmp\SnmpConfig;
use Funnypot\Protocol\Snmp\SnmpServer;
use Funnypot\Protocol\Snmp\SnmpSession;
use Funnypot\Protocol\Stun\StunConfig;
use Funnypot\Protocol\Stun\StunServer;
use Funnypot\Protocol\Stun\StunSession;
use Funnypot\Tests\Protocol\Bacnet\BacnetTestFrames;
use Funnypot\Tests\Protocol\Coap\CoapTestFrames;
use Funnypot\Tests\Protocol\Ipmi\IpmiTestFrames;
use Funnypot\Tests\Protocol\Ntp\NtpTestFrames;
use Funnypot\Tests\Protocol\Snmp\SnmpTestFrames;
use Funnypot\Tests\Protocol\Stun\StunTestFrames;
use PHPUnit\Framework\TestCase;

/**
 * FP-0248 §4a — the reflection-safety invariant, driven per-listener exactly like each server's own
 * handshake tests (`$session->inbuf = $frame; $server->processInbound($session);`): for every one of
 * NTP/SNMP/STUN/CoAP/BACnet/IPMI, `strlen($session->outbuf) <= strlen($frame)` (amp <= 1), including
 * malformed/truncated/empty-reply cases — plus the shared UdpResponseBucket trait's depleted-seed
 * admission and its LRU-eviction-proofing, exercised once (the trait is identical across all 7 UDP
 * listeners; SIP's variant of these same properties is covered by SipEgressBudgetTest and the
 * SipTelemetryTest::test_f4_udp_response_bucket_drains_after_burst regression).
 */
final class UdpReflectionInvariantTest extends TestCase
{
    use BacnetTestFrames;
    use CoapTestFrames;
    use IpmiTestFrames;
    use NtpTestFrames;
    use SnmpTestFrames;
    use StunTestFrames;

    private const OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0';

    // ---- §4a: test_response_never_exceeds_request --------------------------------------------

    /**
     * One row per server names the offending listener on a regression. Each row is
     * [label, server-factory, session-factory, list<frame>] — frames span a normal request, a
     * malformed/truncated one, and (where the protocol has one) the reflection-abuse vector that must
     * draw NO reply at all (still amp<=1, vacuously).
     */
    public static function serverFrameProvider(): array
    {
        $cases = [];

        $cases['NTP'] = [
            static fn (): NtpServer => new NtpServer(new NtpConfig(), static function (array $e): void {
            }),
            static fn (): NtpSession => new NtpSession('192.0.2.10', 43210, 1),
            [
                self::clientRequest(4, 0xE4000000, 0x12340000, 6),
                self::clientRequest(4, 0, 0), // zero timestamps -> seeded-base fallback path
                "\x00", // 1-byte garbage: below NTP_PACKET_SIZE
                self::monlistRequest(42), // mode 7 monlist: must never be answered
                self::controlRequest(2),  // mode 6 control: must never be answered
                str_repeat("\x00", 48),   // all-zero but full-length mode-0 packet
            ],
        ];

        $cases['SNMP'] = [
            static fn (): SnmpServer => new SnmpServer(new SnmpConfig(), static function (array $e): void {
            }),
            static fn (): SnmpSession => new SnmpSession('192.0.2.10', 43210, 1),
            [
                self::getReq(1, 'public', 0x01020304, [self::OID_SYS_DESCR]),
                self::getNextReq(1, 'public', 5, [self::OID_SYS_DESCR]),
                self::getBulkReq(1, 'public', 6, 0, 50, [self::OID_SYS_DESCR]), // GETBULK: repetition must never be honored
                self::setReq(1, 'private', 7, [self::OID_SYS_DESCR]),
                "\x30\x03\x02\x01", // truncated BER
                '',
            ],
        ];

        $cases['STUN'] = [
            static fn (): StunServer => new StunServer(new StunConfig(), static function (array $e): void {
            }),
            static fn (): StunSession => new StunSession('192.0.2.10', 44444, 1),
            [
                self::bindingRequest(self::txid()),
                self::bindingRequest(self::txid(), self::softwareAttr('probe-tool/2')),
                self::bindingRequest(self::txid(), self::softwareAttr(str_repeat('X', 500))), // oversize SOFTWARE echo attempt
                "\x00\x01\x00\x00", // truncated header (no magic/txid)
            ],
        ];

        $cases['CoAP'] = [
            static fn (): CoapServer => new CoapServer(new CoapConfig(), static function (array $e): void {
            }),
            static fn (): CoapSession => new CoapSession('192.0.2.50', 5683, 1),
            [
                self::getMessage(self::T_CON, 1, "\x01", '/.well-known/core'),
                self::getMessage(self::T_NON, 2, "\x02", '/sensors/temp'),
                self::postMessage(self::T_CON, 3, "\x03", '/actuators/relay', 'on'),
                "\x40\x01\x00\x04", // truncated 4-byte header only
                '',
            ],
        ];

        $cases['BACnet'] = [
            static fn (): BacnetServer => new BacnetServer(new BacnetConfig(), static function (array $e): void {
            }),
            static fn (): BacnetSession => new BacnetSession('192.0.2.50', 47808, 1),
            [
                self::datagramWhoIs(),
                self::datagramWhoIs(0, 4194303),
                self::datagramReadProperty(1, 8, 260001, 77),
                self::datagramReadProperty(2, 8, 260001, 77, null, true), // routed envelope
                "\x81\x0a\x00\x04", // BVLC header claiming 4 bytes total, no NPDU
            ],
        ];

        $cases['IPMI'] = [
            static fn (): IpmiServer => new IpmiServer(new IpmiConfig(), static function (array $e): void {
            }),
            static fn (): IpmiSession => new IpmiSession('192.0.2.10', 40123, 1),
            [
                self::getChannelAuthCapDatagram(),
                self::getSessionChallengeDatagram('admin'),
                self::openSessionDatagram(),
                self::rakp1Datagram('admin'),
                "\x06\x00\xff\x07", // truncated RMCP header only
            ],
        ];

        return $cases;
    }

    /**
     * @dataProvider serverFrameProvider
     */
    public function test_response_never_exceeds_request(callable $serverFactory, callable $sessionFactory, array $frames): void
    {
        foreach ($frames as $i => $frame) {
            $server = $serverFactory();
            $session = $sessionFactory();
            $session->inbuf = $frame;
            $server->processInbound($session);

            self::assertLessThanOrEqual(
                strlen($frame),
                strlen($session->outbuf),
                "amp<=1 violated on frame #{$i} (" . strlen($frame) . ' in / ' . strlen($session->outbuf) . ' out)'
            );
        }
    }

    // ---- §4a: the shared UdpResponseBucket trait, exercised via one representative server -----

    /**
     * udpResponseAllowed($ip) grants exactly the first TWO immediate calls (the depleted UDP_RESP_SEED
     * seed — enough for SIP's 100+180 double-send elsewhere), refuses the third. NTP stands in for all
     * 7 composing classes: the trait method is identical wherever it is used.
     */
    public function test_new_source_admitted_with_depleted_bucket(): void
    {
        $server = new NtpServer(new NtpConfig(), static function (array $e): void {
        });
        $allow = new \ReflectionMethod($server, 'udpResponseAllowed');
        $allow->setAccessible(true);

        self::assertTrue($allow->invoke($server, '203.0.113.9'), 'first immediate call must be granted');
        self::assertTrue($allow->invoke($server, '203.0.113.9'), 'second immediate call must be granted (seed=2.0)');
        self::assertFalse($allow->invoke($server, '203.0.113.9'), 'third immediate call must be refused, never a 20-burst');
    }

    /**
     * The spoofed-source-rotation attack the fix closes: drain a "victim" IP's bucket, churn
     * UDP_BUCKET_MAX_IPS distinct fresh IPs to force the victim's eviction (least-recently-refilled),
     * then re-admit the victim. Before FP-0248 this handed back a fresh 20-token burst on every such
     * cycle; now it buys at most the depleted seed (2 packets) per re-admission, never more.
     */
    public function test_lru_cycling_cannot_restore_burst(): void
    {
        $server = new NtpServer(new NtpConfig(), static function (array $e): void {
        });
        $allow = new \ReflectionMethod($server, 'udpResponseAllowed');
        $allow->setAccessible(true);
        $maxIps = (int) (new \ReflectionClassConstant(NtpServer::class, 'UDP_BUCKET_MAX_IPS'))->getValue();

        $victim = '198.51.100.7';
        // Drain the victim's bucket completely (2 grants).
        self::assertTrue($allow->invoke($server, $victim));
        self::assertTrue($allow->invoke($server, $victim));
        self::assertFalse($allow->invoke($server, $victim), 'victim bucket must be depleted before the churn');

        // Churn exactly UDP_BUCKET_MAX_IPS distinct fresh sources so the victim (least-recently-
        // refilled) is evicted from the bounded LRU map.
        for ($i = 0; $i < $maxIps; $i++) {
            $allow->invoke($server, sprintf('10.%d.%d.%d', intdiv($i, 65536) % 256, intdiv($i, 256) % 256, $i % 256));
        }

        // Re-admission after eviction: at most TWO allowed replies (the depleted seed), never the old
        // 20-token burst — this is the whole point of the fix.
        self::assertTrue($allow->invoke($server, $victim), 're-admitted victim gets its first depleted-bucket packet');
        self::assertTrue($allow->invoke($server, $victim), 're-admitted victim gets its second depleted-bucket packet (seed=2.0)');
        self::assertFalse($allow->invoke($server, $victim), 're-admission must NOT restore a 20-token burst');
    }
}

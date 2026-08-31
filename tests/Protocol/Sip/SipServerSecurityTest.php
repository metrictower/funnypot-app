<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\App\ThreatIntel\OperatorBlocklist;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use PHPUnit\Framework\TestCase;

final class SipServerSecurityTest extends TestCase
{
    public function test_b1_anti_reflection_pins_rtp_ip_to_udp_source(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $sdp = "v=0\r\n"
            . "c=IN IP4 198.51.100.99\r\n" // Target victim IP in SDP
            . "m=audio 4000 RTP/AVP 0 101\r\n";

        $raw = "INVITE sip:0014155550199@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-reflect\r\n"
            . "From: <sip:attacker@203.0.113.5>;tag=from1\r\n"
            . "To: <sip:0014155550199@target>\r\n"
            . "Call-ID: reflect-call-1\r\n"
            . "CSeq: 1 INVITE\r\n"
            . "Content-Type: application/sdp\r\n"
            . "Content-Length: " . strlen($sdp) . "\r\n\r\n"
            . $sdp;

        $msg = SipMessage::parse($raw);
        $this->assertNotNull($msg);

        // Sender UDP socket is 203.0.113.5:5060
        $server->dispatchMessage($msg, '203.0.113.5', 5060, 'udp');

        $this->assertNotEmpty($logged);
        $callLog = $logged[0];
        $this->assertSame('call', $callLog['event']);
        // Verify path shows the locked destination IP (203.0.113.5), NOT 198.51.100.99
        $this->assertStringContainsString('rtp: 203.0.113.5:4000', $callLog['path']);
        $this->assertStringNotContainsString('198.51.100.99', $callLog['path']);
    }

    public function test_b1_concurrency_and_per_ip_ceilings(): void
    {
        $logged = [];
        $cfg = new SipConfig(maxActiveCalls: 2, perIpCalls: 1, rtpPort: 0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // Helper to craft INVITE
        $makeInvite = static function (string $id, string $fromIp): SipMessage {
            $raw = "INVITE sip:100@target SIP/2.0\r\n"
                . "Via: SIP/2.0/UDP {$fromIp}:5060;branch=z9hG4bK-{$id}\r\n"
                . "From: <sip:caller@{$fromIp}>;tag=tag-{$id}\r\n"
                . "To: <sip:100@target>\r\n"
                . "Call-ID: call-{$id}\r\n"
                . "CSeq: 1 INVITE\r\n"
                . "Content-Length: 0\r\n\r\n";
            return SipMessage::parse($raw);
        };

        // Call 1 from IP 10.0.0.1: should connect
        $server->dispatchMessage($makeInvite('1', '10.0.0.1'), '10.0.0.1', 5060, 'udp');
        $this->assertSame(1, $server->getActiveSessionCount());
        $this->assertSame('call', end($logged)['event']);

        // Call 2 from SAME IP 10.0.0.1: should be rejected (per-IP cap = 1)
        $server->dispatchMessage($makeInvite('2', '10.0.0.1'), '10.0.0.1', 5060, 'udp');
        $this->assertSame(1, $server->getActiveSessionCount());
        $this->assertSame('call_rejected', end($logged)['event']);

        // Call 3 from NEW IP 10.0.0.2: should connect (active=2, reaches global cap)
        $server->dispatchMessage($makeInvite('3', '10.0.0.2'), '10.0.0.2', 5060, 'udp');
        $this->assertSame(2, $server->getActiveSessionCount());
        $this->assertSame('call', end($logged)['event']);

        // Call 4 from NEW IP 10.0.0.3: should be rejected (global cap = 2 reached)
        $server->dispatchMessage($makeInvite('4', '10.0.0.3'), '10.0.0.3', 5060, 'udp');
        $this->assertSame(2, $server->getActiveSessionCount());
        $this->assertSame('call_rejected', end($logged)['event']);
    }

    /** @return callable(string,string):SipMessage */
    private function inviteMaker(): callable
    {
        return static function (string $id, string $fromIp): SipMessage {
            $raw = "INVITE sip:100@target SIP/2.0\r\n"
                . "Via: SIP/2.0/UDP {$fromIp}:5060;branch=z9hG4bK-{$id}\r\n"
                . "From: <sip:caller@{$fromIp}>;tag=tag-{$id}\r\n"
                . "To: <sip:100@target>\r\n"
                . "Call-ID: call-{$id}\r\n"
                . "CSeq: 1 INVITE\r\n"
                . "Content-Length: 0\r\n\r\n";

            return SipMessage::parse($raw);
        };
    }

    public function test_flood_throttle_drops_and_rolls_up_after_the_burst(): void
    {
        $logged = [];
        // High concurrency ceilings so the ONLY limiter under test is the call-admission throttle.
        // burst 5, no refill during the test -> deterministic: first 5 admitted, the rest dropped.
        $cfg = new SipConfig(rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000, callBurst: 5.0, callRatePerSec: 0.0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $makeInvite = $this->inviteMaker();

        for ($i = 1; $i <= 8; $i++) {
            $server->dispatchMessage($makeInvite("flood-{$i}", '203.0.113.9'), '203.0.113.9', 5060, 'udp');
        }

        $calls = array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call');
        $floods = array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call_flood');

        self::assertCount(5, $calls, 'exactly the first burst (5) of INVITEs are admitted + logged as calls');
        self::assertNotEmpty($floods, 'the flood beyond the burst emits a rollup event');
        // Rollup is collapsed, not one-per-drop: 3 drops within the window produce a single rollup row.
        self::assertLessThanOrEqual(1, count($floods), 'drops within the window collapse to one rollup');
        $flood = array_values($floods)[0];
        self::assertFalse($flood['reportable'], 'a throttled flood is never reportable (spoofable pre-ACK source)');
        self::assertStringContainsString('203.0.113.9', (string) $flood['path']);
        self::assertSame(5, $server->getActiveSessionCount(), 'only the admitted 5 became sessions');
    }

    public function test_flood_throttle_auto_recovers_after_the_source_slows(): void
    {
        // burst 1, fast refill (100/s -> a token every 10ms). Drain, then a short pause refills a token
        // so the source is admitted again — proving the throttle is adaptive, not a permanent block.
        $logged = [];
        $cfg = new SipConfig(rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000, callBurst: 1.0, callRatePerSec: 100.0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $makeInvite = $this->inviteMaker();

        $server->dispatchMessage($makeInvite('r-1', '198.51.100.7'), '198.51.100.7', 5060, 'udp'); // admit (drains)
        $server->dispatchMessage($makeInvite('r-2', '198.51.100.7'), '198.51.100.7', 5060, 'udp'); // drop
        self::assertSame('call', $logged[0]['event'] ?? '');
        self::assertSame('call_flood', end($logged)['event'] ?? '', 'second call drained the bucket and was dropped');

        usleep(40000); // 40ms -> ~4 tokens refilled at 100/s

        $server->dispatchMessage($makeInvite('r-3', '198.51.100.7'), '198.51.100.7', 5060, 'udp'); // admit again
        self::assertSame('call', end($logged)['event'] ?? '', 'the source is re-admitted once its bucket refills');
    }

    public function test_call_ceiling_flips_a_slow_relentless_source_to_strict(): void
    {
        // The rate bucket only catches FAST floods; a slow dialer under the refill is never dropped by it
        // yet buries the log in per-call rows. The cumulative ceiling catches it: disable the rate bucket
        // (huge burst) so the ONLY limiter is callCeiling=3. First 3 calls answered + logged, the rest
        // dropped strict and collapsed to a rollup.
        $logged = [];
        $cfg = new SipConfig(
            rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000,
            callBurst: 100000.0, callRatePerSec: 0.0, callCeiling: 3
        );
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $makeInvite = $this->inviteMaker();

        for ($i = 1; $i <= 8; $i++) {
            $server->dispatchMessage($makeInvite("slow-{$i}", '141.98.252.187'), '141.98.252.187', 5060, 'udp');
        }

        $calls = array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call');
        $floods = array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call_flood');
        self::assertCount(3, $calls, 'exactly the ceiling (3) of calls are answered + logged');
        self::assertNotEmpty($floods, 'calls beyond the ceiling collapse to the flood rollup');
        self::assertLessThanOrEqual(1, count($floods), 'strict drops within the window collapse to one rollup');
        self::assertSame(3, $server->getActiveSessionCount(), 'only the answered 3 became sessions');
    }

    public function test_call_ceiling_auto_recovers_after_the_source_goes_quiet(): void
    {
        // A strict source that stays silent past callCeilingIdleReset is forgiven and re-characterized.
        $logged = [];
        $cfg = new SipConfig(
            rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000,
            callBurst: 100000.0, callRatePerSec: 0.0, callCeiling: 2, callCeilingIdleReset: 300.0
        );
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $makeInvite = $this->inviteMaker();

        for ($i = 1; $i <= 5; $i++) {
            $server->dispatchMessage($makeInvite("q-{$i}", '141.98.252.187'), '141.98.252.187', 5060, 'udp');
        }
        self::assertSame('call_flood', end($logged)['event'] ?? '', 'source is strict after the ceiling');

        // Age its ceiling state past the idle-reset window (simulate the source going quiet).
        $ref = new \ReflectionProperty($server, 'ceilingState');
        $ref->setAccessible(true);
        $state = $ref->getValue($server);
        $state['141.98.252.187']['last'] = microtime(true) - 400.0; // > 300s idle
        $ref->setValue($server, $state);

        $server->dispatchMessage($makeInvite('q-after', '141.98.252.187'), '141.98.252.187', 5060, 'udp');
        self::assertSame('call', end($logged)['event'] ?? '', 'a source quiet past the reset window is re-admitted');
    }

    public function test_call_ceiling_is_disablable_and_per_source(): void
    {
        // callCeiling 0 disables it: a flood of calls from one source is all admitted (rate bucket off too).
        $logged = [];
        $cfg = new SipConfig(
            rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000,
            callBurst: 0.0, callCeiling: 0
        );
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $makeInvite = $this->inviteMaker();
        for ($i = 1; $i <= 30; $i++) {
            $server->dispatchMessage($makeInvite("d-{$i}", '10.6.6.6'), '10.6.6.6', 5060, 'udp');
        }
        $calls = array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call');
        self::assertCount(30, $calls, 'ceiling disabled -> all admitted');

        // A second source is unaffected by the first's ceiling trip (per-apparent-source keying).
        $logged2 = [];
        $cfg2 = new SipConfig(
            rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000,
            callBurst: 100000.0, callRatePerSec: 0.0, callCeiling: 2
        );
        $server2 = new SipServer($cfg2, static function (array $e) use (&$logged2): void {
            $logged2[] = $e;
        });
        for ($i = 1; $i <= 5; $i++) {
            $server2->dispatchMessage($makeInvite("f-{$i}", '10.5.5.5'), '10.5.5.5', 5060, 'udp'); // trips strict
        }
        $server2->dispatchMessage($makeInvite('other', '10.4.4.4'), '10.4.4.4', 5060, 'udp'); // fresh source
        self::assertSame('call', end($logged2)['event'] ?? '', 'a different source is not affected by the flooder');
    }

    public function test_flood_throttle_is_per_source_and_disablable(): void
    {
        // A second source is unaffected by the first's flood (per-apparent-source keying).
        $logged = [];
        $cfg = new SipConfig(rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000, callBurst: 3.0, callRatePerSec: 0.0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $makeInvite = $this->inviteMaker();

        for ($i = 1; $i <= 6; $i++) {
            $server->dispatchMessage($makeInvite("a-{$i}", '10.9.9.9'), '10.9.9.9', 5060, 'udp'); // floods
        }
        $server->dispatchMessage($makeInvite('b-1', '10.8.8.8'), '10.8.8.8', 5060, 'udp'); // fresh source
        self::assertSame('call', end($logged)['event'], 'a different source is not throttled by the flooder');

        // callBurst <= 0 disables the throttle entirely: every request is admitted.
        $logged2 = [];
        $cfgOff = new SipConfig(rtpPort: 0, maxActiveCalls: 1000, perIpCalls: 1000, callBurst: 0.0);
        $serverOff = new SipServer($cfgOff, static function (array $e) use (&$logged2): void {
            $logged2[] = $e;
        });
        for ($i = 1; $i <= 20; $i++) {
            $serverOff->dispatchMessage($makeInvite("off-{$i}", '10.7.7.7'), '10.7.7.7', 5060, 'udp');
        }
        $calls = array_filter($logged2, static fn (array $e): bool => ($e['event'] ?? '') === 'call');
        $floods = array_filter($logged2, static fn (array $e): bool => ($e['event'] ?? '') === 'call_flood');
        self::assertCount(20, $calls, 'throttle disabled -> all 20 admitted');
        self::assertEmpty($floods, 'throttle disabled -> no flood rollups');
    }

    public function test_operator_block_silently_drops_a_blocked_source(): void
    {
        $dbFile = sys_get_temp_dir() . '/fpsipblk_' . bin2hex(random_bytes(6)) . '.sqlite';
        $block = new OperatorBlocklist($dbFile, 0.0);
        $block->add('203.0.113.66', 'sip flooder');

        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        }, null, null, null, $block);
        $makeInvite = $this->inviteMaker();

        // A blocked source produces ZERO events — no session, no log, no response (silent drop).
        $server->dispatchMessage($makeInvite('blk', '203.0.113.66'), '203.0.113.66', 5060, 'udp');
        self::assertSame([], $logged, 'a blocked source must be silently dropped');
        self::assertSame(0, $server->getActiveSessionCount(), 'no session is allocated for a blocked source');

        // A different, unblocked source is served normally.
        $server->dispatchMessage($makeInvite('ok', '198.51.100.5'), '198.51.100.5', 5060, 'udp');
        self::assertSame('call', end($logged)['event'] ?? '', 'an unblocked source still connects');

        foreach (['', '-wal', '-shm'] as $s) {
            @unlink($dbFile . $s);
        }
    }

    public function test_b2_anti_spoofing_abuse_reporting_suppression(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // 1. Bare UDP OPTIONS probe -> reportable MUST be false (spoofable)
        $optUdp = SipMessage::parse("OPTIONS sip:target SIP/2.0\r\nCall-ID: c1\r\nCSeq: 1 OPTIONS\r\n\r\n");
        $server->dispatchMessage($optUdp, '1.2.3.4', 5060, 'udp');
        $this->assertFalse(end($logged)['reportable'], 'Bare UDP OPTIONS must not be reportable');

        // 2. TCP OPTIONS probe -> reportable MUST be true (SYN-ACK proved round-trip)
        $optTcp = SipMessage::parse("OPTIONS sip:target SIP/2.0\r\nCall-ID: c2\r\nCSeq: 1 OPTIONS\r\n\r\n");
        $server->dispatchMessage($optTcp, '1.2.3.4', 5060, 'tcp');
        $this->assertTrue(end($logged)['reportable'], 'TCP OPTIONS must be reportable');

        // 3. First-leg UDP REGISTER (no digest) -> reportable MUST be false
        $reg1 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: c3\r\nCSeq: 1 REGISTER\r\n\r\n");
        $server->dispatchMessage($reg1, '1.2.3.4', 5060, 'udp');
        $this->assertFalse(end($logged)['reportable'], 'First-leg UDP REGISTER must not be reportable');

        // 4. Second-leg UDP REGISTER with Digest response -> reportable MUST be true when nonce matches
        $refProp = new \ReflectionProperty($server, 'activeNonces');
        $refProp->setAccessible(true);
        $nonces = $refProp->getValue($server);
        $issuedNonce = array_key_last($nonces);

        $reg2 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: c4\r\nCSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"101\", realm=\"asterisk\", nonce=\"{$issuedNonce}\", uri=\"sip:target\", response=\"resp1\"\r\n\r\n");
        $server->dispatchMessage($reg2, '1.2.3.4', 5060, 'udp');
        $this->assertTrue(end($logged)['reportable'], 'Second-leg authenticated REGISTER with issued nonce must be reportable');

        // 5. INVITE followed by a valid ACK (echoing our To-tag) -> ACK event must be reportable
        $inv = SipMessage::parse("INVITE sip:101@target SIP/2.0\r\nCall-ID: call-ack\r\nCSeq: 1 INVITE\r\n\r\n");
        $server->dispatchMessage($inv, '1.2.3.4', 5060, 'udp');

        $toTag = $server->dialogToTag('call-ack', '1.2.3.4');
        $ack = SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: call-ack\r\nTo: <sip:101@target>;tag={$toTag}\r\nCSeq: 1 ACK\r\n\r\n");
        $server->dispatchMessage($ack, '1.2.3.4', 5060, 'udp');
        $this->assertTrue(end($logged)['reportable'], 'ACK confirming two-way call setup must be reportable');
    }

    /**
     * FP-0247 anti-spoof (re-review blocking): a REGISTER nonce is bound to the source IP it was
     * issued to. An attacker at IP-A harvests a nonce from a real 401, then sends ONE spoofed UDP
     * REGISTER with source = victim IP-B carrying that nonce — that must NOT validate the round-trip
     * and must report reportable=false. A nonce used from the SAME UDP source still reports, and is
     * one-shot (a captured nonce cannot be replayed).
     */
    public function test_register_nonce_is_bound_to_issuing_source_ip(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $refProp = new \ReflectionProperty($server, 'activeNonces');
        $refProp->setAccessible(true);

        // IP-A sends a real first-leg REGISTER and is issued a nonce (bound to IP-A).
        $reg1 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: n1\r\nCSeq: 1 REGISTER\r\n\r\n");
        self::assertNotNull($reg1);
        $server->dispatchMessage($reg1, '203.0.113.10', 5060, 'udp');   // IP-A
        $nonceA = (string) array_key_last($refProp->getValue($server));
        self::assertNotSame('', $nonceA, 'a 401 challenge must issue a nonce');

        // Attacker replays that nonce in ONE spoofed UDP REGISTER whose source is the victim (IP-B).
        $spoof = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: n2\r\nCSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"101\", realm=\"asterisk\", nonce=\"{$nonceA}\", uri=\"sip:target\", response=\"resp\"\r\n\r\n");
        self::assertNotNull($spoof);
        $server->dispatchMessage($spoof, '198.51.100.23', 5060, 'udp');   // spoofed source = victim
        self::assertFalse(end($logged)['reportable'], 'a nonce issued to IP-A must not validate a spoofed REGISTER from IP-B');

        // Positive control: a fresh nonce issued to IP-C, replayed by IP-C itself over UDP, still reports.
        $reg3 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: n3\r\nCSeq: 1 REGISTER\r\n\r\n");
        self::assertNotNull($reg3);
        $server->dispatchMessage($reg3, '203.0.113.44', 5060, 'udp');   // IP-C
        $nonceC = (string) array_key_last($refProp->getValue($server));
        self::assertNotSame('', $nonceC);
        self::assertNotSame($nonceA, $nonceC, 'each challenge issues a distinct nonce');

        $reg4 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: n4\r\nCSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"101\", realm=\"asterisk\", nonce=\"{$nonceC}\", uri=\"sip:target\", response=\"resp\"\r\n\r\n");
        self::assertNotNull($reg4);
        $server->dispatchMessage($reg4, '203.0.113.44', 5060, 'udp');   // same source IP-C
        self::assertTrue(end($logged)['reportable'], 'a nonce used from the same UDP source it was issued to still reports');

        // One-shot: the nonce is consumed on first use, so a replay (even from IP-C) is no longer valid.
        $reg5 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: n5\r\nCSeq: 3 REGISTER\r\n"
            . "Authorization: Digest username=\"101\", realm=\"asterisk\", nonce=\"{$nonceC}\", uri=\"sip:target\", response=\"resp\"\r\n\r\n");
        self::assertNotNull($reg5);
        $server->dispatchMessage($reg5, '203.0.113.44', 5060, 'udp');
        self::assertFalse(end($logged)['reportable'], 'a consumed one-shot nonce cannot be replayed');
    }

    public function test_no_rtp_reflection_without_return_routable_ack(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(recordCalls: true, rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // A spoofed INVITE (attacker sets source = victim). It must NOT stream RTP: streaming waits
        // for an ACK that echoes our To-tag, which a spoofer never sees.
        $inv = SipMessage::parse(
            "INVITE sip:101@target SIP/2.0\r\nCall-ID: reflect-1\r\nCSeq: 1 INVITE\r\n"
            . "Content-Type: application/sdp\r\nContent-Length: 40\r\n\r\n"
            . "v=0\r\nm=audio 53 RTP/AVP 0\r\n"
        );
        $server->dispatchMessage($inv, '198.51.100.9', 5060, 'udp');
        $server->tickRtpStreams();
        $this->assertSame('', $this->recordedUlawFor($server, 'reflect-1', '198.51.100.9'), 'no RTP before a valid ACK');

        // A forged ACK with the wrong tag is also rejected.
        $badAck = SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: reflect-1\r\nTo: <sip:101@target>;tag=wrong\r\nCSeq: 1 ACK\r\n\r\n");
        $server->dispatchMessage($badAck, '198.51.100.9', 5060, 'udp');
        $server->tickRtpStreams();
        $this->assertSame('', $this->recordedUlawFor($server, 'reflect-1', '198.51.100.9'), 'forged-tag ACK must not start streaming');

        // The real caller's ACK (correct tag) does start streaming.
        $tag = $server->dialogToTag('reflect-1', '198.51.100.9');
        $goodAck = SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: reflect-1\r\nTo: <sip:101@target>;tag={$tag}\r\nCSeq: 1 ACK\r\n\r\n");
        $server->dispatchMessage($goodAck, '198.51.100.9', 5060, 'udp');
        usleep(25000);
        $server->tickRtpStreams();
        $this->assertNotSame('', $this->recordedUlawFor($server, 'reflect-1', '198.51.100.9'), 'valid ACK starts streaming');
    }

    /**
     * FP-0247 anti-spoof (fable #1): a lone forged INFO carrying a DTMF body is one spoofable UDP
     * datagram with no session behind it. captureInfoDtmf() must NOT mark it reportable — otherwise a
     * single forged packet would get its spoofed source blocklisted.
     */
    public function test_bare_info_dtmf_over_udp_is_never_reportable(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $info = SipMessage::parse(
            "INFO sip:101@target SIP/2.0\r\nCall-ID: lone-info\r\nCSeq: 1 INFO\r\n"
            . "Content-Type: application/dtmf-relay\r\nContent-Length: 10\r\n\r\n"
            . "Signal=5\r\n"
        );
        self::assertNotNull($info);
        $server->dispatchMessage($info, '203.0.113.77', 5060, 'udp');

        $dtmf = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'dtmf'));
        self::assertNotEmpty($dtmf, 'the bare INFO must still be logged as intel');
        self::assertFalse($dtmf[0]['reportable'], 'a lone spoofable UDP INFO/DTMF must never be reportable');

        // The gate drops any reportable=false event, so nothing reaches the abuse queue.
        foreach ($logged as $e) {
            self::assertFalse($e['reportable'] ?? false, 'no event from a lone UDP INFO may be reportable');
        }
    }

    /** A bare INFO/DTMF over TCP IS reportable — the SYN-ACK proved the source is return-routable. */
    public function test_bare_info_dtmf_over_tcp_is_reportable(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $info = SipMessage::parse(
            "INFO sip:101@target SIP/2.0\r\nCall-ID: tcp-info\r\nCSeq: 1 INFO\r\n"
            . "Content-Type: application/dtmf-relay\r\nContent-Length: 10\r\n\r\n"
            . "Signal=5\r\n"
        );
        self::assertNotNull($info);
        $server->dispatchMessage($info, '203.0.113.77', 5060, 'tcp');

        $dtmf = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'dtmf'));
        self::assertNotEmpty($dtmf);
        self::assertTrue($dtmf[0]['reportable'], 'a return-routable TCP INFO/DTMF is reportable');
    }

    /**
     * FP-0247 anti-spoof (fable #2): a session created by a spoofed UDP INVITE that never ACKs is
     * reaped by the setup-stall eviction. Its call_end event must NOT be reportable — the source never
     * passed the ACK To-tag return-routability check, so it may be a spoofed victim.
     */
    public function test_unacked_invite_reaped_by_setup_stall_is_never_reportable(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $inv = SipMessage::parse(
            "INVITE sip:101@target SIP/2.0\r\nCall-ID: stall-1\r\nCSeq: 1 INVITE\r\n"
            . "Content-Type: application/sdp\r\nContent-Length: 30\r\n\r\n"
            . "v=0\r\nm=audio 53 RTP/AVP 0\r\n"
        );
        self::assertNotNull($inv);
        $server->dispatchMessage($inv, '198.51.100.44', 5060, 'udp');

        // Backdate startTime past INVITE_SETUP_TIMEOUT so the next cleanup reaps the never-ACKed call.
        $this->backdateSessions($server, 100.0);
        $this->reapExpired($server);

        $end = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call_end'));
        self::assertNotEmpty($end, 'a reaped setup-stalled call must still emit a call_end for the dashboard');
        self::assertFalse($end[0]['reportable'], 'a never-ACKed reaped call must never be reportable (spoofable source)');
    }

    /**
     * FP-0247 anti-spoof (fable #2): a spoofed BYE tears down a never-streamed session. Its call_end
     * must NOT be reportable.
     */
    public function test_spoofed_bye_ending_unstreamed_call_is_never_reportable(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $inv = SipMessage::parse(
            "INVITE sip:101@target SIP/2.0\r\nCall-ID: bye-1\r\nCSeq: 1 INVITE\r\n"
            . "Content-Type: application/sdp\r\nContent-Length: 30\r\n\r\n"
            . "v=0\r\nm=audio 53 RTP/AVP 0\r\n"
        );
        self::assertNotNull($inv);
        $server->dispatchMessage($inv, '198.51.100.55', 5060, 'udp');

        $bye = SipMessage::parse("BYE sip:101@target SIP/2.0\r\nCall-ID: bye-1\r\nCSeq: 2 BYE\r\n\r\n");
        self::assertNotNull($bye);
        $server->dispatchMessage($bye, '198.51.100.55', 5060, 'udp');

        $end = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call_end'));
        self::assertNotEmpty($end);
        self::assertFalse($end[0]['reportable'], 'a spoofed BYE on a never-streamed call must never be reportable');
    }

    /** A call that completed the ACK handshake IS reportable at end, even after teardown. */
    public function test_streamed_call_end_is_reportable(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $inv = SipMessage::parse("INVITE sip:101@target SIP/2.0\r\nCall-ID: good-1\r\nCSeq: 1 INVITE\r\n\r\n");
        self::assertNotNull($inv);
        $server->dispatchMessage($inv, '198.51.100.66', 5060, 'udp');

        $tag = $server->dialogToTag('good-1', '198.51.100.66');
        $ack = SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: good-1\r\nTo: <sip:101@target>;tag={$tag}\r\nCSeq: 1 ACK\r\n\r\n");
        self::assertNotNull($ack);
        $server->dispatchMessage($ack, '198.51.100.66', 5060, 'udp');

        $bye = SipMessage::parse("BYE sip:101@target SIP/2.0\r\nCall-ID: good-1\r\nCSeq: 2 BYE\r\n\r\n");
        self::assertNotNull($bye);
        $server->dispatchMessage($bye, '198.51.100.66', 5060, 'udp');

        $end = array_values(array_filter($logged, static fn (array $e): bool => ($e['event'] ?? '') === 'call_end'));
        self::assertNotEmpty($end);
        self::assertTrue($end[0]['reportable'], 'a call that passed the ACK handshake is reportable at end');
    }

    /** Backdate every live session's startTime so the setup-stall reaper fires deterministically. */
    private function backdateSessions(SipServer $server, float $secondsAgo): void
    {
        $ref = new \ReflectionProperty($server, 'sessions');
        $ref->setAccessible(true);
        foreach ($ref->getValue($server) as $s) {
            $s->startTime = microtime(true) - $secondsAgo;
        }
    }

    /** Invoke the private setup-stall / idle reaper (normally driven by runOnce()). */
    private function reapExpired(SipServer $server): void
    {
        $m = new \ReflectionMethod($server, 'cleanupExpiredSessions');
        $m->setAccessible(true);
        $m->invoke($server);
    }

    private function recordedUlawFor(SipServer $server, string $callId, string $ip): string
    {
        $ref = new \ReflectionProperty($server, 'sessions');
        $ref->setAccessible(true);
        foreach ($ref->getValue($server) as $s) {
            if ($s->callId === $callId && $s->peerIp === $ip) {
                return $s->recordedUlaw;
            }
        }

        return '';
    }
}

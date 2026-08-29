<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use PHPUnit\Framework\TestCase;

final class SipServerSecurityTest extends TestCase
{
    public function test_b1_anti_reflection_pins_rtp_ip_to_udp_source(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
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
        $cfg = new SipConfig(maxActiveCalls: 2, perIpCalls: 1);
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

    public function test_b2_anti_spoofing_abuse_reporting_suppression(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
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

        // 5. INVITE followed by ACK -> ACK event must be reportable
        $inv = SipMessage::parse("INVITE sip:101@target SIP/2.0\r\nCall-ID: call-ack\r\nCSeq: 1 INVITE\r\n\r\n");
        $server->dispatchMessage($inv, '1.2.3.4', 5060, 'udp');

        $ack = SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: call-ack\r\nCSeq: 1 ACK\r\n\r\n");
        $server->dispatchMessage($ack, '1.2.3.4', 5060, 'udp');
        $this->assertTrue(end($logged)['reportable'], 'ACK confirming two-way call setup must be reportable');
    }
}

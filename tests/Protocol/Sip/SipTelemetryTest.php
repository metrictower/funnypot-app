<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use Funnypot\Protocol\Sip\SipSession;
use PHPUnit\Framework\TestCase;

/**
 * Covers the attacker-attribution + DTMF + anti-reflection-throttle features added to the SIP
 * honeypot. These are all intel/hardening surfaces: nothing here is emitted back to a client.
 */
final class SipTelemetryTest extends TestCase
{
    public function test_user_agent_and_tool_are_attributed_and_logged(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-x\r\n"
            . "Call-ID: ua-1\r\nCSeq: 1 OPTIONS\r\n"
            . "User-Agent: friendly-scanner\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $ev = end($logged);
        $this->assertSame('friendly-scanner', $ev['ua']);
        $this->assertSame('sipvicious', $ev['tool']);
    }

    public function test_transport_tells_flag_spoofable_and_automated_traffic(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // No branch cookie, no rport, no Contact, source port 5060, over UDP.
        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060\r\n"
            . "Call-ID: tells-1\r\nCSeq: 1 OPTIONS\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $tells = end($logged)['tells'];
        $this->assertStringContainsString('udp(spoofable)', $tells);
        $this->assertStringContainsString('pre-rfc3261-branch', $tells);
        $this->assertStringContainsString('no-rport', $tells);
        $this->assertStringContainsString('no-contact', $tells);
        $this->assertStringContainsString('src-port-5060', $tells);
    }

    public function test_tcp_transport_tell_marks_return_routable(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/TCP 9.9.9.9:41232;branch=z9hG4bK-y;rport\r\n"
            . "Contact: <sip:x@9.9.9.9:41232>\r\n"
            . "Call-ID: tells-tcp\r\nCSeq: 1 OPTIONS\r\n"
            . "User-Agent: Zoiper rev.1234\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 41232, 'tcp');

        $ev = end($logged);
        $this->assertStringContainsString('tcp(return-routable)', $ev['tells']);
        $this->assertStringNotContainsString('src-port-5060', $ev['tells']);
        $this->assertSame('zoiper-softphone', $ev['tool']);
    }

    public function test_sdp_telephone_event_payload_type_is_parsed(): void
    {
        $raw = "INVITE sip:1@t SIP/2.0\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\n"
            . "Content-Type: application/sdp\r\nContent-Length: 80\r\n\r\n"
            . "v=0\r\nm=audio 4000 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n";
        $msg = SipMessage::parse($raw);
        $this->assertSame(101, $msg->sdpTelephoneEventPt);
    }

    public function test_rtp_dtmf_decodes_digit_and_dedups_by_timestamp(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $s = new SipSession('dtmf-call', '5.5.5.5', 5060, 'udp');
        $s->dtmfPt = 101;

        $capture = new \ReflectionMethod($server, 'captureRtpDtmf');
        $capture->setAccessible(true);

        // Event 5 = digit '5'. Two packets with the SAME RTP timestamp = one key-press.
        $evt5 = chr(5) . chr(0x0a) . "\x00\x50"; // event, vol byte, duration
        $capture->invoke($server, $s, $evt5, 1000);
        $capture->invoke($server, $s, $evt5, 1000); // repeat of same press: ignored
        // Event 11 = '#', new timestamp = a new press.
        $evtHash = chr(11) . chr(0x8a) . "\x01\x00"; // end bit set
        $capture->invoke($server, $s, $evtHash, 1160);

        $this->assertSame('5#', $s->dtmfDigits);
        $dtmfEvents = array_values(array_filter($logged, static fn ($e): bool => ($e['event'] ?? '') === 'dtmf'));
        $this->assertCount(2, $dtmfEvents);
        $this->assertStringContainsString("'5'", $dtmfEvents[0]['path']);
        $this->assertTrue($dtmfEvents[0]['reportable']);
    }

    public function test_info_dtmf_relay_is_captured(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $body = "Signal=7\r\nDuration=250\r\n";
        $raw = "INFO sip:1@t SIP/2.0\r\nCall-ID: info-1\r\nCSeq: 3 INFO\r\n"
            . "Content-Type: application/dtmf-relay\r\n"
            . "Content-Length: " . strlen($body) . "\r\n\r\n" . $body;
        $server->dispatchMessage(SipMessage::parse($raw), '6.6.6.6', 5060, 'udp');

        $dtmf = array_values(array_filter($logged, static fn ($e): bool => ($e['event'] ?? '') === 'dtmf'));
        $this->assertCount(1, $dtmf);
        $this->assertStringContainsString("'7'", $dtmf[0]['path']);
    }

    public function test_info_bare_dtmf_body_is_captured(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = "INFO sip:1@t SIP/2.0\r\nCall-ID: info-2\r\nCSeq: 3 INFO\r\n"
            . "Content-Type: application/dtmf\r\nContent-Length: 1\r\n\r\n9";
        $server->dispatchMessage(SipMessage::parse($raw), '6.6.6.7', 5060, 'udp');

        $dtmf = array_values(array_filter($logged, static fn ($e): bool => ($e['event'] ?? '') === 'dtmf'));
        $this->assertCount(1, $dtmf);
        $this->assertStringContainsString("'9'", $dtmf[0]['path']);
    }

    public function test_f4_udp_response_bucket_drains_after_burst(): void
    {
        $server = new SipServer(new SipConfig(), null);

        $allow = new \ReflectionMethod($server, 'udpResponseAllowed');
        $allow->setAccessible(true);

        $burst = (new \ReflectionClassConstant(SipServer::class, 'UDP_RESP_BURST'))->getValue();

        $granted = 0;
        for ($i = 0; $i < $burst + 5; $i++) {
            if ($allow->invoke($server, '7.7.7.7')) {
                $granted++;
            }
        }

        // The bucket starts full at the burst size and refills negligibly within a tight loop, so a
        // sustained flood from one source is capped near the burst — never unbounded reflection.
        $this->assertSame((int) $burst, $granted);
    }
}

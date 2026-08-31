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
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
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

    public function test_sippts_is_classified_by_wire_signature_despite_a_changed_user_agent(): void
    {
        // sippts (Pepelux) defaults its UA to 'pplsip' but operators routinely change it. Its shared
        // message builder still stamps a hard RFC-3261 violation: a long lowercase-alnum Via branch with
        // NO z9hG4bK cookie + a bare 32-hex Call-ID (no @host). Classify on that even with a spoofed UA.
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $branch = str_repeat('a', 71);           // sippts: generate_random_string(71,71,'ascii'), no z9hG4bK
        $callId = str_repeat('b', 32);           // sippts: bare 32-hex Call-ID, no @host
        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch={$branch};rport\r\n"
            . "From: <sip:100@target>;tag=deadbeef\r\nTo: <sip:100@target>\r\n"
            . "Call-ID: {$callId}\r\nCSeq: 1 OPTIONS\r\n"
            . "User-Agent: Totally Legit Phone 5.0\r\nContent-Length: 0\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $ev = end($logged);
        $this->assertSame('pplsip-scanner', $ev['tool'], 'sippts must be caught by its wire signature, not just the default UA');
        // A genuine client (RFC-compliant z9hG4bK branch) with the same custom UA stays unclassified.
        $logged2 = [];
        $server2 = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged2): void {
            $logged2[] = $e;
        });
        $ok = "OPTIONS sip:target SIP/2.0\r\nVia: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-real;rport\r\n"
            . "From: <sip:100@target>;tag=deadbeef\r\nTo: <sip:100@target>\r\n"
            . "Call-ID: abc@9.9.9.9\r\nCSeq: 1 OPTIONS\r\nUser-Agent: Totally Legit Phone 5.0\r\n\r\n";
        $server2->dispatchMessage(SipMessage::parse($ok), '9.9.9.9', 5060, 'udp');
        $this->assertSame('other', end($logged2)['tool'], 'an RFC-compliant client is not mislabelled sippts');
    }

    public function test_transport_tells_flag_spoofable_and_automated_traffic(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
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
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
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
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
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
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
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
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
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
        $server = new SipServer(new SipConfig(rtpPort: 0), null);

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

    public function test_tcp_source_ip_comes_from_accept_time_peer_not_a_fabricated_loopback(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // A connected pair stands in for an accepted TCP client; the server reads the request from
        // its end. The real peer is captured at accept, so seed it as handleTcpAccept would.
        [$client, $sock] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
        stream_set_blocking($client, false);
        stream_set_blocking($sock, false);
        $this->seedTcpConn($server, (int) $sock, '203.0.113.7:41000');

        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/TCP 203.0.113.7:41000;branch=z9hG4bK-x\r\n"
            . "Call-ID: tcp-attrib\r\nCSeq: 1 OPTIONS\r\n\r\n";
        fwrite($client, $raw);

        $handle = new \ReflectionMethod($server, 'handleInboundTcp');
        $handle->setAccessible(true);
        $handle->invoke($server, $sock);

        $ev = end($logged);
        $this->assertSame('203.0.113.7', $ev['ip']);
        $this->assertNotSame('127.0.0.1', $ev['ip']);

        fclose($client);
        fclose($sock);
    }

    public function test_tcp_unresolvable_peer_is_not_fabricated_and_not_reportable(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        [$client, $sock] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
        stream_set_blocking($client, false);
        stream_set_blocking($sock, false);
        // Peer resolution failed at accept: empty stored peer must never become a fabricated loopback.
        $this->seedTcpConn($server, (int) $sock, '');

        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/TCP 9.9.9.9:5060;branch=z9hG4bK-x\r\n"
            . "Call-ID: tcp-unknown\r\nCSeq: 1 OPTIONS\r\n\r\n";
        fwrite($client, $raw);

        $handle = new \ReflectionMethod($server, 'handleInboundTcp');
        $handle->setAccessible(true);
        $handle->invoke($server, $sock);

        $ev = end($logged);
        $this->assertNotSame('127.0.0.1', $ev['ip']);
        $this->assertNotSame('127.0.0.1:5060', $ev['ip'] . ':' . $ev['port']);
        $this->assertSame('', $ev['ip']);
        // An OPTIONS probe over TCP is normally reportable; a placeholder source suppresses that.
        $this->assertFalse($ev['reportable']);

        fclose($client);
        fclose($sock);
    }

    public function test_every_sip_event_carries_an_iso8601_timestamp(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $raw = "OPTIONS sip:target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-x\r\n"
            . "Call-ID: ts-1\r\nCSeq: 1 OPTIONS\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw), '9.9.9.9', 5060, 'udp');

        $ev = end($logged);
        $this->assertArrayHasKey('ts', $ev);
        $this->assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/',
            $ev['ts']
        );
    }

    /**
     * Seed the per-connection TCP state handleTcpAccept would set, so handleInboundTcp can be driven
     * directly with a chosen accept-time peer.
     */
    private function seedTcpConn(SipServer $server, int $id, string $peerAddr): void
    {
        foreach (['tcpClients' => null, 'tcpBuffers' => '', 'tcpLastActivity' => microtime(true), 'tcpPeers' => $peerAddr] as $prop => $val) {
            $ref = new \ReflectionProperty($server, $prop);
            $ref->setAccessible(true);
            $map = $ref->getValue($server);
            $map[$id] = $val;
            $ref->setValue($server, $map);
        }
    }
}

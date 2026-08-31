<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use Funnypot\Protocol\Sip\ToneGenerator;
use PHPUnit\Framework\TestCase;

/**
 * Anti-fingerprint + protocol-coverage behaviours: match a real Asterisk closely enough that a
 * single probe can't unmask the honeypot, and capture the intel real scanners/fraudsters generate.
 */
final class SipRealismTest extends TestCase
{
    public function test_responses_carry_server_but_not_user_agent(): void
    {
        $req = SipMessage::parse("OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bK-1\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n");
        $res = $req->buildResponse(200, 'OK');
        $this->assertStringContainsString("Server:", $res);
        $this->assertStringNotContainsString("User-Agent:", $res, 'a response emitting both Server and User-Agent is a stack-fingerprint tell');
    }

    public function test_local_tags_use_the_asterisk_as_hex_fingerprint_shape(): void
    {
        // The dominant field a SIP scanner (sippts/svmap) keys on to fingerprint the box as Asterisk is
        // the local To-tag shape ^as[0-9a-f]{8}$. A differently-shaped tag reads as a non-Asterisk stack
        // and contradicts our 'Asterisk PBX' Server banner, so every response must use this shape.
        self::assertMatchesRegularExpression('/^as[0-9a-f]{8}$/', SipMessage::asteriskTag());
        self::assertNotSame(SipMessage::asteriskTag(), SipMessage::asteriskTag(), 'freshly random per transaction');
        $req = SipMessage::parse("OPTIONS sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bK-o\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n");
        $res = $req->buildOk(SipMessage::asteriskTag(), '<sip:10.0.0.1:5060>', '', [], 'Asterisk PBX 20.5.0');
        self::assertMatchesRegularExpression('/;tag=as[0-9a-f]{8}/', $res, 'the wire To-tag must be the Asterisk as+8hex shape');
    }

    public function test_options_ok_advertises_a_full_pjsip_capability_set(): void
    {
        // The OPTIONS reply is the scanner's first-contact fingerprint: it must read as a complete
        // Asterisk (SDP negotiation + event subscriptions) so the box is marked live and escalated to.
        $req = SipMessage::parse("OPTIONS sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bK-o\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n");
        $res = $req->buildOk('tag-o', '<sip:10.0.0.1:5060>', '', [
            'Accept' => 'application/sdp',
            'Allow-Events' => 'message-summary, presence, dialog, refer, cc',
        ]);
        $this->assertStringContainsString('Allow: INVITE, ACK, CANCEL, OPTIONS, BYE', $res);
        $this->assertStringContainsString('Supported: 100rel, timer, replaces, norefersub', $res);
        $this->assertStringContainsString('Accept: application/sdp', $res);
        $this->assertStringContainsString('Allow-Events: message-summary, presence, dialog, refer, cc', $res);
        // The REGISTER-only 'path' extension must not appear here — advertising it on OPTIONS is a tell.
        $this->assertStringNotContainsString('path', $res);
    }

    public function test_unknown_method_gets_501_not_a_bare_200(): void
    {
        $res = SipMessage::parse("PING sip:x SIP/2.0\r\nCall-ID: c\r\nCSeq: 1 PING\r\n\r\n")->buildNotImplemented();
        $this->assertStringStartsWith('SIP/2.0 501 Not Implemented', $res);

        // And dispatch actually answers 501 + logs the probe.
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $server->dispatchMessage(SipMessage::parse("PING sip:x SIP/2.0\r\nCall-ID: c2\r\nCSeq: 1 PING\r\n\r\n"), '2.2.2.2', 5060, 'udp');
        $this->assertStringContainsString('501', end($logged)['path']);
    }

    public function test_sdp_uses_pjsip_style_origin_and_short_session_name(): void
    {
        $sdp = SipMessage::buildSdp('203.0.113.5', 10000);
        $this->assertStringContainsString("o=- ", $sdp);
        $this->assertStringContainsString("s=Asterisk\r\n", $sdp);
        $this->assertStringNotContainsString('o=root', $sdp);
        $this->assertStringContainsString("c=IN IP4 203.0.113.5", $sdp);
    }

    public function test_sip_message_is_captured_as_intel(): void
    {
        $logged = [];
        $server = new SipServer(new SipConfig(rtpPort: 0), static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $body = 'Your parcel is held: http://evil.example/track';
        $raw = "MESSAGE sip:447700900123@t SIP/2.0\r\nCall-ID: m1\r\nCSeq: 1 MESSAGE\r\n"
            . "From: <sip:spoofed@t>;tag=f1\r\n"
            . "Content-Type: text/plain\r\nContent-Length: " . strlen($body) . "\r\n\r\n" . $body;
        $server->dispatchMessage(SipMessage::parse($raw), '3.3.3.3', 5060, 'udp');

        $ev = end($logged);
        $this->assertSame('message', $ev['event']);
        $this->assertStringContainsString('447700900123', $ev['path']);
        $this->assertStringContainsString('evil.example', $ev['path']);
    }

    public function test_via_rport_is_echoed_with_received(): void
    {
        $server = new SipServer(new SipConfig(rtpPort: 0), null);
        $m = new \ReflectionMethod($server, 'addViaReceived');
        $m->setAccessible(true);

        $raw = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.9.8.7:5060;branch=z9hG4bK-x;rport\r\nCSeq: 1 OPTIONS\r\n\r\n";
        $out = $m->invoke($server, $raw, '198.51.100.9', 41234);
        $this->assertStringContainsString('received=198.51.100.9;rport=41234', $out);

        // No rport requested -> Via left untouched.
        $noRport = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.9.8.7:5060;branch=z9hG4bK-y\r\n\r\n";
        $this->assertSame($noRport, $m->invoke($server, $noRport, '198.51.100.9', 41234));
    }

    public function test_abuseipdb_categorises_sip_as_fraud_voip(): void
    {
        $this->assertSame('8,18', AbuseIpdb::categoriesForProtocol('sip'));
        $this->assertNotSame('14,15', AbuseIpdb::categoriesForProtocol('sip'), 'SIP fraud must not fall to the port-scan default');
    }

    public function test_comfort_noise_is_faint_hiss_not_dead_silence(): void
    {
        $slice = (new ToneGenerator())->getComfortNoiseSlice();
        $this->assertSame(160, strlen($slice));
        $this->assertNotSame(str_repeat(chr(0xff), 160), $slice, 'inter-clip pauses must not be pure mu-law silence');
        // Every sample stays in the lowest mu-law amplitude band: faint line hiss, never an audible tone.
        for ($i = 0, $n = strlen($slice); $i < $n; $i++) {
            $val = ~ord($slice[$i]) & 0xff;
            $this->assertSame(0, ($val >> 4) & 0x07, 'comfort noise must stay at the lowest amplitude');
        }
    }
}

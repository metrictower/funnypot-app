<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\SipMessage;
use PHPUnit\Framework\TestCase;

/**
 * TCP stream framing + best-effort 400 (FP-0189). A stream read can carry a partial message or
 * several pipelined ones; the framer must consume exactly one complete message at a time and never
 * parse a body split across reads as if it were complete.
 */
final class SipTcpFramingTest extends TestCase
{
    private static function inviteWithSdp(string $callId = 'c1'): string
    {
        $sdp = "v=0\r\no=- 1 1 IN IP4 9.9.9.9\r\ns=x\r\nc=IN IP4 9.9.9.9\r\n"
            . "t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        $head = "INVITE sip:100@t SIP/2.0\r\n"
            . "Via: SIP/2.0/TCP 9.9.9.9:5060;branch=z9hG4bK-f\r\n"
            . "From: <sip:a@9.9.9.9>;tag=f\r\nTo: <sip:100@t>\r\n"
            . "Call-ID: {$callId}\r\nCSeq: 1 INVITE\r\n"
            . 'Content-Length: ' . strlen($sdp) . "\r\n\r\n";

        return $head . $sdp;
    }

    public function test_framelength_null_until_headers_complete(): void
    {
        $this->assertNull(SipMessage::frameLength("INVITE sip:x SIP/2.0\r\nVia: a\r\n"));
    }

    public function test_framelength_null_until_full_body_arrives(): void
    {
        $full = self::inviteWithSdp();
        // A body split across reads: everything but the last 20 bytes has arrived.
        $partial = substr($full, 0, strlen($full) - 20);
        $this->assertNull(SipMessage::frameLength($partial), 'must wait for the whole Content-Length body');
        $this->assertSame(strlen($full), SipMessage::frameLength($full));
    }

    public function test_framelength_frames_pipelined_messages_in_one_read(): void
    {
        $a = self::inviteWithSdp('call-a');
        $b = self::inviteWithSdp('call-b');
        $buf = $a . $b;

        $len1 = SipMessage::frameLength($buf);
        $this->assertSame(strlen($a), $len1);
        $remainder = substr($buf, $len1);
        $this->assertSame(strlen($b), SipMessage::frameLength($remainder));
    }

    public function test_full_frame_preserves_the_sdp_audio_port(): void
    {
        // The bug this guards: a truncated body dropped the SDP port and RTP fell back to a default.
        $req = SipMessage::parse(self::inviteWithSdp());
        $this->assertNotNull($req);
        $this->assertSame(40000, $req->sdpAudioPort);
    }

    public function test_build400_echoes_routing_headers(): void
    {
        $raw = "INVALID nonsense\r\n"
            . "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-bad\r\n"
            . "From: <sip:a@9.9.9.9>;tag=f\r\nTo: <sip:x@t>\r\n"
            . "Call-ID: bad-1\r\nCSeq: 7 INVALID\r\n\r\n";
        $res = SipMessage::build400($raw);
        $this->assertNotNull($res);
        $this->assertStringStartsWith('SIP/2.0 400 Bad Request', $res);
        $this->assertStringContainsString('Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bK-bad', $res);
        $this->assertStringContainsString('Call-ID: bad-1', $res);
        $this->assertStringContainsString('CSeq: 7 INVALID', $res);
        $this->assertStringContainsString(';tag=', $res); // a To-tag is added when the request has none
        $this->assertStringContainsString('Content-Length: 0', $res);
    }

    public function test_build400_returns_null_without_routing_headers(): void
    {
        // Ungrammatical garbage with no Via/Call-ID/CSeq is dropped, never answered.
        $this->assertNull(SipMessage::build400("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
    }
}

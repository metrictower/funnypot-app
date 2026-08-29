<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\SipMessage;
use PHPUnit\Framework\TestCase;

final class SipMessageTest extends TestCase
{
    public function test_parse_options_request(): void
    {
        $raw = "OPTIONS sip:100@192.168.1.50:5060 SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 192.168.1.200:5060;branch=z9hG4bK-1234\r\n"
            . "From: <sip:scanner@192.168.1.200>;tag=from123\r\n"
            . "To: <sip:100@192.168.1.50>\r\n"
            . "Call-ID: call-abc-123\r\n"
            . "CSeq: 1 OPTIONS\r\n"
            . "Contact: <sip:scanner@192.168.1.200:5060>\r\n"
            . "Content-Length: 0\r\n\r\n";

        $msg = SipMessage::parse($raw);
        $this->assertNotNull($msg);
        $this->assertTrue($msg->isRequest);
        $this->assertSame('OPTIONS', $msg->method);
        $this->assertSame('sip:100@192.168.1.50:5060', $msg->uri);
        $this->assertSame('call-abc-123', $msg->getCallId());
        $this->assertSame('1 OPTIONS', $msg->getCSeq());
        $this->assertSame('100', $msg->getDialedNumber());
    }

    public function test_parse_compact_headers(): void
    {
        $raw = "INVITE sip:0014155550199@10.0.0.1 SIP/2.0\r\n"
            . "v: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-xyz\r\n"
            . "f: \"Attacker\" <sip:caller@10.0.0.2>;tag=tag1\r\n"
            . "t: <sip:0014155550199@10.0.0.1>\r\n"
            . "i: invite-call-999\r\n"
            . "CSeq: 100 INVITE\r\n"
            . "c: application/sdp\r\n"
            . "l: 12\r\n\r\n"
            . "hello world!";

        $msg = SipMessage::parse($raw);
        $this->assertNotNull($msg);
        $this->assertSame('INVITE', $msg->method);
        $this->assertSame('invite-call-999', $msg->getCallId());
        $this->assertSame('application/sdp', $msg->getHeader('content-type'));
        $this->assertSame('0014155550199', $msg->getDialedNumber());
        $this->assertSame('hello world!', $msg->body);
    }

    public function test_parse_sdp_media_descriptors(): void
    {
        $sdp = "v=0\r\n"
            . "o=user1 53655765 2353687637 IN IP4 172.16.0.5\r\n"
            . "s=-\r\n"
            . "c=IN IP4 172.16.0.5\r\n"
            . "t=0 0\r\n"
            . "m=audio 16402 RTP/AVP 0 8 101\r\n"
            . "a=rtpmap:0 PCMU/8000\r\n";

        $raw = "INVITE sip:200@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 172.16.0.5:5060;branch=z9hG4bK-abc\r\n"
            . "From: <sip:attacker@172.16.0.5>;tag=11\r\n"
            . "To: <sip:200@target>\r\n"
            . "Call-ID: call-sdp-test\r\n"
            . "CSeq: 1 INVITE\r\n"
            . "Content-Type: application/sdp\r\n"
            . "Content-Length: " . strlen($sdp) . "\r\n\r\n"
            . $sdp;

        $msg = SipMessage::parse($raw);
        $this->assertNotNull($msg);
        $this->assertSame('172.16.0.5', $msg->sdpIp);
        $this->assertSame(16402, $msg->sdpAudioPort);
        $this->assertSame([0, 8, 101], $msg->sdpCodecs);
    }

    public function test_digest_auth_parsing(): void
    {
        $raw = "REGISTER sip:pbx.example.com SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-reg\r\n"
            . "From: <sip:101@pbx.example.com>;tag=reg1\r\n"
            . "To: <sip:101@pbx.example.com>\r\n"
            . "Call-ID: reg-call-1\r\n"
            . "CSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"101\", realm=\"asterisk\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"sip:pbx.example.com\", response=\"6629fae49393a05397450978507c4ef1\"\r\n"
            . "Content-Length: 0\r\n\r\n";

        $msg = SipMessage::parse($raw);
        $this->assertNotNull($msg);
        $auth = $msg->getDigestAuth();
        $this->assertSame('101', $auth['username']);
        $this->assertSame('asterisk', $auth['realm']);
        $this->assertSame('dcd98b7102dd2f0e8b11d0f600bfb0c093', $auth['nonce']);
        $this->assertSame('6629fae49393a05397450978507c4ef1', $auth['response']);
    }

    public function test_response_builders(): void
    {
        $raw = "OPTIONS sip:100@target SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 1.1.1.1:5060;branch=branch1\r\n"
            . "From: <sip:client@1.1.1.1>;tag=f1\r\n"
            . "To: <sip:100@target>\r\n"
            . "Call-ID: call-test\r\n"
            . "CSeq: 1 OPTIONS\r\n\r\n";

        $req = SipMessage::parse($raw);
        $this->assertNotNull($req);

        // 100 Trying
        $trying = $req->buildTrying('Asterisk PBX 20.5.0');
        $this->assertStringContainsString('SIP/2.0 100 Trying', $trying);
        $this->assertStringContainsString('Via: SIP/2.0/UDP 1.1.1.1:5060;branch=branch1', $trying);

        // 401 Unauthorized
        $unauth = $req->buildUnauthorized('tag-99', 'asterisk', 'random-nonce-123', 'Asterisk PBX 20.5.0');
        $this->assertStringContainsString('SIP/2.0 401 Unauthorized', $unauth);
        $this->assertStringContainsString('WWW-Authenticate: Digest realm="asterisk", nonce="random-nonce-123", algorithm=MD5, qop="auth"', $unauth);
        $this->assertStringContainsString('To: <sip:100@target>;tag=tag-99', $unauth);

        // 200 OK with SDP
        $sdp = SipMessage::buildSdp('192.168.1.1', 10000);
        $ok = $req->buildOk('tag-100', '<sip:192.168.1.1:5060>', $sdp);
        $this->assertStringContainsString('SIP/2.0 200 OK', $ok);
        $this->assertStringContainsString('Content-Type: application/sdp', $ok);
        $this->assertStringContainsString('m=audio 10000 RTP/AVP 0 101', $ok);
    }
}

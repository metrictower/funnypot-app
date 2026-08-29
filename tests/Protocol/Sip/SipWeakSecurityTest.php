<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use PHPUnit\Framework\TestCase;

final class SipWeakSecurityTest extends TestCase
{
    private string $recordingsDir;
    private string $latchedFile;

    protected function setUp(): void
    {
        $this->recordingsDir = sys_get_temp_dir() . '/funnypot_rec_' . bin2hex(random_bytes(4));
        $this->latchedFile = sys_get_temp_dir() . '/funnypot_latch_' . bin2hex(random_bytes(4)) . '.json';
        @mkdir($this->recordingsDir, 0777, true);
    }

    protected function tearDown(): void
    {
        if (is_file($this->latchedFile)) {
            @unlink($this->latchedFile);
        }
        if (is_dir($this->recordingsDir)) {
            $files = glob($this->recordingsDir . '/*');
            if ($files) {
                foreach ($files as $f) {
                    @unlink($f);
                }
            }
            @rmdir($this->recordingsDir);
        }
    }

    public function test_open_unauthenticated_registration(): void
    {
        $logged = [];
        $cfg = new SipConfig(authMode: 'open');
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // Bare unauthenticated REGISTER
        $raw = "REGISTER sip:pbx.example.com SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK-open\r\n"
            . "From: <sip:101@pbx.example.com>;tag=t1\r\n"
            . "To: <sip:101@pbx.example.com>\r\n"
            . "Call-ID: open-reg-1\r\n"
            . "CSeq: 1 REGISTER\r\n"
            . "Contact: <sip:101@10.0.0.5:5060>\r\n\r\n";

        $msg = SipMessage::parse($raw);
        $server->dispatchMessage($msg, '10.0.0.5', 5060, 'udp');

        $this->assertNotEmpty($logged);
        $this->assertSame('login', end($logged)['event']);
        $this->assertStringContainsString('unauthenticated open access', end($logged)['path']);
    }

    public function test_weak_security_accepts_username_as_password(): void
    {
        $logged = [];
        $cfg = new SipConfig(authMode: 'weak', latchedCredentialsFile: $this->latchedFile);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // Step 1: Initial probe to get challenge nonce
        $raw1 = "REGISTER sip:pbx.example.com SIP/2.0\r\nCall-ID: reg-userpass\r\nCSeq: 1 REGISTER\r\n\r\n";
        $server->dispatchMessage(SipMessage::parse($raw1), '10.0.0.6', 5060, 'udp');

        $refProp = new \ReflectionProperty($server, 'activeNonces');
        $refProp->setAccessible(true);
        $nonces = $refProp->getValue($server);
        $nonce = array_key_last($nonces);

        // Step 2: Attacker tests password = username ('101' for extension '101')
        $ha1 = md5("101:asterisk:101");
        $ha2 = md5("REGISTER:sip:pbx.example.com");
        $resp = md5("{$ha1}:{$nonce}:{$ha2}");

        $raw2 = "REGISTER sip:pbx.example.com SIP/2.0\r\n"
            . "Via: SIP/2.0/UDP 10.0.0.6:5060;branch=z9hG4bK-2\r\n"
            . "From: <sip:101@pbx.example.com>;tag=t2\r\n"
            . "To: <sip:101@pbx.example.com>\r\n"
            . "Call-ID: reg-userpass\r\n"
            . "CSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"101\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:pbx.example.com\", response=\"{$resp}\"\r\n\r\n";

        $server->dispatchMessage(SipMessage::parse($raw2), '10.0.0.6', 5060, 'udp');

        $this->assertSame('login', end($logged)['event']);
        $this->assertStringContainsString("ACCEPTED & LATCHED password '101'", end($logged)['path']);
    }

    public function test_weak_security_accepts_common_default_passwords(): void
    {
        $logged = [];
        $cfg = new SipConfig(authMode: 'weak', defaultPasswords: ['1234', 'admin', 'secret'], latchedCredentialsFile: $this->latchedFile);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // Get challenge nonce
        $server->dispatchMessage(SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: reg-cand\r\nCSeq: 1 REGISTER\r\n\r\n"), '10.0.0.7', 5060, 'udp');
        $refProp = new \ReflectionProperty($server, 'activeNonces');
        $refProp->setAccessible(true);
        $nonce = array_key_last($refProp->getValue($server));

        // Attacker uses password '1234' on extension '200'
        $ha1 = md5("200:asterisk:1234");
        $ha2 = md5("REGISTER:sip:target");
        $resp = md5("{$ha1}:{$nonce}:{$ha2}");

        $raw = "REGISTER sip:target SIP/2.0\r\n"
            . "Call-ID: reg-cand\r\n"
            . "CSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"200\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:target\", response=\"{$resp}\"\r\n\r\n";

        $server->dispatchMessage(SipMessage::parse($raw), '10.0.0.7', 5060, 'udp');

        $this->assertSame('login', end($logged)['event']);
        $this->assertStringContainsString("ACCEPTED & LATCHED password '1234'", end($logged)['path']);
    }

    public function test_weak_security_rejects_non_default_password(): void
    {
        $logged = [];
        $cfg = new SipConfig(authMode: 'weak', defaultPasswords: ['1234'], latchedCredentialsFile: $this->latchedFile);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // Get challenge nonce
        $server->dispatchMessage(SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: reg-wrong\r\nCSeq: 1 REGISTER\r\n\r\n"), '10.0.0.8', 5060, 'udp');
        $refProp = new \ReflectionProperty($server, 'activeNonces');
        $refProp->setAccessible(true);
        $nonce = array_key_last($refProp->getValue($server));

        // Attacker uses unknown password 'ComplexPass999!'
        $ha1 = md5("300:asterisk:ComplexPass999!");
        $ha2 = md5("REGISTER:sip:target");
        $resp = md5("{$ha1}:{$nonce}:{$ha2}");

        $raw = "REGISTER sip:target SIP/2.0\r\n"
            . "Call-ID: reg-wrong\r\n"
            . "CSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"300\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:target\", response=\"{$resp}\"\r\n\r\n";

        $server->dispatchMessage(SipMessage::parse($raw), '10.0.0.8', 5060, 'udp');

        $this->assertSame('login', end($logged)['event']);
        // Must NOT contain ACCEPTED
        $this->assertStringNotContainsString('ACCEPTED', end($logged)['path']);
    }

    public function test_call_recording_creates_wav_and_logs_url(): void
    {
        $logged = [];
        $cfg = new SipConfig(recordCalls: true, recordingsDir: $this->recordingsDir);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $callId = 'test-rec-call-99';

        // 1. INVITE
        $invite = SipMessage::parse("INVITE sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nCSeq: 1 INVITE\r\n\r\n");
        $server->dispatchMessage($invite, '10.0.0.9', 5060, 'udp');

        // 2. ACK to start streaming
        $ack = SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nCSeq: 1 ACK\r\n\r\n");
        $server->dispatchMessage($ack, '10.0.0.9', 5060, 'udp');

        // 3. Wait 25ms and simulate RTP audio transmission ticks
        usleep(25000);
        $server->tickRtpStreams();

        // 4. BYE to end call
        $bye = SipMessage::parse("BYE sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nCSeq: 2 BYE\r\n\r\n");
        $server->dispatchMessage($bye, '10.0.0.9', 5060, 'udp');

        $lastLog = end($logged);
        $this->assertSame('call_end', $lastLog['event']);
        $this->assertNotEmpty($lastLog['recording'], 'Recording URL must be present');
        $this->assertStringContainsString('test-rec-call-99', $lastLog['recording']);

        // Verify the gzip'd mu-law recording exists on disk (served as WAV on demand).
        $expectedRec = $this->recordingsDir . '/test-rec-call-99.ulaw.gz';
        $this->assertFileExists($expectedRec);
        $this->assertGreaterThan(0, filesize($expectedRec));
        // And it round-trips back to mu-law bytes.
        $this->assertNotFalse(gzdecode((string) file_get_contents($expectedRec)));
    }
}

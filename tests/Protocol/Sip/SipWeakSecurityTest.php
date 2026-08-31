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
        $cfg = new SipConfig(authMode: 'open', rtpPort: 0);
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
        $cfg = new SipConfig(authMode: 'weak', latchedCredentialsFile: $this->latchedFile, rtpPort: 0);
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

    public function test_permissive_crack_resistance_rejects_first_guesses_then_accepts(): void
    {
        // FP-0225: under permissive, an ARBITRARY password must not "crack" on guess #1 (the svcrack
        // honeypot tell). Fixed threshold 3 -> the first 3 arbitrary guesses are 403'd, then the 4th is
        // accepted + latched: the toll-fraud lure is kept, just not first-guess.
        $logged = [];
        $cfg = new SipConfig(authMode: 'permissive', crackMin: 3, crackMax: 3, latchedCredentialsFile: $this->latchedFile, rtpPort: 0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $server->dispatchMessage(SipMessage::parse("REGISTER sip:pbx SIP/2.0\r\nCall-ID: cr-0\r\nCSeq: 1 REGISTER\r\n\r\n"), '10.9.9.9', 5060, 'udp');
        $ref = new \ReflectionProperty($server, 'activeNonces');
        $ref->setAccessible(true);
        $nonce = array_key_last($ref->getValue($server));
        $ha2 = md5('REGISTER:sip:pbx');

        $guess = function (string $pass, string $cid) use ($server, $nonce, $ha2, &$logged): array {
            $ha1 = md5("100:asterisk:{$pass}");
            $resp = md5("{$ha1}:{$nonce}:{$ha2}");
            $raw = "REGISTER sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP 10.9.9.9:5060;branch=z9hG4bK-{$cid}\r\n"
                . "From: <sip:100@pbx>;tag={$cid}\r\nTo: <sip:100@pbx>\r\nCall-ID: {$cid}\r\nCSeq: 2 REGISTER\r\n"
                . "Authorization: Digest username=\"100\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:pbx\", response=\"{$resp}\"\r\n\r\n";
            $server->dispatchMessage(SipMessage::parse($raw), '10.9.9.9', 5060, 'udp');

            return end($logged);
        };

        foreach (['aaa', 'bbb', 'ccc'] as $i => $p) {
            $log = $guess($p, "cr-g{$i}");
            self::assertStringNotContainsString('ACCEPTED', (string) $log['path'], 'guess ' . ($i + 1) . ' must not crack on an arbitrary password');
        }
        $log4 = $guess('ddd', 'cr-g9');
        self::assertStringContainsString('ACCEPTED & LATCHED', (string) $log4['path'], 'the crack succeeds only after the threshold of guesses');
    }

    public function test_weak_security_accepts_common_default_passwords(): void
    {
        $logged = [];
        $cfg = new SipConfig(authMode: 'weak', defaultPasswords: ['1234', 'admin', 'secret'], latchedCredentialsFile: $this->latchedFile, rtpPort: 0);
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
        $cfg = new SipConfig(authMode: 'weak', defaultPasswords: ['1234'], latchedCredentialsFile: $this->latchedFile, rtpPort: 0);
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
        $cfg = new SipConfig(recordCalls: true, recordingsDir: $this->recordingsDir, rtpPort: 0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $callId = 'test-rec-call-99';

        // 1. INVITE
        $invite = SipMessage::parse("INVITE sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nCSeq: 1 INVITE\r\n\r\n");
        $server->dispatchMessage($invite, '10.0.0.9', 5060, 'udp');

        // 2. ACK (echoing our To-tag, so it passes return-routability) to start streaming
        $toTag = $server->dialogToTag($callId, '10.0.0.9');
        $ack = SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nTo: <sip:101@target>;tag={$toTag}\r\nCSeq: 1 ACK\r\n\r\n");
        $server->dispatchMessage($ack, '10.0.0.9', 5060, 'udp');

        // 3. Simulate the CALLER sending audio (the intel a real call carries) — required now for a
        //    recording to be kept — plus an outbound persona tick.
        $refS = new \ReflectionProperty($server, 'sessions');
        $refS->setAccessible(true);
        foreach ($refS->getValue($server) as $sess) {
            $sess->recordedInbound .= str_repeat("\x7f", 800); // ~0.1s of inbound mu-law
        }
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

    public function test_call_with_no_caller_audio_writes_no_recording(): void
    {
        // A scanner answers the handshake but sends NO RTP — we must NOT keep a one-sided recording
        // (zero intel, pure storage waste). The call is still logged, flagged "no caller audio".
        $logged = [];
        $cfg = new SipConfig(recordCalls: true, recordingsDir: $this->recordingsDir, rtpPort: 0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });
        $callId = 'test-noaudio-1';

        $server->dispatchMessage(SipMessage::parse("INVITE sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nCSeq: 1 INVITE\r\n\r\n"), '10.0.0.9', 5060, 'udp');
        $toTag = $server->dialogToTag($callId, '10.0.0.9');
        $server->dispatchMessage(SipMessage::parse("ACK sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nTo: <sip:101@target>;tag={$toTag}\r\nCSeq: 1 ACK\r\n\r\n"), '10.0.0.9', 5060, 'udp');
        usleep(25000);
        $server->tickRtpStreams();               // our persona streams; caller stays silent (no inbound RTP)
        $server->dispatchMessage(SipMessage::parse("BYE sip:101@target SIP/2.0\r\nCall-ID: {$callId}\r\nCSeq: 2 BYE\r\n\r\n"), '10.0.0.9', 5060, 'udp');

        $lastLog = end($logged);
        $this->assertSame('call_end', $lastLog['event']);
        $this->assertSame('', (string) $lastLog['recording'], 'no recording URL when the caller sent no audio');
        $this->assertStringContainsString('no caller audio (recording dropped)', $lastLog['path']);
        $this->assertFileDoesNotExist($this->recordingsDir . '/test-noaudio-1.ulaw.gz');
    }

    /**
     * Regression: pruneRecordings() must glob every recording extension WITHOUT GLOB_BRACE (undefined
     * on musl/Alpine, where it is a fatal error that kills the listener) and delete oldest-first until
     * under the cap. Writing one file per extension proves all three are seen and pruned.
     */
    public function test_prune_recordings_globs_all_extensions_and_enforces_cap(): void
    {
        $cfg = new SipConfig(recordCalls: true, recordingsDir: $this->recordingsDir, recordingsMaxBytes: 300, rtpPort: 0);
        $server = new SipServer($cfg, null);

        $mk = function (string $name, int $bytes, int $ageSeconds): string {
            $p = $this->recordingsDir . '/' . $name;
            file_put_contents($p, str_repeat('x', $bytes));
            touch($p, time() - $ageSeconds);
            return $p;
        };
        $old = $mk('old.ulaw.gz', 200, 300);   // oldest
        $mid = $mk('mid.ulaw', 200, 200);
        $new = $mk('new.wav', 200, 100);       // newest

        $prune = new \ReflectionMethod($server, 'pruneRecordings');
        $prune->setAccessible(true);
        $prune->invoke($server); // must not throw (the GLOB_BRACE regression)

        // 600 bytes over a 300 cap -> oldest deleted until <= cap; newest survives.
        $this->assertFileDoesNotExist($old);
        $this->assertFileDoesNotExist($mid);
        $this->assertFileExists($new);

        $remaining = array_merge(
            glob($this->recordingsDir . '/*.ulaw.gz') ?: [],
            glob($this->recordingsDir . '/*.ulaw') ?: [],
            glob($this->recordingsDir . '/*.wav') ?: []
        );
        $this->assertLessThanOrEqual(300, array_sum(array_map('filesize', $remaining)));
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\CredentialStore;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipMessage;
use Funnypot\Protocol\Sip\SipServer;
use PHPUnit\Framework\TestCase;

final class CredentialStoreTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/funnypot_latch_' . bin2hex(random_bytes(4)) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->tempFile)) {
            @unlink($this->tempFile);
        }
    }

    public function test_credential_latching_and_retrieval(): void
    {
        $store = new CredentialStore($this->tempFile);

        $this->assertFalse($store->hasLatched('10.0.0.1', '101'));
        $this->assertNull($store->getLatched('10.0.0.1', '101'));

        $store->latch('10.0.0.1', '101', 'hash-12345');

        $this->assertTrue($store->hasLatched('10.0.0.1', '101'));
        $this->assertSame('hash-12345', $store->getLatched('10.0.0.1', '101'));
        $this->assertTrue($store->matches('10.0.0.1', '101', 'hash-12345'));
        $this->assertFalse($store->matches('10.0.0.1', '101', 'different-hash'));

        // Independent extension
        $this->assertFalse($store->hasLatched('10.0.0.1', '102'));
    }

    public function test_sip_server_smart_credential_latching(): void
    {
        $logged = [];
        // crackMin:0 disables crack-resistance so this test isolates the latching behaviour (accept-first);
        // FP-0225's reject-first-then-accept is covered by its own test in SipWeakSecurityTest.
        $cfg = new SipConfig(authMode: 'permissive', latchPasswords: true, latchedCredentialsFile: $this->tempFile, rtpPort: 0, crackMin: 0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        // 1. Initial probe to obtain challenge nonce
        $probe = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: latch-c1\r\nCSeq: 1 REGISTER\r\n\r\n");
        $server->dispatchMessage($probe, '10.0.0.2', 5060, 'udp');

        $refProp = new \ReflectionProperty($server, 'activeNonces');
        $refProp->setAccessible(true);
        $nonces = $refProp->getValue($server);
        $nonce = array_key_last($nonces);

        // 2. First attempt: password "firstpass"
        $ha1_first = md5("100:asterisk:firstpass");
        $ha2 = md5("REGISTER:sip:target");
        $resp_first = md5("{$ha1_first}:{$nonce}:{$ha2}");

        $reg1 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: latch-c2\r\nCSeq: 2 REGISTER\r\n"
            . "Authorization: Digest username=\"100\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:target\", response=\"{$resp_first}\"\r\n\r\n");
        $server->dispatchMessage($reg1, '10.0.0.2', 5060, 'udp');

        $log1 = end($logged);
        $this->assertSame('login', $log1['event']);
        $this->assertStringContainsString('ACCEPTED & LATCHED', $log1['path']);

        // 3. Second attempt: scanner tests different password "secondpass" on extension 100
        $ha1_second = md5("100:asterisk:secondpass");
        $resp_second = md5("{$ha1_second}:{$nonce}:{$ha2}");

        $reg2 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: latch-c3\r\nCSeq: 3 REGISTER\r\n"
            . "Authorization: Digest username=\"100\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:target\", response=\"{$resp_second}\"\r\n\r\n");
        $server->dispatchMessage($reg2, '10.0.0.2', 5060, 'udp');

        $log2 = end($logged);
        $this->assertSame('login', $log2['event']);
        // A different password on a cracked AOR is CAPTURED, never rejected — a honeypot lures by
        // staying easy to authenticate, so every guess is answered 200 and logged as intel.
        $this->assertStringContainsString('additional credential captured', $log2['path']);

        // 4. Third attempt: softphone logs back in using the original "firstpass"
        $reg3 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: latch-c4\r\nCSeq: 4 REGISTER\r\n"
            . "Authorization: Digest username=\"100\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:target\", response=\"{$resp_first}\"\r\n\r\n");
        $server->dispatchMessage($reg3, '10.0.0.2', 5060, 'udp');

        $log3 = end($logged);
        $this->assertSame('login', $log3['event']);
        $this->assertStringContainsString('latched credentials verified', $log3['path']);
    }

    /**
     * Regression: a softphone re-REGISTERs with the SAME password but a fresh nonce every time (the
     * digest response is nonce-dependent). The latch must recognise it as the same credential and
     * verify — not re-log it as a fresh guess. A genuinely different password on a fresh nonce is
     * captured as intel, never rejected.
     */
    public function test_reregister_same_password_new_nonce_is_verified(): void
    {
        $logged = [];
        $cfg = new SipConfig(authMode: 'weak', latchPasswords: true, latchedCredentialsFile: $this->tempFile, rtpPort: 0);
        $server = new SipServer($cfg, static function (array $e) use (&$logged): void {
            $logged[] = $e;
        });

        $ref = new \ReflectionProperty($server, 'activeNonces');
        $ref->setAccessible(true);
        $freshNonce = static function () use ($server, $ref): string {
            // An authless REGISTER makes the server mint + challenge with a new nonce.
            $server->dispatchMessage(
                SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: n-" . bin2hex(random_bytes(3)) . "\r\nCSeq: 1 REGISTER\r\n\r\n"),
                '10.0.0.9',
                5060,
                'udp'
            );
            return (string) array_key_last($ref->getValue($server));
        };
        $ha2 = md5('REGISTER:sip:target');
        $reg = static function (string $pass, string $nonce) use ($server, $ha2): SipMessage {
            $resp = md5(md5("root:asterisk:{$pass}") . ":{$nonce}:" . $ha2);
            return SipMessage::parse(
                "REGISTER sip:target SIP/2.0\r\nCall-ID: r-" . bin2hex(random_bytes(3)) . "\r\nCSeq: 2 REGISTER\r\n"
                . "Authorization: Digest username=\"root\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:target\", response=\"{$resp}\"\r\n\r\n"
            );
        };

        // 1. First REGISTER with password == username: accepted + latched.
        $n1 = $freshNonce();
        $server->dispatchMessage($reg('root', $n1), '10.0.0.9', 5060, 'udp');
        $this->assertStringContainsString("ACCEPTED & LATCHED password 'root'", end($logged)['path']);

        // 2. Re-REGISTER, SAME password, DIFFERENT nonce -> must verify (this was the bug).
        $n2 = $freshNonce();
        $this->assertNotSame($n1, $n2, 'precondition: a fresh nonce was issued');
        $server->dispatchMessage($reg('root', $n2), '10.0.0.9', 5060, 'udp');
        $this->assertStringContainsString('latched credentials verified', end($logged)['path']);

        // 3. A genuinely different password on a fresh nonce is captured, not rejected.
        $n3 = $freshNonce();
        $server->dispatchMessage($reg('hunter2', $n3), '10.0.0.9', 5060, 'udp');
        $this->assertStringContainsString('additional credential captured', end($logged)['path']);
    }
}

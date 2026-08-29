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
        $cfg = new SipConfig(authMode: 'permissive', latchPasswords: true, latchedCredentialsFile: $this->tempFile);
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
        // Must be REJECTED!
        $this->assertStringContainsString('REJECTED conflicting password', $log2['path']);

        // 4. Third attempt: softphone logs back in using the original "firstpass"
        $reg3 = SipMessage::parse("REGISTER sip:target SIP/2.0\r\nCall-ID: latch-c4\r\nCSeq: 4 REGISTER\r\n"
            . "Authorization: Digest username=\"100\", realm=\"asterisk\", nonce=\"{$nonce}\", uri=\"sip:target\", response=\"{$resp_first}\"\r\n\r\n");
        $server->dispatchMessage($reg3, '10.0.0.2', 5060, 'udp');

        $log3 = end($logged);
        $this->assertSame('login', $log3['event']);
        $this->assertStringContainsString('latched credentials verified', $log3['path']);
    }
}

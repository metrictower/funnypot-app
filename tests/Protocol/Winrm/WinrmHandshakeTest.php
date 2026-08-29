<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Winrm;

use Funnypot\Protocol\Winrm\WinrmConfig;
use Funnypot\Protocol\Winrm\WinrmServer;
use Funnypot\Protocol\Winrm\WinrmSession;
use PHPUnit\Framework\TestCase;

final class WinrmHandshakeTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?WinrmConfig $config = null): WinrmServer
    {
        $this->events = [];

        return new WinrmServer($config ?? new WinrmConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    /**
     * @param array<string,string> $headers
     */
    private static function request(string $method, string $path, array $headers = [], string $body = ''): string
    {
        $lines = ["{$method} {$path} HTTP/1.1", 'Host: 10.0.0.5:5985'];
        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }
        if ($body !== '') {
            $lines[] = 'Content-Length: ' . strlen($body);
        }

        return implode("\r\n", $lines) . "\r\n\r\n" . $body;
    }

    private static function u16(string $s): string
    {
        return (string) mb_convert_encoding($s, 'UTF-16LE', 'UTF-8');
    }

    /** A minimal NTLMSSP type-1 NEGOTIATE message (only the type field matters to us). */
    private static function ntlmNegotiate(): string
    {
        return "NTLMSSP\x00" . pack('V', 1) . pack('V', 0x00088207) . str_repeat("\x00", 16);
    }

    /** A well-formed NTLMSSP type-3 AUTHENTICATE carrying an account name and NT response. */
    private static function ntlmAuthenticate(string $domain, string $user, string $workstation): string
    {
        $d = self::u16($domain);
        $u = self::u16($user);
        $w = self::u16($workstation);
        $lm = str_repeat("\x00", 24);
        $nt = str_repeat("\xAB", 24);

        $field = static fn (int $len, int $off): string => pack('v', $len) . pack('v', $len) . pack('V', $off);
        $o = 64;
        $lmD = $field(24, $o); $o += 24;
        $ntD = $field(strlen($nt), $o); $o += strlen($nt);
        $dD = $field(strlen($d), $o); $o += strlen($d);
        $uD = $field(strlen($u), $o); $o += strlen($u);
        $wD = $field(strlen($w), $o);

        return "NTLMSSP\x00" . pack('V', 3)
            . $lmD . $ntD . $dD . $uD . $wD . $field(0, $o)
            . pack('V', 0x00000001) // NTLMSSP_NEGOTIATE_UNICODE
            . $lm . $nt . $d . $u . $w;
    }

    public function test_post_wsman_without_credential_is_challenged(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('203.0.113.5', 51000, 1);
        $session->inbuf = self::request('POST', '/wsman', [], '<s:Envelope/>');
        $server->processInbound($session);

        self::assertStringStartsWith('HTTP/1.1 401 Unauthorized', $session->outbuf);
        self::assertStringContainsString("WWW-Authenticate: Negotiate\r\n", $session->outbuf);
        self::assertStringContainsString('WWW-Authenticate: Basic realm="WSMAN"', $session->outbuf);
        self::assertStringContainsString('Server: Microsoft-HTTPAPI/2.0', $session->outbuf);
        // The connection stays open so the client can retry with a credential.
        self::assertFalse($session->close);
        self::assertNotNull($this->eventOfType('winrm_probe'));
    }

    public function test_basic_credential_is_captured_and_denied(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('203.0.113.5', 51000, 1);
        $session->inbuf = self::request('POST', '/wsman', [
            'Authorization' => 'Basic ' . base64_encode('Administrator:Sup3rSecret!'),
        ], '<s:Envelope/>');
        $server->processInbound($session);

        $auth = $this->eventOfType('winrm_auth');
        self::assertNotNull($auth);
        self::assertSame('Administrator', $auth['username']);
        self::assertSame('Sup3rSecret!', $auth['password']);
        self::assertSame('high', $auth['severity']);
        self::assertStringContainsString('basic login attempt: Administrator', $auth['path']);
        // Never authenticated: still a 401.
        self::assertStringStartsWith('HTTP/1.1 401 Unauthorized', $session->outbuf);
    }

    public function test_ntlm_handshake_challenges_then_captures_type3_username(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('198.51.100.9', 40000, 1);

        // type-1 NEGOTIATE -> a type-2 CHALLENGE in the Negotiate header, connection kept open.
        $session->inbuf = self::request('POST', '/wsman', [
            'Authorization' => 'Negotiate ' . base64_encode(self::ntlmNegotiate()),
        ]);
        $server->processInbound($session);

        self::assertFalse($session->close);
        self::assertTrue((bool) preg_match('/WWW-Authenticate: Negotiate (\S+)/', $session->outbuf, $m));
        $challenge = base64_decode($m[1], true);
        self::assertIsString($challenge);
        self::assertStringStartsWith("NTLMSSP\x00", $challenge);
        self::assertSame(2, unpack('V', substr($challenge, 8, 4))[1], 'server sends a type-2 CHALLENGE');

        $session->outbuf = '';

        // type-3 AUTHENTICATE on the same connection -> username/domain/workstation captured.
        $session->inbuf = self::request('POST', '/wsman', [
            'Authorization' => 'Negotiate ' . base64_encode(self::ntlmAuthenticate('CORP', 'jdoe', 'WS7')),
        ]);
        $server->processInbound($session);

        $auth = $this->eventOfType('winrm_auth');
        self::assertNotNull($auth);
        self::assertSame('jdoe', $auth['username']);
        self::assertStringContainsString('CORP\\jdoe', $auth['path']);
        self::assertStringContainsString('workstation=WS7', $auth['body']);
        self::assertStringContainsString('nt_response=' . str_repeat('ab', 24), $auth['body']);
        self::assertSame('high', $auth['severity']);
    }

    public function test_get_root_returns_microsoft_httpapi_404(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('192.0.2.7', 5000, 1);
        $session->inbuf = self::request('GET', '/');
        $server->processInbound($session);

        self::assertStringStartsWith('HTTP/1.1 404 Not Found', $session->outbuf);
        self::assertStringContainsString('Server: Microsoft-HTTPAPI/2.0', $session->outbuf);
        self::assertStringContainsString('Connection: close', $session->outbuf);
        self::assertTrue($session->close);

        $probe = $this->eventOfType('winrm_probe');
        self::assertNotNull($probe);
        self::assertStringContainsString('404', $probe['path']);
    }

    public function test_malformed_request_logs_unknown_and_closes(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('192.0.2.8', 5001, 1);
        $session->inbuf = "not-a-http-request-line\r\nGarbage: yes\r\n\r\n";
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('winrm_unknown'));
        self::assertStringStartsWith('HTTP/1.1 400 Bad Request', $session->outbuf);
        self::assertTrue($session->close);
    }

    public function test_partial_body_is_buffered_until_content_length_satisfied(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('192.0.2.9', 5002, 1);

        $full = self::request('POST', '/wsman', [
            'Authorization' => 'Basic ' . base64_encode('svc:pw'),
        ], '<Envelope>bodybodybody</Envelope>');

        // Feed everything except the last 5 body bytes: nothing should parse yet.
        $session->inbuf = substr($full, 0, -5);
        $server->processInbound($session);
        self::assertNull($this->eventOfType('winrm_auth'));
        self::assertSame('', $session->outbuf);

        // Deliver the remainder: the request now parses and the credential is captured.
        $session->inbuf .= substr($full, -5);
        $server->processInbound($session);
        self::assertNotNull($this->eventOfType('winrm_auth'));
    }

    public function test_spnego_kerberos_negotiate_is_recorded_without_crash(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('192.0.2.10', 5003, 1);

        // A GSS-API/SPNEGO application token (leading 0x60) with no NTLMSSP signature inside.
        $spnego = "\x60\x2b\x06\x06\x2b\x06\x01\x05\x05\x02" . str_repeat("\x41", 20);
        $session->inbuf = self::request('POST', '/wsman', [
            'Authorization' => 'Negotiate ' . base64_encode($spnego),
        ]);
        $server->processInbound($session);

        $auth = $this->eventOfType('winrm_auth');
        self::assertNotNull($auth);
        self::assertStringContainsString('mechanism=spnego/kerberos', $auth['body']);
    }

    public function test_pipelined_keepalive_requests_are_all_processed(): void
    {
        $server = $this->newServer();
        $session = new WinrmSession('192.0.2.11', 5004, 1);

        // Two keep-alive requests delivered in one read: an unauthenticated POST /wsman (401 challenge,
        // connection stays open) followed by a Basic credential on the same connection.
        $session->inbuf = self::request('POST', '/wsman', [], '<x/>')
            . self::request('POST', '/wsman', [
                'Authorization' => 'Basic ' . base64_encode('svc-admin:hunter2'),
            ], '<y/>');
        $server->processInbound($session);

        // Both framed messages were dispatched: the probe from the first, the capture from the second.
        self::assertNotNull($this->eventOfType('winrm_probe'));
        $auth = $this->eventOfType('winrm_auth');
        self::assertNotNull($auth);
        self::assertSame('svc-admin', $auth['username']);
        self::assertSame('hunter2', $auth['password']);
        self::assertSame('', $session->inbuf, 'both pipelined requests were consumed');
    }

    /**
     * @return array<string,mixed>|null
     */
    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }
}

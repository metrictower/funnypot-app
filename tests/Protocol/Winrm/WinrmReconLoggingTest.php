<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Winrm;

use Funnypot\Protocol\Winrm\WinrmConfig;
use Funnypot\Protocol\Winrm\WinrmServer;
use Funnypot\Protocol\Winrm\WinrmSession;
use PHPUnit\Framework\TestCase;

final class WinrmReconLoggingTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:WinrmServer,1:WinrmSession}
     */
    private function serverSession(?WinrmConfig $config = null): array
    {
        $this->events = [];
        $server = new WinrmServer($config ?? new WinrmConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new WinrmSession('198.51.100.44', 5985, 1);

        return [$server, $session];
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

    public function test_every_event_carries_the_winrm_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::request('POST', '/wsman', [
            'User-Agent' => 'Microsoft WinRM Client',
        ], '<s:Envelope/>');
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('winrm', $e['proto']);
            self::assertSame('WINRM', $e['method']);
            self::assertSame(1, $e['matched']);
            self::assertSame(1, $e['served']);
            self::assertArrayHasKey('ts', $e);
            self::assertArrayHasKey('severity', $e);
            self::assertArrayHasKey('event', $e);
            self::assertArrayHasKey('ip', $e);
            self::assertArrayHasKey('port', $e);
            self::assertArrayHasKey('path', $e);
        }
    }

    public function test_user_agent_is_captured_on_the_probe(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::request('POST', '/wsman', [
            'User-Agent' => 'Ruby WinRM Client/2.3',
        ], '<s:Envelope/>');
        $server->processInbound($session);

        $probe = $this->eventOfType('winrm_probe');
        self::assertNotNull($probe);
        self::assertSame('Ruby WinRM Client/2.3', $probe['user_agent']);
    }

    public function test_non_printable_credential_bytes_are_sanitised(): void
    {
        [$server, $session] = $this->serverSession();

        // A password with an embedded control byte must be neutralised in the log.
        $session->inbuf = self::request('POST', '/wsman', [
            'Authorization' => 'Basic ' . base64_encode("user:pa\x01ss"),
        ]);
        $server->processInbound($session);

        $auth = $this->eventOfType('winrm_auth');
        self::assertNotNull($auth);
        self::assertSame('pa.ss', $auth['password']);
    }

    public function test_parse_authorization_basic(): void
    {
        $parsed = WinrmServer::parseAuthorization('Basic ' . base64_encode('bob:letmein'));
        self::assertNotNull($parsed);
        self::assertSame('basic', $parsed['scheme']);
        self::assertSame('bob', $parsed['username']);
        self::assertSame('letmein', $parsed['password']);
    }

    public function test_parse_authorization_ntlm_type3_extracts_account(): void
    {
        $u16 = static fn (string $s): string => (string) mb_convert_encoding($s, 'UTF-16LE', 'UTF-8');
        $d = $u16('WORKGROUP');
        $user = $u16('alice');
        $w = $u16('DESKTOP1');
        $nt = str_repeat("\x22", 24);

        $field = static fn (int $len, int $off): string => pack('v', $len) . pack('v', $len) . pack('V', $off);
        $o = 64;
        $lmD = $field(24, $o); $o += 24;
        $ntD = $field(24, $o); $o += 24;
        $dD = $field(strlen($d), $o); $o += strlen($d);
        $uD = $field(strlen($user), $o); $o += strlen($user);
        $wD = $field(strlen($w), $o);
        $msg = "NTLMSSP\x00" . pack('V', 3)
            . $lmD . $ntD . $dD . $uD . $wD . $field(0, $o)
            . pack('V', 0x00000001)
            . str_repeat("\x00", 24) . $nt . $d . $user . $w;

        $parsed = WinrmServer::parseAuthorization('Negotiate ' . base64_encode($msg));
        self::assertNotNull($parsed);
        self::assertSame('negotiate', $parsed['scheme']);
        self::assertSame(3, $parsed['ntlmssp_type']);
        self::assertSame('alice', $parsed['username']);
        self::assertSame('WORKGROUP', $parsed['domain']);
        self::assertSame('DESKTOP1', $parsed['workstation']);
        self::assertSame(str_repeat('22', 24), $parsed['nt_response']);
    }

    public function test_parse_authorization_ntlm_type1_has_no_account(): void
    {
        $msg = "NTLMSSP\x00" . pack('V', 1) . pack('V', 0x00088207) . str_repeat("\x00", 16);
        $parsed = WinrmServer::parseAuthorization('Negotiate ' . base64_encode($msg));
        self::assertNotNull($parsed);
        self::assertSame(1, $parsed['ntlmssp_type']);
        self::assertArrayNotHasKey('username', $parsed);
    }

    public function test_path_from_uri_variants(): void
    {
        self::assertSame('/wsman', WinrmServer::pathFromUri('/wsman'));
        self::assertSame('/wsman', WinrmServer::pathFromUri('/wsman?PSVersion=5.1'));
        self::assertSame('/wsman', WinrmServer::pathFromUri('http://host:5985/wsman'));
        self::assertSame('/', WinrmServer::pathFromUri('http://host:5985'));
        self::assertSame('*', WinrmServer::pathFromUri('*'));
    }

    public function test_is_wsman_requires_post(): void
    {
        self::assertTrue(WinrmServer::isWsman('POST', '/wsman'));
        self::assertTrue(WinrmServer::isWsman('POST', '/wsman/SubscriptionManager/x'));
        self::assertFalse(WinrmServer::isWsman('GET', '/wsman'));
        self::assertFalse(WinrmServer::isWsman('POST', '/'));
    }

    public function test_malformed_request_returns_null(): void
    {
        self::assertNull(WinrmServer::parseRequest("GARBAGE-NO-VERSION\r\n\r\n"));
        self::assertNull(WinrmServer::parseRequest(''));
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_WINRM_SERVER=Microsoft-HTTPAPI/2.0');
        putenv('FUNNYPOT_WINRM_REALM=WSMAN');
        putenv('FUNNYPOT_WINRM_AUTH=basic');
        putenv('FUNNYPOT_WINRM_COMPUTER=DC01');

        $config = WinrmConfig::fromEnv();
        self::assertSame('Microsoft-HTTPAPI/2.0', $config->serverName);
        self::assertSame('WSMAN', $config->realm);
        self::assertSame(WinrmConfig::AUTH_BASIC, $config->authScheme);
        self::assertSame('DC01', $config->computerName);

        putenv('FUNNYPOT_WINRM_SERVER');
        putenv('FUNNYPOT_WINRM_REALM');
        putenv('FUNNYPOT_WINRM_AUTH');
        putenv('FUNNYPOT_WINRM_COMPUTER');

        // Defaults when unset.
        $default = WinrmConfig::fromEnv();
        self::assertSame(WinrmConfig::AUTH_BOTH, $default->authScheme);
        self::assertSame('WIN-WINRM01', $default->computerName);
    }

    public function test_basic_only_config_omits_negotiate_challenge(): void
    {
        [$server, $session] = $this->serverSession(new WinrmConfig(authScheme: WinrmConfig::AUTH_BASIC));

        $session->inbuf = self::request('POST', '/wsman', [], '<s:Envelope/>');
        $server->processInbound($session);

        self::assertStringContainsString('WWW-Authenticate: Basic realm="WSMAN"', $session->outbuf);
        self::assertStringNotContainsString('WWW-Authenticate: Negotiate', $session->outbuf);
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

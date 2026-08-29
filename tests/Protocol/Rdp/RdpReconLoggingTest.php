<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Rdp;

use Funnypot\Protocol\Rdp\RdpConfig;
use Funnypot\Protocol\Rdp\RdpServer;
use Funnypot\Protocol\Rdp\RdpSession;
use PHPUnit\Framework\TestCase;

final class RdpReconLoggingTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private static function tpkt(string $payload): string
    {
        return "\x03\x00" . pack('n', strlen($payload) + 4) . $payload;
    }

    private static function connectionRequest(string $variable): string
    {
        $x224 = chr(6 + strlen($variable)) . "\xe0\x00\x00" . pack('n', 0x1000) . "\x00" . $variable;

        return self::tpkt($x224);
    }

    private static function negReq(int $protocols): string
    {
        return "\x01\x00" . pack('v', 8) . pack('V', $protocols);
    }

    private static function u16(string $s): string
    {
        return (string) mb_convert_encoding($s, 'UTF-16LE', 'UTF-8');
    }

    /**
     * @return array{0:RdpServer,1:RdpSession}
     */
    private function connected(string $variable): array
    {
        $this->events = [];
        $server = new RdpServer(new RdpConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new RdpSession('198.51.100.20', 3389, 1);
        $session->inbuf .= self::connectionRequest($variable);
        $server->processInbound($session);

        return [$server, $session];
    }

    public function test_cookie_and_negotiate_are_logged(): void
    {
        $this->connected(
            "Cookie: mstshash=root\r\n" . self::negReq(RdpConfig::PROTOCOL_SSL | RdpConfig::PROTOCOL_HYBRID_EX)
        );

        $cookie = $this->eventOfType('rdp_cookie');
        self::assertNotNull($cookie);
        self::assertSame('root', $cookie['body']);
        self::assertStringContainsString('mstshash=root', $cookie['path']);

        $negotiate = $this->eventOfType('rdp_negotiate');
        self::assertNotNull($negotiate);
        self::assertStringContainsString('SSL', $negotiate['path']);
        self::assertStringContainsString('HYBRID_EX', $negotiate['path']);
    }

    public function test_every_event_carries_the_rdp_envelope(): void
    {
        $this->connected("Cookie: mstshash=x\r\n" . self::negReq(RdpConfig::PROTOCOL_RDP));

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('rdp', $e['proto']);
            self::assertSame('RDP', $e['method']);
            self::assertArrayHasKey('ts', $e);
            self::assertArrayHasKey('severity', $e);
        }
    }

    public function test_negotiate_logged_without_cookie(): void
    {
        [, $session] = $this->connected(self::negReq(RdpConfig::PROTOCOL_HYBRID));

        self::assertNull($this->eventOfType('rdp_cookie'));
        self::assertNotNull($this->eventOfType('rdp_negotiate'));
        self::assertNull($session->mstshash);
    }

    public function test_unmodelled_mcs_pdu_logs_unknown_and_closes(): void
    {
        [$server, $session] = $this->connected(self::negReq(RdpConfig::PROTOCOL_RDP));
        $session->outbuf = '';

        // 0xFF is not a discriminator we model.
        $session->inbuf .= self::tpkt("\x02\xf0\x80\xff\x00\x00");
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('rdp_unknown'));
        self::assertTrue($session->close);
    }

    public function test_protocol_names_mapping(): void
    {
        self::assertSame('RDP', RdpServer::protocolNames(0));
        self::assertSame('SSL', RdpServer::protocolNames(RdpConfig::PROTOCOL_SSL));
        self::assertSame('SSL, HYBRID', RdpServer::protocolNames(RdpConfig::PROTOCOL_SSL | RdpConfig::PROTOCOL_HYBRID));
        self::assertSame(
            'SSL, HYBRID, HYBRID_EX',
            RdpServer::protocolNames(RdpConfig::PROTOCOL_SSL | RdpConfig::PROTOCOL_HYBRID | RdpConfig::PROTOCOL_HYBRID_EX)
        );
    }

    public function test_parse_connection_request_extracts_routing_token(): void
    {
        $parsed = RdpServer::parseConnectionRequest("Cookie: msts=3640205228.15629.0000\r\n");
        self::assertNull($parsed['mstshash']);
        self::assertSame('3640205228.15629.0000', $parsed['routingToken']);
        self::assertFalse($parsed['sawNegotiationRequest']);
    }

    public function test_parse_client_info_ansi_credential(): void
    {
        // A client that does not set INFO_UNICODE sends single-byte strings with 1-byte terminators.
        $info = pack('V', 0)          // codePage
            . pack('V', 0)            // flags: no INFO_UNICODE
            . pack('v', 3)            // cbDomain "LAB"
            . pack('v', 5)            // cbUserName "guest"
            . pack('v', 4)            // cbPassword "1234"
            . pack('v', 0)
            . pack('v', 0)
            . "LAB\x00"
            . "guest\x00"
            . "1234\x00"
            . "\x00\x00";
        $userData = pack('v', 0x0040) . pack('v', 0) . $info;

        $cred = RdpServer::parseClientInfo($userData);
        self::assertNotNull($cred);
        self::assertSame('LAB', $cred['domain']);
        self::assertSame('guest', $cred['username']);
        self::assertSame('1234', $cred['password']);
    }

    public function test_parse_client_info_rejects_non_info_pdu(): void
    {
        // A basic security header without SEC_INFO_PKT is not a credential PDU.
        self::assertNull(RdpServer::parseClientInfo(pack('v', 0x0001) . pack('v', 0) . str_repeat("\x00", 40)));
        self::assertNull(RdpServer::parseClientInfo("\x00\x00"));
    }

    public function test_parse_ntlm_authenticate_returns_null_for_non_authenticate(): void
    {
        // A NEGOTIATE message (type 1) is not a credential; only AUTHENTICATE (type 3) is captured.
        $negotiate = "NTLMSSP\x00" . pack('V', 1) . str_repeat("\x00", 40);
        self::assertNull(RdpServer::parseNtlmAuthenticate($negotiate));
        self::assertNull(RdpServer::parseNtlmAuthenticate('no ntlm here'));
    }

    public function test_parse_ntlm_authenticate_extracts_fields_and_hash(): void
    {
        $d = self::u16('CORP');
        $u = self::u16('jdoe');
        $w = self::u16('WS7');
        $nt = str_repeat("\x11", 24);
        $field = static fn (int $len, int $off): string => pack('v', $len) . pack('v', $len) . pack('V', $off);
        $start = 64;
        $o = $start;
        $lmD = $field(24, $o); $o += 24;
        $ntD = $field(24, $o); $o += 24;
        $dD = $field(strlen($d), $o); $o += strlen($d);
        $uD = $field(strlen($u), $o); $o += strlen($u);
        $wD = $field(strlen($w), $o);
        $msg = "NTLMSSP\x00" . pack('V', 3)
            . $lmD . $ntD . $dD . $uD . $wD . $field(0, $o)
            . pack('V', 0x00000001)
            . str_repeat("\x00", 24) . $nt . $d . $u . $w;

        $parsed = RdpServer::parseNtlmAuthenticate($msg);
        self::assertNotNull($parsed);
        self::assertSame('jdoe', $parsed['username']);
        self::assertSame('CORP', $parsed['domain']);
        self::assertSame('WS7', $parsed['workstation']);
        self::assertSame(str_repeat('11', 24), $parsed['nt_response']);
    }

    public function test_config_from_env_selects_protocol(): void
    {
        putenv('FUNNYPOT_RDP_SELECT=hybrid');
        self::assertSame(RdpConfig::PROTOCOL_HYBRID, RdpConfig::fromEnv()->selectedProtocol);

        putenv('FUNNYPOT_RDP_SELECT');
        self::assertSame(RdpConfig::PROTOCOL_RDP, RdpConfig::fromEnv()->selectedProtocol);
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

<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Rdp;

use Funnypot\Protocol\Rdp\RdpConfig;
use Funnypot\Protocol\Rdp\RdpServer;
use Funnypot\Protocol\Rdp\RdpSession;
use PHPUnit\Framework\TestCase;

final class RdpHandshakeTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?RdpConfig $config = null): RdpServer
    {
        $this->events = [];

        return new RdpServer($config ?? new RdpConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    private static function tpkt(string $payload): string
    {
        return "\x03\x00" . pack('n', strlen($payload) + 4) . $payload;
    }

    private static function x224Data(string $mcs): string
    {
        return self::tpkt("\x02\xf0\x80" . $mcs);
    }

    private static function connectionRequest(string $variable, int $srcRef = 0x1234): string
    {
        $x224 = chr(6 + strlen($variable)) . "\xe0\x00\x00" . pack('n', $srcRef) . "\x00" . $variable;

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

    public function test_connection_request_parses_mstshash_and_requested_protocols(): void
    {
        $variable = "Cookie: mstshash=Administrator\r\n"
            . self::negReq(RdpConfig::PROTOCOL_SSL | RdpConfig::PROTOCOL_HYBRID);

        $server = $this->newServer();
        $session = new RdpSession('203.0.113.9', 51000, 1);
        $session->inbuf .= self::connectionRequest($variable);
        $server->processInbound($session);

        self::assertSame('Administrator', $session->mstshash);
        self::assertSame(RdpConfig::PROTOCOL_SSL | RdpConfig::PROTOCOL_HYBRID, $session->requestedProtocols);
        self::assertTrue($session->sawNegotiationRequest);
        self::assertSame(RdpSession::STATE_MCS, $session->state);
    }

    public function test_connection_confirm_selects_standard_rdp_security(): void
    {
        $server = $this->newServer();
        $session = new RdpSession('203.0.113.9', 51000, 1);
        $session->inbuf .= self::connectionRequest(self::negReq(RdpConfig::PROTOCOL_HYBRID), 0x1234);
        $server->processInbound($session);

        $cc = $session->outbuf;

        // TPKT header: version 0x03, length 19.
        self::assertSame(0x03, ord($cc[0]));
        self::assertSame(19, (ord($cc[2]) << 8) | ord($cc[3]));
        self::assertSame(19, strlen($cc));

        // X.224 Connection Confirm: LI 0x0e, code 0xd0, DST-REF echoes the client SRC-REF.
        self::assertSame(0x0e, ord($cc[4]));
        self::assertSame(0xd0, ord($cc[5]));
        self::assertSame(0x1234, unpack('n', substr($cc, 6, 2))[1]);

        // RDP Negotiation Response: type 0x02, length 8, selectedProtocol = PROTOCOL_RDP (0).
        self::assertSame(0x02, ord($cc[11]));
        self::assertSame(8, unpack('v', substr($cc, 13, 2))[1]);
        self::assertSame(RdpConfig::PROTOCOL_RDP, unpack('V', substr($cc, 15, 4))[1]);
    }

    public function test_bare_connection_request_gets_confirm_without_negotiation_response(): void
    {
        // A client that sends no RDP Negotiation Request must still receive a valid Connection
        // Confirm — a bare one (LI 0x06, no negotiation response).
        $server = $this->newServer();
        $session = new RdpSession('198.51.100.1', 4000, 1);
        $session->inbuf .= self::connectionRequest('');
        $server->processInbound($session);

        $cc = $session->outbuf;
        self::assertSame(11, strlen($cc));
        self::assertSame(0x06, ord($cc[4]));
        self::assertSame(0xd0, ord($cc[5]));
        self::assertFalse($session->sawNegotiationRequest);
        self::assertSame(RdpSession::STATE_MCS, $session->state);
    }

    public function test_full_sequence_captures_cleartext_client_info_credential(): void
    {
        $server = $this->newServer();
        $session = new RdpSession('203.0.113.9', 51000, 1);

        // X.224 Connection Request -> Connection Confirm.
        $session->inbuf .= self::connectionRequest(
            "Cookie: mstshash=svc-admin\r\n" . self::negReq(RdpConfig::PROTOCOL_RDP)
        );
        $server->processInbound($session);
        $session->outbuf = '';

        // MCS Connect Initial -> Connect Response (framed as a valid TPKT).
        $session->inbuf .= self::x224Data("\x7f\x65" . str_repeat("\x00", 40));
        $server->processInbound($session);
        $mcr = $session->outbuf;
        $session->outbuf = '';
        self::assertSame((ord($mcr[2]) << 8) | ord($mcr[3]), strlen($mcr), 'Connect Response TPKT length must match');
        self::assertSame("\x7f\x66", substr($mcr, 7, 2), 'MCS Connect-Response BER tag');

        // Erect Domain Request -> no reply.
        $session->inbuf .= self::x224Data("\x04\x01\x00\x01\x00\x01");
        $server->processInbound($session);
        self::assertSame('', $session->outbuf);

        // Attach User Request -> Attach User Confirm assigning the user channel.
        $session->inbuf .= self::x224Data("\x28");
        $server->processInbound($session);
        $auc = $session->outbuf;
        $session->outbuf = '';
        $userChannel = 1001 + unpack('n', substr($auc, 9, 2))[1];
        self::assertSame(1007, $userChannel);

        // Channel Join Requests -> Channel Join Confirms echoing the joined channel.
        foreach ([$userChannel, 1003] as $channel) {
            $session->inbuf .= self::x224Data("\x38" . pack('n', $userChannel - 1001) . pack('n', $channel));
            $server->processInbound($session);
            $cjc = $session->outbuf;
            $session->outbuf = '';
            self::assertSame($channel, unpack('n', substr($cjc, -2))[1]);
        }

        // Client Info PDU -> credential captured, connection finished.
        $session->inbuf .= self::x224Data(self::sendDataClientInfo('CORP', 'bob', 'P@ssw0rd!'));
        $server->processInbound($session);

        $cred = $this->eventOfType('rdp_cred');
        self::assertNotNull($cred);
        self::assertStringContainsString('CORP\\bob', $cred['path']);
        self::assertStringContainsString('password=P@ssw0rd!', $cred['body']);
        self::assertTrue($session->close);
    }

    public function test_ntlmssp_authenticate_over_the_wire_is_captured(): void
    {
        // Some tools leak CredSSP/NTLM in the clear; an AUTHENTICATE message inside any post-
        // negotiation PDU must be harvested (username/domain/workstation + NTLMv2 response).
        $server = $this->newServer();
        $session = new RdpSession('192.0.2.50', 60000, 1);
        $session->inbuf .= self::connectionRequest(self::negReq(RdpConfig::PROTOCOL_HYBRID));
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::x224Data(self::ntlmAuthenticate('WORKGROUP', 'alice', 'DESKTOP1'));
        $server->processInbound($session);

        $cred = $this->eventOfType('rdp_cred');
        self::assertNotNull($cred);
        self::assertStringContainsString('WORKGROUP\\alice', $cred['path']);
        self::assertStringContainsString('workstation=DESKTOP1', $cred['body']);
        self::assertStringContainsString('nt_response=', $cred['body']);
        self::assertTrue($session->close);
    }

    public function test_non_tpkt_input_closes_cleanly(): void
    {
        // An NLA-only client that opens with a TLS ClientHello (0x16) is unmodelled: log and drop,
        // never crash.
        $server = $this->newServer();
        $session = new RdpSession('192.0.2.1', 5000, 1);
        $session->inbuf .= "\x16\x03\x01\x00\x50" . str_repeat("\x00", 80);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('rdp_unknown'));
    }

    public function test_partial_pdu_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new RdpSession('192.0.2.2', 5001, 1);

        $cr = self::connectionRequest("Cookie: mstshash=partial\r\n" . self::negReq(RdpConfig::PROTOCOL_RDP));
        // Feed the TPKT header and a fragment first: nothing should be parsed yet.
        $session->inbuf .= substr($cr, 0, 6);
        $server->processInbound($session);
        self::assertNull($session->mstshash);
        self::assertSame(RdpSession::STATE_WAIT_CONNECTION_REQUEST, $session->state);

        // Deliver the remainder: the request now parses.
        $session->inbuf .= substr($cr, 6);
        $server->processInbound($session);
        self::assertSame('partial', $session->mstshash);
    }

    private static function sendDataClientInfo(string $domain, string $user, string $pass): string
    {
        $d = self::u16($domain);
        $u = self::u16($user);
        $p = self::u16($pass);
        $info = pack('V', 0)          // codePage
            . pack('V', 0x10)         // flags: INFO_UNICODE
            . pack('v', strlen($d))
            . pack('v', strlen($u))
            . pack('v', strlen($p))
            . pack('v', 0)            // cbAlternateShell
            . pack('v', 0)            // cbWorkingDir
            . $d . "\x00\x00"
            . $u . "\x00\x00"
            . $p . "\x00\x00"
            . "\x00\x00" . "\x00\x00"; // AlternateShell + WorkingDir terminators
        $userData = pack('v', 0x0040) . pack('v', 0) . $info; // SEC_INFO_PKT basic security header

        return "\x64" . pack('n', 6) . pack('n', 1003) . "\x70" . chr(strlen($userData)) . $userData;
    }

    private static function ntlmAuthenticate(string $domain, string $user, string $workstation): string
    {
        $d = self::u16($domain);
        $u = self::u16($user);
        $w = self::u16($workstation);
        $lm = str_repeat("\x00", 24);
        $nt = str_repeat("\xAB", 24);

        $field = static fn (int $len, int $off): string => pack('v', $len) . pack('v', $len) . pack('V', $off);
        $start = 64;
        $o = $start;
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

<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Smb;

use Funnypot\Protocol\Smb\SmbConfig;
use Funnypot\Protocol\Smb\SmbServer;
use Funnypot\Protocol\Smb\SmbSession;
use PHPUnit\Framework\TestCase;

final class SmbHandshakeTest extends TestCase
{
    use SmbTestFrames;

    /** Strips the 4-byte NetBIOS header, returning the SMB2 message. */
    private static function unwrapNbss(string $frame): string
    {
        $len = (ord($frame[1]) << 16) | (ord($frame[2]) << 8) | ord($frame[3]);

        return substr($frame, 4, $len);
    }

    public function test_negotiate_is_parsed_and_answered(): void
    {
        $events = [];
        $logger = static function (array $e) use (&$events): void {
            $events[] = $e;
        };

        $config = new SmbConfig(domain: 'CORP', computerName: 'FILE01');
        $server = new SmbServer($config, $logger);
        $session = new SmbSession('192.0.2.10', 49555, 1);

        $guid = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00";
        $session->inbuf .= self::negotiateRequest([0x0202, 0x0210, 0x0300, 0x0311], $guid);
        $server->processInbound($session);

        // --- recon event: dialects + client GUID logged ---
        $neg = null;
        foreach ($events as $e) {
            if ($e['event'] === 'smb_negotiate') {
                $neg = $e;
            }
        }
        self::assertNotNull($neg);
        self::assertStringContainsString('0x0202', $neg['path']);
        self::assertStringContainsString('0x0311', $neg['path']);
        self::assertStringContainsString('11223344-5566-7788-99aa-bbccddeeff00', $neg['path']);

        // --- NEGOTIATE response bytes ---
        self::assertNotSame('', $session->outbuf);
        $msg = self::unwrapNbss($session->outbuf);

        self::assertSame("\xFESMB", substr($msg, 0, 4), 'SMB2 protocol id');
        // Header flags carry SERVER_TO_REDIR.
        $flags = unpack('V', substr($msg, 16, 4))[1];
        self::assertSame(1, $flags & 1);
        // Command is NEGOTIATE (0).
        self::assertSame(0, unpack('v', substr($msg, 12, 2))[1]);

        // Negotiate response body starts at 64. StructureSize must be 65.
        self::assertSame(65, unpack('v', substr($msg, 64, 2))[1]);
        // Chosen dialect: highest offered that is not 3.1.1 -> 0x0300.
        self::assertSame(0x0300, unpack('v', substr($msg, 68, 2))[1]);
        // SecurityMode: signing enabled.
        self::assertSame(1, unpack('v', substr($msg, 66, 2))[1] & 1);
        // Server GUID is the stable per-deploy value.
        self::assertSame($config->serverGuid(), substr($msg, 72, 16));
        // The security blob advertises NTLMSSP (its OID DER bytes appear in the SPNEGO token).
        $ntlmsspOid = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";
        self::assertStringContainsString($ntlmsspOid, $msg);

        self::assertSame(SmbSession::STATE_SESSION_SETUP, $session->state);
    }

    public function test_session_setup_emits_ntlm_challenge_with_8_byte_challenge(): void
    {
        $server = new SmbServer(new SmbConfig(), static fn () => null);
        $session = new SmbSession('192.0.2.11', 49556, 2);

        // Negotiate first so the server is in the session-setup state.
        $session->inbuf .= self::negotiateRequest([0x0210], str_repeat("\x00", 16));
        $server->processInbound($session);
        $session->outbuf = '';

        // SESSION_SETUP with an NTLMSSP NEGOTIATE -> expect a CHALLENGE.
        $session->inbuf .= self::sessionSetupRequest(self::ntlmNegotiate(), "\x02\x00\x00\x00\x00\x00\x00\x00");
        $server->processInbound($session);

        $msg = self::unwrapNbss($session->outbuf);

        // Status = STATUS_MORE_PROCESSING_REQUIRED (0xC0000016).
        self::assertSame(0xC0000016, unpack('V', substr($msg, 8, 4))[1]);

        // The response carries an NTLMSSP CHALLENGE (Type 2) with our 8-byte server challenge.
        $pos = strpos($msg, "NTLMSSP\x00");
        self::assertNotFalse($pos);
        $ntlm = substr($msg, $pos);
        self::assertSame(2, unpack('V', substr($ntlm, 8, 4))[1], 'NTLM message type CHALLENGE');

        $challenge = substr($ntlm, 24, 8);
        self::assertSame(8, strlen($challenge));
        self::assertSame($session->serverChallenge, $challenge);
        self::assertNotSame(str_repeat("\x00", 8), $session->serverChallenge, 'challenge must be random');
    }

    public function test_authenticate_is_captured_and_logon_denied(): void
    {
        $events = [];
        $logger = static function (array $e) use (&$events): void {
            $events[] = $e;
        };

        $server = new SmbServer(new SmbConfig(), $logger);
        $session = new SmbSession('192.0.2.12', 49557, 3);

        // Drive the flow to the challenge so a server challenge exists.
        $session->inbuf .= self::negotiateRequest([0x0210], str_repeat("\x00", 16));
        $server->processInbound($session);
        $session->inbuf .= self::sessionSetupRequest(self::ntlmNegotiate(), "\x02\x00\x00\x00\x00\x00\x00\x00");
        $server->processInbound($session);
        $session->outbuf = '';

        // Now the AUTHENTICATE with the harvestable material.
        $ntResp = random_bytes(48); // NTProofStr(16) + blob
        $auth = self::ntlmAuthenticate('administrator', 'ACME', 'DESKTOP-7F3K', $ntResp);
        $session->inbuf .= self::sessionSetupRequest($auth, "\x03\x00\x00\x00\x00\x00\x00\x00");
        $server->processInbound($session);

        // --- credential captured ---
        $cred = null;
        foreach ($events as $e) {
            if ($e['event'] === 'smb_cred') {
                $cred = $e;
            }
        }
        self::assertNotNull($cred);
        self::assertSame('administrator', $cred['user']);
        self::assertSame('ACME', $cred['domain']);
        self::assertSame('DESKTOP-7F3K', $cred['workstation']);
        self::assertSame(bin2hex($ntResp), $cred['ntlmv2']);
        self::assertSame(bin2hex($session->serverChallenge), $cred['server_challenge']);
        self::assertStringContainsString('administrator::ACME:', $cred['body']);
        self::assertSame('high', $cred['severity']);

        // --- logon denied, session never granted ---
        $msg = self::unwrapNbss($session->outbuf);
        self::assertSame(0xC000006D, unpack('V', substr($msg, 8, 4))[1], 'STATUS_LOGON_FAILURE');
        self::assertTrue($session->denied);
        self::assertSame(SmbSession::STATE_DONE, $session->state);
    }

    public function test_partial_netbios_frame_waits_for_rest(): void
    {
        $server = new SmbServer(new SmbConfig(), static fn () => null);
        $session = new SmbSession('192.0.2.13', 49558, 4);

        $full = self::negotiateRequest([0x0210], str_repeat("\x00", 16));

        // Feed only the first half: the server must buffer and emit nothing yet.
        $half = (int) (strlen($full) / 2);
        $session->inbuf .= substr($full, 0, $half);
        $server->processInbound($session);
        self::assertSame('', $session->outbuf);
        self::assertFalse($session->close);

        // Feed the remainder: now it answers.
        $session->inbuf .= substr($full, $half);
        $server->processInbound($session);
        self::assertNotSame('', $session->outbuf);
    }
}

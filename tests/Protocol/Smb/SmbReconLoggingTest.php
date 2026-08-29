<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Smb;

use Funnypot\Protocol\Smb\SmbConfig;
use Funnypot\Protocol\Smb\SmbServer;
use Funnypot\Protocol\Smb\SmbSession;
use PHPUnit\Framework\TestCase;

final class SmbReconLoggingTest extends TestCase
{
    use SmbTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function serverSession(): array
    {
        $this->events = [];
        $logger = function (array $e): void {
            $this->events[] = $e;
        };
        $server = new SmbServer(new SmbConfig(), $logger);
        $session = new SmbSession('198.51.100.9', 445, 1);

        return [$server, $session];
    }

    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }

    public function test_smb1_probe_is_logged_and_closed(): void
    {
        [$server, $session] = $this->serverSession();

        // SMB1 COM_NEGOTIATE: header 0xFF 'S' 'M' 'B', command 0x72.
        $smb1 = "\xFFSMB" . chr(0x72) . str_repeat("\x00", 28);
        $session->inbuf .= self::nbss($smb1);
        $server->processInbound($session);

        $probe = $this->eventOfType('smb1_probe');
        self::assertNotNull($probe);
        self::assertSame('smb', $probe['proto']);
        self::assertTrue($session->close);
    }

    public function test_unmodelled_command_is_logged_as_unknown(): void
    {
        [$server, $session] = $this->serverSession();

        // A valid SMB2 header but an unmodelled command (TREE_CONNECT = 0x0003).
        $frame = self::smb2ReqHeader(0x0003, "\x05\x00\x00\x00\x00\x00\x00\x00");
        $session->inbuf .= self::nbss($frame);
        $server->processInbound($session);

        $unknown = $this->eventOfType('smb_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('0x0003', $unknown['path']);
        self::assertTrue($session->close);
    }

    public function test_non_smb_frame_is_logged_as_unknown(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::nbss("GARBAGE-not-smb-at-all");
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('smb_unknown'));
        self::assertTrue($session->close);
    }

    public function test_session_setup_without_ntlmssp_is_unknown(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::negotiateRequest([0x0210], str_repeat("\x00", 16));
        $server->processInbound($session);
        $session->outbuf = '';

        // SESSION_SETUP whose security buffer is not NTLMSSP (e.g. raw Kerberos).
        $session->inbuf .= self::sessionSetupRequest("\x60\x82\x00\x00kerberos", "\x02\x00\x00\x00\x00\x00\x00\x00");
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('smb_unknown'));
        self::assertTrue($session->close);
    }

    public function test_negotiate_logs_all_offered_dialects(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::negotiateRequest([0x0202, 0x0210], str_repeat("\x01", 16));
        $server->processInbound($session);

        $neg = $this->eventOfType('smb_negotiate');
        self::assertNotNull($neg);
        self::assertStringContainsString('0x0202', $neg['path']);
        self::assertStringContainsString('0x0210', $neg['path']);
        self::assertStringContainsString('01010101-0101-0101-0101-010101010101', $neg['path']);
        self::assertSame('smb', $neg['proto']);
        self::assertSame('SMB', $neg['method']);
    }
}

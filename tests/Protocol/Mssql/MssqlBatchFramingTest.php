<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlServer;
use Funnypot\Protocol\Mssql\MssqlSession;
use PHPUnit\Framework\TestCase;

/**
 * TDS message framing in SESSION mode: ALL_HEADERS stripping, the no-headers fallback, multi-packet
 * EOM reassembly, and the reassembly cap.
 */
final class MssqlBatchFramingTest extends TestCase
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
        $session = new MssqlSession('198.51.100.9', 1433, 1);
        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);
        $session->inbuf .= self::login7Request('PC', 'sa', 'sa', 'sqlcmd', 'ODBC', 'master');
        $server->processInbound($session);
        $session->outbuf = '';

        return [$server, $session];
    }

    public function test_all_headers_block_is_stripped(): void
    {
        [$server, $session] = $this->authed();

        $session->inbuf .= self::sqlBatch('SELECT @@version', true);
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertSame(0x81, ord($body[0]), 'the SQL parsed correctly with the header block present');
        self::assertStringContainsString(self::u16le('Microsoft SQL Server 2019'), $body);
    }

    public function test_batch_without_header_block_still_parses(): void
    {
        [$server, $session] = $this->authed();

        // Some clients omit ALL_HEADERS: the leading DWORD is not a plausible header length.
        $session->inbuf .= self::sqlBatch('SELECT @@version', false);
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertStringContainsString(self::u16le('Microsoft SQL Server 2019'), $body);
    }

    public function test_multi_packet_batch_is_reassembled_until_eom(): void
    {
        [$server, $session] = $this->authed();

        // Build one SQLBATCH body, then split it across two packets: the first NOT end-of-message.
        $full = self::sqlBatch("EXEC xp_cmdshell 'whoami'");
        $fullBody = self::tdsBody($full);
        $half = intdiv(strlen($fullBody), 2);

        $p1 = self::tdsPacketStatus(0x01, substr($fullBody, 0, $half), 0x00); // EOM clear
        $p2 = self::tdsPacketStatus(0x01, substr($fullBody, $half), 0x01);    // EOM set

        $session->inbuf .= $p1;
        $server->processInbound($session);
        self::assertSame('', $session->outbuf, 'nothing is answered until EOM arrives');

        $session->inbuf .= $p2;
        $server->processInbound($session);

        $body = self::tdsBody($session->outbuf);
        self::assertStringContainsString(self::u16le('nt authority\\system'), $body, 'the reassembled batch ran');
        $rce = null;
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === 'mssql_rce_attempt') {
                $rce = $e;
            }
        }
        self::assertNotNull($rce);
    }

    public function test_reassembly_over_cap_closes(): void
    {
        [$server, $session] = $this->authed();

        // A never-ending non-EOM stream must be bounded: feed continuation packets past the cap.
        $chunk = str_repeat('A', 16384);
        for ($i = 0; $i < 20 && !$session->close; $i++) {
            $session->inbuf .= self::tdsPacketStatus(0x01, $chunk, 0x00); // never EOM
            $server->processInbound($session);
        }

        self::assertTrue($session->close, 'the reassembly buffer cap closes the connection');
    }
}

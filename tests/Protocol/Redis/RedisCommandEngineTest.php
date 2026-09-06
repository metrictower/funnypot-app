<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Redis\RedisConfig;
use Funnypot\Protocol\Redis\RedisSession;
use Funnypot\Protocol\RespEncoder;
use Funnypot\Protocol\RespReply;
use PHPUnit\Framework\TestCase;

/**
 * The Redis 6.2 command surface: correct reply types, arity/type errors, and state transitions for
 * connection, discovery, string, key, expiry, CONFIG, persistence and replication commands.
 */
final class RedisCommandEngineTest extends TestCase
{
    use RedisTestFrames;

    private function session(?RedisConfig $config = null): RedisSession
    {
        return new RedisSession($config ?? $this->redisConfig(), 5);
    }

    public function test_ping_echo_quit(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame("+PONG\r\n", $this->wire($e, $s, ['PING']));
        self::assertSame("\$5\r\nhello\r\n", $this->wire($e, $s, ['PING', 'hello']));
        self::assertSame("\$3\r\nabc\r\n", $this->wire($e, $s, ['ECHO', 'abc']));
        self::assertSame("+OK\r\n", $this->wire($e, $s, ['QUIT']));
        self::assertTrue($s->close);
    }

    public function test_hello_negotiates_protocol(): void
    {
        $e = $this->engine();
        $s = $this->session();
        $this->cmd($e, $s, ['HELLO', '3']);
        self::assertSame(3, $s->respVersion);
        $reply = $this->cmd($e, $s, ['HELLO', '2']);
        self::assertSame(2, $s->respVersion);
        self::assertSame(RespReply::MAP, $reply->type);
        $bad = $this->cmd($e, $s, ['HELLO', '9']);
        self::assertSame(RespReply::ERROR, $bad->type);
        self::assertStringContainsString('NOPROTO', (string) $bad->scalar);
    }

    public function test_auth_on_nopass_returns_authentic_error(): void
    {
        $e = $this->engine();
        $s = $this->session();
        $reply = $this->cmd($e, $s, ['AUTH', 'hunter2']);
        self::assertSame(RespReply::ERROR, $reply->type);
        self::assertStringContainsString('no password is set', (string) $reply->scalar);
    }

    public function test_select_range(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame('OK', $this->cmd($e, $s, ['SELECT', '3'])->scalar);
        self::assertSame(3, $s->db);
        self::assertStringContainsString('out of range', (string) $this->cmd($e, $s, ['SELECT', '99'])->scalar);
        self::assertStringContainsString('not an integer', (string) $this->cmd($e, $s, ['SELECT', 'x'])->scalar);
    }

    public function test_client_id_setname_getname(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame(5, $this->cmd($e, $s, ['CLIENT', 'ID'])->scalar);
        self::assertSame('OK', $this->cmd($e, $s, ['CLIENT', 'SETNAME', 'app1'])->scalar);
        self::assertSame('app1', $this->cmd($e, $s, ['CLIENT', 'GETNAME'])->scalar);
        // Names with spaces/control chars are rejected exactly as Redis does.
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['CLIENT', 'SETNAME', 'a b'])->type);
    }

    public function test_set_get_and_missing(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame('OK', $this->cmd($e, $s, ['SET', 'k', 'v'])->scalar);
        self::assertSame('v', $this->cmd($e, $s, ['GET', 'k'])->scalar);
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $s, ['GET', 'absent'])->type);
    }

    public function test_set_nx_xx_and_expiry(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $s, ['SET', 'k', 'v', 'XX'])->type); // absent
        self::assertSame('OK', $this->cmd($e, $s, ['SET', 'k', 'v', 'NX'])->scalar);
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $s, ['SET', 'k', 'v2', 'NX'])->type); // exists
        self::assertSame('OK', $this->cmd($e, $s, ['SET', 'k', 'v3', 'EX', '100'])->scalar);
        self::assertSame(100, $this->cmd($e, $s, ['TTL', 'k'])->scalar);
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['SET', 'k', 'v', 'EX', '0'])->type);
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['SET', 'k', 'v', 'BOGUS'])->type);
    }

    public function test_mget_mset(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame('OK', $this->cmd($e, $s, ['MSET', 'a', '1', 'b', '2'])->scalar);
        $reply = $this->cmd($e, $s, ['MGET', 'a', 'b', 'missing']);
        self::assertSame(RespReply::ARR, $reply->type);
        self::assertSame('1', $reply->items[0]->scalar);
        self::assertSame('2', $reply->items[1]->scalar);
        self::assertSame(RespReply::NULL_BULK, $reply->items[2]->type);
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['MSET', 'a', '1', 'b'])->type); // odd args
    }

    public function test_del_exists_type(): void
    {
        $e = $this->engine();
        $s = $this->session();
        $this->cmd($e, $s, ['SET', 'k', 'v']);
        self::assertSame('string', $this->cmd($e, $s, ['TYPE', 'k'])->scalar);
        self::assertSame('none', $this->cmd($e, $s, ['TYPE', 'absent'])->scalar);
        self::assertSame(1, $this->cmd($e, $s, ['EXISTS', 'k', 'absent'])->scalar);
        self::assertSame(1, $this->cmd($e, $s, ['DEL', 'k', 'absent'])->scalar);
        self::assertSame(0, $this->cmd($e, $s, ['EXISTS', 'k'])->scalar);
    }

    public function test_ttl_pttl_expire_persist(): void
    {
        $e = $this->engine();
        $s = $this->session();
        $this->cmd($e, $s, ['SET', 'k', 'v']);
        self::assertSame(-1, $this->cmd($e, $s, ['TTL', 'k'])->scalar);  // no expiry
        self::assertSame(-2, $this->cmd($e, $s, ['TTL', 'absent'])->scalar); // no key
        self::assertSame(1, $this->cmd($e, $s, ['EXPIRE', 'k', '50'])->scalar);
        self::assertSame(50, $this->cmd($e, $s, ['TTL', 'k'])->scalar);
        self::assertSame(1, $this->cmd($e, $s, ['PERSIST', 'k'])->scalar);
        self::assertSame(-1, $this->cmd($e, $s, ['TTL', 'k'])->scalar);
        self::assertSame(0, $this->cmd($e, $s, ['EXPIRE', 'absent', '50'])->scalar);
    }

    public function test_keys_and_scan(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 5);
        $s->store->flushall();
        foreach (['user:1', 'user:2', 'post:1'] as $k) {
            $this->cmd($e, $s, ['SET', $k, 'x']);
        }
        $keys = $this->cmd($e, $s, ['KEYS', 'user:*']);
        $names = array_map(static fn ($r) => $r->scalar, $keys->items);
        sort($names);
        self::assertSame(['user:1', 'user:2'], $names);

        $scan = $this->cmd($e, $s, ['SCAN', '0', 'MATCH', '*', 'COUNT', '100']);
        self::assertSame(RespReply::ARR, $scan->type);
        self::assertSame('0', $scan->items[0]->scalar); // fully iterated -> cursor 0
        self::assertCount(3, $scan->items[1]->items);
        // Unknown option is a syntax error.
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['SCAN', '0', 'BOGUS'])->type);
        // Non-numeric cursor is an invalid cursor.
        self::assertStringContainsString('invalid cursor', (string) $this->cmd($e, $s, ['SCAN', 'x'])->scalar);
    }

    public function test_dbsize_and_flush(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 5);
        $base = $this->cmd($e, $s, ['DBSIZE'])->scalar;
        self::assertGreaterThan(0, $base);
        self::assertSame('OK', $this->cmd($e, $s, ['FLUSHDB'])->scalar);
        self::assertSame(0, $this->cmd($e, $s, ['DBSIZE'])->scalar);
    }

    public function test_config_get_returns_only_matching_params(): void
    {
        $e = $this->engine();
        $s = $this->session();
        $reply = $this->cmd($e, $s, ['CONFIG', 'GET', 'dir']);
        self::assertSame(RespReply::MAP, $reply->type);
        self::assertCount(1, $reply->pairs);
        self::assertSame('dir', $reply->pairs[0][0]->scalar);
        self::assertSame('/var/lib/redis', $reply->pairs[0][1]->scalar);
        // A wildcard returns the whole fixed set.
        $all = $this->cmd($e, $s, ['CONFIG', 'GET', '*']);
        self::assertGreaterThanOrEqual(9, count($all->pairs));
    }

    public function test_config_set_only_dir_and_dbfilename(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame('OK', $this->cmd($e, $s, ['CONFIG', 'SET', 'dir', '/tmp'])->scalar);
        self::assertSame('/tmp', $s->dir);
        self::assertSame('OK', $this->cmd($e, $s, ['CONFIG', 'SET', 'dbfilename', 'out.rdb'])->scalar);
        $err = $this->cmd($e, $s, ['CONFIG', 'SET', 'maxmemory', '100mb']);
        self::assertSame(RespReply::ERROR, $err->type);
        self::assertStringContainsString("CONFIG SET - 'maxmemory'", (string) $err->scalar);
    }

    public function test_save_bgsave_lastsave(): void
    {
        $now = 1_700_000_500;
        $config = $this->redisConfig(42, function () use (&$now): int { return $now; });
        $e = $this->engine($config);
        $s = new RedisSession($config, 5);
        self::assertSame('OK', $this->cmd($e, $s, ['SAVE'])->scalar);
        self::assertSame($now, $this->cmd($e, $s, ['LASTSAVE'])->scalar);
        self::assertSame('Background saving started', $this->cmd($e, $s, ['BGSAVE'])->scalar);
        self::assertTrue($s->bgsaveInProgress);
        // A second BGSAVE while one is in progress is refused.
        self::assertStringContainsString('already in progress', (string) $this->cmd($e, $s, ['BGSAVE'])->scalar);
        // After the injected-clock deadline passes, the next command completes it.
        $now += RedisConfig::BGSAVE_DEADLINE + 1;
        $this->cmd($e, $s, ['PING']);
        self::assertFalse($s->bgsaveInProgress);
    }

    public function test_role_and_replicaof_read_only(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame('master', $this->cmd($e, $s, ['ROLE'])->items[0]->scalar);
        self::assertSame('OK', $this->cmd($e, $s, ['REPLICAOF', '10.0.0.9', '6379'])->scalar);
        self::assertSame('slave', $s->role);
        self::assertSame('slave', $this->cmd($e, $s, ['ROLE'])->items[0]->scalar);
        // Writes are rejected with the exact READONLY error while a replica.
        $w = $this->cmd($e, $s, ['SET', 'k', 'v']);
        self::assertSame(RespReply::ERROR, $w->type);
        self::assertStringContainsString('READONLY', (string) $w->scalar);
        // Reads still work.
        self::assertContains($this->cmd($e, $s, ['GET', 'k'])->type, [RespReply::NULL_BULK, RespReply::BULK]);
        // REPLICAOF NO ONE restores primary + writes.
        self::assertSame('OK', $this->cmd($e, $s, ['REPLICAOF', 'NO', 'ONE'])->scalar);
        self::assertSame('master', $s->role);
        self::assertSame('OK', $this->cmd($e, $s, ['SET', 'k', 'v'])->scalar);
    }

    public function test_module_list_and_load(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame(RespReply::ARR, $this->cmd($e, $s, ['MODULE', 'LIST'])->type);
        $load = $this->cmd($e, $s, ['MODULE', 'LOAD', '/tmp/exp.so']);
        self::assertSame(RespReply::ERROR, $load->type);
        self::assertStringContainsString('Error loading the extension', (string) $load->scalar);
    }

    public function test_command_count_and_info(): void
    {
        $e = $this->engine();
        $s = $this->session();
        self::assertSame(RespReply::INT, $this->cmd($e, $s, ['COMMAND', 'COUNT'])->type);
        $info = $this->cmd($e, $s, ['COMMAND', 'INFO', 'get', 'nope']);
        self::assertSame(RespReply::ARR, $info->type);
        self::assertSame(RespReply::ARR, $info->items[0]->type); // known command spec
        self::assertSame(RespReply::NULL_ARRAY, $info->items[1]->type); // unknown -> null
    }

    public function test_info_reports_version_and_keyspace(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 5);
        $dbsize = $this->cmd($e, $s, ['DBSIZE'])->scalar;
        $info = (string) $this->cmd($e, $s, ['INFO'])->scalar;
        self::assertStringContainsString('redis_version:' . RedisConfig::VERSION, $info);
        self::assertStringContainsString("db0:keys={$dbsize},", $info);
        self::assertStringNotContainsString('7.2', $info);
    }

    public function test_time(): void
    {
        $e = $this->engine();
        $s = $this->session();
        $reply = $this->cmd($e, $s, ['TIME']);
        self::assertSame(RespReply::ARR, $reply->type);
        self::assertSame((string) $this->fixedNow, $reply->items[0]->scalar);
    }

    public function test_unknown_command_and_arity_errors(): void
    {
        $e = $this->engine();
        $s = $this->session();
        $unk = $this->cmd($e, $s, ['LOLWUT', 'x']);
        self::assertSame(RespReply::ERROR, $unk->type);
        self::assertStringContainsString("unknown command 'LOLWUT'", (string) $unk->scalar);
        $arity = $this->cmd($e, $s, ['GET']);
        self::assertStringContainsString("wrong number of arguments for 'get'", (string) $arity->scalar);
    }

    public function test_keys_pattern_length_and_budget_bounded(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 5);
        // Over-long glob is rejected before scanning.
        $long = str_repeat('a', RedisConfig::MAX_GLOB_BYTES + 1);
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['KEYS', $long])->type);
        // Fill many long keys and hit an adversarial alternating-star pattern; must fail bounded, not hang.
        $s->store->flushall();
        for ($i = 0; $i < RedisConfig::MAX_KEYS; $i++) {
            $s->store->set(0, str_repeat('k', 200) . $i, 'x', 0);
        }
        $pattern = str_repeat('*a', 60); // 120 bytes, pathological
        $reply = $this->cmd($e, $s, ['KEYS', $pattern]);
        // Either a bounded empty/complete result or the fixed too-complex error — never a hang or crash.
        self::assertContains($reply->type, [RespReply::ARR, RespReply::ERROR]);
    }
}

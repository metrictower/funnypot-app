<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Redis\RedisConfig;
use Funnypot\Protocol\Redis\RedisSession;
use Funnypot\Protocol\RespReply;
use PHPUnit\Framework\TestCase;

/**
 * Per-connection state isolation and the atomic memory caps: one attacker never sees another's data,
 * each new session gets a clean seeded copy, the 16 DBs are independent, and MSET/SET fail atomically
 * at the key-count / value-size / aggregate-byte caps without a partial mutation.
 */
final class RedisSessionIsolationTest extends TestCase
{
    use RedisTestFrames;

    public function test_two_sessions_do_not_share_writes(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $a = new RedisSession($config, 1);
        $b = new RedisSession($config, 2);
        $this->cmd($e, $a, ['SET', 'secret', 'in-a']);
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $b, ['GET', 'secret'])->type);
        self::assertSame('in-a', $this->cmd($e, $a, ['GET', 'secret'])->scalar);
    }

    public function test_new_session_starts_from_clean_base(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $a = new RedisSession($config, 1);
        $this->cmd($e, $a, ['FLUSHALL']);
        self::assertSame(0, $this->cmd($e, $a, ['DBSIZE'])->scalar);
        // A fresh connection sees the seeded base again — a reconnect resets the lure.
        $b = new RedisSession($config, 2);
        self::assertGreaterThan(0, $this->cmd($e, $b, ['DBSIZE'])->scalar);
    }

    public function test_dbs_are_isolated(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $this->cmd($e, $s, ['SELECT', '1']);
        $this->cmd($e, $s, ['SET', 'k', 'db1']);
        $this->cmd($e, $s, ['SELECT', '2']);
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $s, ['GET', 'k'])->type);
        $this->cmd($e, $s, ['SELECT', '1']);
        self::assertSame('db1', $this->cmd($e, $s, ['GET', 'k'])->scalar);
    }

    public function test_key_count_cap_is_enforced_and_atomic(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $s->store->flushall();
        for ($i = 0; $i < RedisConfig::MAX_KEYS; $i++) {
            self::assertSame('OK', $this->cmd($e, $s, ['SET', 'k' . $i, 'v'])->scalar);
        }
        // The next new key is refused with OOM; the store is unchanged.
        $over = $this->cmd($e, $s, ['SET', 'one-too-many', 'v']);
        self::assertSame(RespReply::ERROR, $over->type);
        self::assertStringContainsString('OOM', (string) $over->scalar);
        self::assertSame(RedisConfig::MAX_KEYS, $this->cmd($e, $s, ['DBSIZE'])->scalar);
    }

    public function test_mset_over_cap_is_all_or_nothing(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $s->store->flushall();
        // Fill to one below the cap, then MSET two new keys — the whole MSET must be rejected.
        for ($i = 0; $i < RedisConfig::MAX_KEYS - 1; $i++) {
            $this->cmd($e, $s, ['SET', 'k' . $i, 'v']);
        }
        $reply = $this->cmd($e, $s, ['MSET', 'new1', 'a', 'new2', 'b']);
        self::assertSame(RespReply::ERROR, $reply->type);
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $s, ['GET', 'new1'])->type, 'no partial mutation');
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $s, ['GET', 'new2'])->type);
    }

    public function test_value_size_cap(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $big = str_repeat('Z', RedisConfig::MAX_VALUE_BYTES + 1);
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['SET', 'k', $big])->type);
    }

    public function test_aggregate_byte_cap(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $s->store->flushall();
        $chunk = str_repeat('Z', RedisConfig::MAX_VALUE_BYTES);
        $accepted = 0;
        for ($i = 0; $i < RedisConfig::MAX_KEYS; $i++) {
            if ($this->cmd($e, $s, ['SET', 'k' . $i, $chunk])->type === RespReply::SIMPLE) {
                $accepted++;
            }
        }
        // 256 KiB aggregate / 16 KiB per value ⇒ far fewer than 128 keys fit; the cap bites first.
        self::assertLessThan(RedisConfig::MAX_KEYS, $accepted);
        self::assertLessThanOrEqual(RedisConfig::MAX_AGGREGATE_BYTES, $s->store->byteCount());
    }

    public function test_lazy_expiry(): void
    {
        $now = 1_700_000_000;
        $config = $this->redisConfig(42, function () use (&$now): int { return $now; });
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $this->cmd($e, $s, ['SET', 'k', 'v', 'PX', '500']);
        self::assertSame('v', $this->cmd($e, $s, ['GET', 'k'])->scalar);
        $now += 1; // +1000 ms, past the 500 ms expiry
        self::assertSame(RespReply::NULL_BULK, $this->cmd($e, $s, ['GET', 'k'])->type);
    }

    public function test_client_name_metadata_cap(): void
    {
        $config = $this->redisConfig();
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $tooLong = str_repeat('n', RedisConfig::MAX_CLIENT_NAME + 1);
        self::assertSame(RespReply::ERROR, $this->cmd($e, $s, ['CLIENT', 'SETNAME', $tooLong])->type);
        self::assertSame('', $s->clientName);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Redis\RedisConfig;
use Funnypot\Protocol\Redis\RedisSession;
use PHPUnit\Framework\TestCase;

/**
 * The persona is one coherent, stable Redis 6.2.24 misconfiguration: it advertises 6.2.24 (never a
 * hardened 7.x), a nopass/protected-mode-off/public config, a stable run id and base keyspace derived
 * only from the deploy seed (never from the attacker), and INFO facts that agree with each other.
 */
final class RedisPersonaTest extends TestCase
{
    use RedisTestFrames;

    private function info(int $seed, string $section = 'default'): string
    {
        $config = $this->redisConfig($seed);
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);

        return (string) $this->cmd($e, $s, ['INFO', $section])->scalar;
    }

    public function test_advertises_only_6_2_24(): void
    {
        $info = $this->info(42);
        self::assertStringContainsString('redis_version:' . RedisConfig::VERSION, $info);
        self::assertSame('6.2.24', RedisConfig::VERSION);
        self::assertStringNotContainsString('7.2', $info);
        self::assertStringNotContainsString('redis_version:7', $info);
    }

    public function test_run_id_is_40_hex_and_stable_per_seed(): void
    {
        $a = $this->redisConfig(42)->runId();
        $b = $this->redisConfig(42)->runId();
        $c = $this->redisConfig(43)->runId();
        self::assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $a);
        self::assertSame($a, $b, 'same deploy seed ⇒ same run id');
        self::assertNotSame($a, $c, 'a different deploy seed varies the run id');
    }

    public function test_persona_stable_across_reconnects(): void
    {
        // A reconnect (new session, same config) sees the identical run id and base keyspace.
        $config = $this->redisConfig(99);
        $s1 = new RedisSession($config, 1);
        $s2 = new RedisSession($config, 2);
        $e = $this->engine($config);
        self::assertSame(
            (string) $this->cmd($e, $s1, ['INFO', 'server'])->scalar,
            (string) $this->cmd($e, $s2, ['INFO', 'server'])->scalar
        );
        self::assertSame(
            $this->cmd($e, $s1, ['DBSIZE'])->scalar,
            $this->cmd($e, $s2, ['DBSIZE'])->scalar
        );
    }

    public function test_misconfiguration_is_coherent(): void
    {
        $config = $this->redisConfig(42);
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $get = function (string $p) use ($e, $s): string {
            $reply = $this->cmd($e, $s, ['CONFIG', 'GET', $p]);

            return (string) ($reply->pairs[0][1]->scalar ?? '');
        };
        self::assertSame('no', $get('protected-mode'));
        self::assertSame('', $get('requirepass'), 'nopass persona has an empty requirepass');
        self::assertSame('yes', $get('replica-read-only'));
    }

    public function test_info_keyspace_agrees_with_dbsize(): void
    {
        $config = $this->redisConfig(7);
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $this->cmd($e, $s, ['SET', 'extra', 'x']);
        $size = $this->cmd($e, $s, ['DBSIZE'])->scalar;
        $info = (string) $this->cmd($e, $s, ['INFO', 'keyspace'])->scalar;
        self::assertStringContainsString("db0:keys={$size},", $info);
    }

    public function test_run_id_not_keyed_by_attacker(): void
    {
        // Two connections from "different attackers" (client ids) on one deploy share one run id.
        $config = $this->redisConfig(55);
        $e = $this->engine($config);
        $s1 = new RedisSession($config, 111);
        $s1->peerIp = '203.0.113.1';
        $s2 = new RedisSession($config, 222);
        $s2->peerIp = '198.51.100.9';
        $rid = fn (RedisSession $s): string => (string) preg_replace('/.*run_id:([0-9a-f]+).*/s', '$1',
            (string) $this->cmd($e, $s, ['INFO', 'server'])->scalar);
        self::assertSame($rid($s1), $rid($s2));
    }
}

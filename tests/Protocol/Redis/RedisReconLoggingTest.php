<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Redis\RedisConnection;
use Funnypot\Protocol\Redis\RedisServer;
use PHPUnit\Framework\TestCase;

/**
 * The RedisServer log-event envelope: every event carries the canonical protocol identity fields the
 * dashboard and ReportGate expect (proto/method/matched/served/ts/event/ip/port/path), routine
 * events are non-reportable, and an intent event's reportable=true survives the envelope stamping.
 */
final class RedisReconLoggingTest extends TestCase
{
    use RedisTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $logged = [];

    private function server(): RedisServer
    {
        $this->logged = [];

        return new RedisServer($this->redisConfig(42), function (array $e): void {
            $this->logged[] = $e;
        });
    }

    private function emit(RedisServer $server, RedisConnection $conn): void
    {
        $port = new \ReflectionProperty($server, 'port');
        $port->setAccessible(true);
        $port->setValue($server, 6379);
        $m = new \ReflectionMethod($server, 'emitEvents');
        $m->setAccessible(true);
        $m->invoke($server, $conn, '203.0.113.9');
    }

    public function test_routine_command_envelope(): void
    {
        $server = $this->server();
        $conn = new RedisConnection($this->redisConfig(42), 1, '203.0.113.9');
        $conn->feed("PING\r\n");
        $conn->pump();
        $this->emit($server, $conn);

        self::assertCount(1, $this->logged);
        $e = $this->logged[0];
        self::assertSame('redis', $e['proto']);
        self::assertSame('REDIS', $e['method']);
        self::assertSame(1, $e['matched']);
        self::assertSame(1, $e['served']);
        self::assertSame('203.0.113.9', $e['ip']);
        self::assertSame(6379, $e['port']);
        self::assertSame('/redis/command/PING', $e['path']);
        self::assertFalse($e['reportable'], 'a routine command is never reportable');
        self::assertArrayHasKey('ts', $e);
        self::assertArrayHasKey('severity', $e);
        self::assertArrayHasKey('event', $e);
    }

    public function test_intent_event_is_reportable_through_the_envelope(): void
    {
        $server = $this->server();
        $conn = new RedisConnection($this->redisConfig(42), 1, '203.0.113.9');
        $conn->feed($this->respArray(['REPLICAOF', 'evil.example.com', '6379']));
        $conn->pump();
        $this->emit($server, $conn);

        $intent = array_values(array_filter($this->logged, static fn ($e): bool => ($e['event'] ?? '') === 'redis_replicaof_attempt'));
        self::assertCount(1, $intent);
        self::assertTrue($intent[0]['reportable'], 'the envelope must not clobber an intent reportable=true');
        self::assertSame('redis', $intent[0]['proto']);
    }

    public function test_connect_event_is_non_reportable(): void
    {
        $server = $this->server();
        $log = new \ReflectionMethod($server, 'logEvent');
        $log->setAccessible(true);
        $log->invoke($server, ['event' => 'connect', 'ip' => '203.0.113.9', 'port' => 6379, 'path' => '/redis/connect', 'reportable' => false]);

        self::assertFalse($this->logged[0]['reportable']);
        self::assertSame('REDIS', $this->logged[0]['method']);
    }
}

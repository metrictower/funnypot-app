<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Listener;
use Funnypot\Protocol\ProtocolEmulator;
use Funnypot\Protocol\Redis\RedisSafeEventProjector;
use PHPUnit\Framework\TestCase;

/**
 * The malformed-style Redis privacy boundary: the generic Listener's raw connect/clipboard events are
 * reshaped by the injected RedisSafeEventProjector into bounded class/length/keyed-fingerprint
 * telemetry — no raw clipboard/command byte is ever persisted, and every malformed-Redis event is
 * non-reportable. Also verifies the projector is only applied when injected (other protocols untouched).
 */
final class RedisMalformedProjectorTest extends TestCase
{
    use RedisTestFrames;

    public function test_clipboard_is_reduced_to_class_length_and_fingerprint(): void
    {
        $projector = new RedisSafeEventProjector($this->redisConfig(42));
        $rawKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 attacker@evil";
        $out = $projector->project([
            'event' => 'clipboard',
            'ip' => '203.0.113.5',
            'port' => 6379,
            'path' => $rawKey, // Listener puts the raw clipboard value in path
        ]);

        self::assertSame('redis_malformed_clipboard', $out['event']);
        self::assertFalse($out['reportable']);
        self::assertStringContainsString('class=ssh', $out['path']);
        self::assertStringContainsString('len=' . strlen($rawKey), $out['path']);
        self::assertStringNotContainsString('ssh-ed25519 AAAA', $out['path'], 'raw key bytes must never survive');
        self::assertStringNotContainsString($rawKey, $out['path']);
    }

    public function test_connect_is_safe_and_non_reportable(): void
    {
        $projector = new RedisSafeEventProjector($this->redisConfig(42));
        $out = $projector->project(['event' => 'connect', 'ip' => '203.0.113.5', 'port' => 6379, 'path' => '']);
        self::assertSame('connect', $out['event']);
        self::assertFalse($out['reportable']);
        self::assertSame('/redis/malformed/connect', $out['path']);
    }

    public function test_listener_applies_the_injected_projector(): void
    {
        $logged = [];
        $projector = new RedisSafeEventProjector($this->redisConfig(42));
        $listener = new Listener(
            new ProtocolEmulator([]),
            'redis',
            static function (array $e) use (&$logged): void {
                $logged[] = $e;
            },
            null,
            [$projector, 'project']
        );

        // Drive the private log() seam directly with a raw clipboard capture.
        $log = new \ReflectionMethod($listener, 'log');
        $log->setAccessible(true);
        $rawKey = 'ssh-rsa AAAAB3Nz secret-key-material';
        $log->invoke($listener, 'clipboard', '203.0.113.5', 6379, $rawKey);

        self::assertCount(1, $logged);
        self::assertSame('redis_malformed_clipboard', $logged[0]['event']);
        self::assertFalse($logged[0]['reportable']);
        self::assertStringNotContainsString('secret-key-material', json_encode($logged[0]));
    }

    public function test_listener_without_projector_keeps_raw_event(): void
    {
        $logged = [];
        $listener = new Listener(
            new ProtocolEmulator([]),
            'ssh',
            static function (array $e) use (&$logged): void {
                $logged[] = $e;
            }
        );
        $log = new \ReflectionMethod($listener, 'log');
        $log->setAccessible(true);
        $log->invoke($listener, 'command', '203.0.113.5', 22, 'uname -a');

        // Default behaviour for every other protocol is unchanged: raw command, reportable=true.
        self::assertSame('uname -a', $logged[0]['path']);
        self::assertTrue($logged[0]['reportable']);
    }
}

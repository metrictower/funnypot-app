<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Redis\RedisCommandEngine;
use Funnypot\Protocol\Redis\RedisConfig;
use Funnypot\Protocol\Redis\RedisSession;
use Funnypot\Protocol\RespCommand;
use Funnypot\Protocol\RespEncoder;
use Funnypot\Protocol\RespReply;

/**
 * Shared helpers for the Redis engine tests: a fixed-clock config, a driver that runs one command
 * against a session, an encoder, and RESP wire-frame builders for connection-level tests.
 */
trait RedisTestFrames
{
    private int $fixedNow = 1_700_000_000;

    private function redisConfig(int $seed = 42, ?callable $clock = null): RedisConfig
    {
        return new RedisConfig($seed, 'test-fingerprint-key', $clock ?? fn (): int => $this->fixedNow);
    }

    private function engine(?RedisConfig $config = null): RedisCommandEngine
    {
        return new RedisCommandEngine($config ?? $this->redisConfig());
    }

    /** Run one command (given as argv) against the session; returns the typed reply. */
    private function cmd(RedisCommandEngine $engine, RedisSession $s, array $argv): RespReply
    {
        return $engine->execute(new RespCommand(array_map('strval', $argv)), $s);
    }

    /** Run one command and return its encoded wire bytes for the session's negotiated protocol. */
    private function wire(RedisCommandEngine $engine, RedisSession $s, array $argv): string
    {
        return (new RespEncoder())->encode($this->cmd($engine, $s, $argv), $s->respVersion);
    }

    /** Build a RESP command-array frame from argv. */
    private function respArray(array $argv): string
    {
        $out = '*' . count($argv) . "\r\n";
        foreach ($argv as $a) {
            $a = (string) $a;
            $out .= '$' . strlen($a) . "\r\n" . $a . "\r\n";
        }

        return $out;
    }
}

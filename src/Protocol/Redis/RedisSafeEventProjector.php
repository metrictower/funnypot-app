<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

/**
 * Applies the interactive Redis engine's privacy boundary to the generic {@see \Funnypot\Protocol\Listener}
 * events produced on the malformed-style Redis path. That path streams the shared bounded visual lure
 * and reads an OSC-52 clipboard value back — which could carry an SSH key or command — so before any
 * event reaches the logger this projector strips the raw bytes to a class, a length and a keyed
 * fingerprint, and marks every malformed-Redis event non-reportable. Connects and routine events stay
 * local; no raw clipboard/command byte is ever persisted or externally reported.
 */
final class RedisSafeEventProjector
{
    public function __construct(private RedisConfig $config)
    {
    }

    /**
     * @param array<string,mixed> $entry the raw event the generic Listener built
     * @return array<string,mixed> the sanitised event to log instead
     */
    public function project(array $entry): array
    {
        $event = (string) ($entry['event'] ?? '');
        $base = [
            'ts' => $entry['ts'] ?? gmdate('c'),
            'ip' => (string) ($entry['ip'] ?? ''),
            'method' => 'REDIS',
            'proto' => 'redis',
            'port' => (int) ($entry['port'] ?? 6379),
            'matched' => true,
            'served' => $event !== 'connect',
            'reportable' => false, // malformed Redis is a bounded lure — never externally reported
        ];

        if ($event === 'clipboard') {
            $raw = (string) ($entry['path'] ?? '');

            return $base + [
                'event' => 'redis_malformed_clipboard',
                'severity' => 'high',
                'path' => '/redis/malformed/clipboard'
                    . ' class=' . RedisExploitDetector::classifyValue($raw)
                    . ' len=' . strlen($raw)
                    . ' fp=' . $this->config->fingerprint($raw),
            ];
        }

        return $base + [
            'event' => $event !== '' ? $event : 'connect',
            'severity' => 'low',
            'path' => '/redis/malformed/' . ($event !== '' ? $event : 'connect'),
        ];
    }
}

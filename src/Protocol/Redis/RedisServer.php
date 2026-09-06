<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

use Funnypot\App\ThreatIntel\OperatorBlocklist;

/**
 * Zero-dependency, single-process TCP server for the interactive Redis honeypot (port 6379). It
 * speaks RESP2/RESP3 in pure PHP over a non-blocking stream_select loop and drops an attacker into a
 * believable, misconfigured Redis 6.2.24 that engages the full exposed-Redis exploit playbook while
 * writing nothing, dialling nothing and executing nothing.
 *
 * The server owns only sockets: accept/select, partial writes straight from each connection's single
 * output queue, blocklist-at-accept, global/per-IP connection caps, idle reaping, a slow-drain
 * deadline and per-connection fault isolation. All framing, state, memory bounds and output
 * backpressure live in {@see RedisConnection}. A connection whose queue reaches its high-water mark
 * has reads disabled until it drains below the low-water mark, so one 64 KiB read of pipelined
 * INFO/COMMAND frames can never build an unbounded response.
 */
final class RedisServer
{
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick

    private int $clientIdSeq = 0;
    private int $port = 6379;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private RedisConfig $config,
        private $logger,
        private ?OperatorBlocklist $block = null
    ) {
    }

    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-redis: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $this->port = self::portOf($bind);
        $port = $this->port;
        fwrite(STDERR, "funnypot-redis (Redis " . RedisConfig::VERSION . ") listening on {$bind}\n");

        /** @var array<int,array{sock:resource,conn:RedisConnection,ip:string,last:int,outSince:int}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                if ($c['conn']->canAcceptReply()) {
                    $read[] = $c['sock']; // reads disabled at high-water (backpressure)
                }
                if ($c['conn']->outputPending()) {
                    $write[] = $c['sock'];
                }
            }
            $except = [];

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }
            $now = time();

            foreach ($read as $r) {
                if ($r === $server) {
                    $this->accept($server, $conns, $perIp, $port, $now);
                    continue;
                }
                $id = get_resource_id($r);
                if (!isset($conns[$id])) {
                    continue;
                }
                $data = @fread($r, self::READ_CHUNK);
                if ($data === false || ($data === '' && feof($r))) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($data === '') {
                    continue;
                }
                $conns[$id]['last'] = $now;
                $conn = $conns[$id]['conn'];
                try {
                    $conn->feed($data);
                    $conn->pump();
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'], $e, $port);
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                $this->emitEvents($conn, $conns[$id]['ip']);
                $this->markOutput($conns[$id], $now);
                $this->flush($conns, $perIp, $id, $now);
            }

            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (isset($conns[$id])) {
                    $this->flush($conns, $perIp, $id, $now);
                }
            }

            // Idle reap + slow-drain deadline.
            foreach ($conns as $id => $c) {
                if ($now - $c['last'] > RedisConfig::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($c['conn']->outputPending() && $c['outSince'] > 0 && $now - $c['outSince'] > RedisConfig::DRAIN_DEADLINE) {
                    $this->close($conns, $perIp, $id); // a peer that will not read its replies
                }
            }
        }
    }

    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0, $peer);
        if ($sock === false) {
            return;
        }
        $ip = self::ipOf((string) $peer);
        // Operator manual block: refuse a blocked source at accept — no session, zero bytes.
        if (($this->block !== null && $ip !== '' && $this->block->isBlocked($ip))
            || count($conns) >= RedisConfig::MAX_CONNS || ($perIp[$ip] ?? 0) >= RedisConfig::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }
        stream_set_blocking($sock, false);
        $id = get_resource_id($sock);
        $conns[$id] = [
            'sock' => $sock,
            'conn' => new RedisConnection($this->config, ++$this->clientIdSeq, $ip),
            'ip' => $ip,
            'last' => $now,
            'outSince' => 0,
            'port' => $port,
        ];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        // Redis is silent on connect (no banner). Log the connect as routine, non-reportable.
        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => '/redis/connect',
            'reportable' => false,
            'severity' => 'low',
        ]);
    }

    /** Flush queued output with partial-write awareness, then close if drained and asked to. */
    private function flush(array &$conns, array &$perIp, int $id, int $now): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $conn = $conns[$id]['conn'];
        if ($conn->outbuf !== '') {
            $n = @fwrite($conns[$id]['sock'], $conn->outbuf);
            if ($n === false) {
                $this->close($conns, $perIp, $id);

                return;
            }
            $conn->outbuf = $n > 0 ? substr($conn->outbuf, $n) : $conn->outbuf;
        }
        if ($conn->outbuf === '') {
            $conns[$id]['outSince'] = 0;
            if ($conn->wantsClose()) {
                $this->close($conns, $perIp, $id);

                return;
            }
            // Queue drained below the reserve — resume any frames left buffered under backpressure.
            $conn->pump();
            $this->markOutput($conns[$id], $now);
            $this->emitEvents($conn, $conns[$id]['ip']);
        }
    }

    /** Note the moment a connection's output queue first became non-empty (for the drain deadline). */
    private function markOutput(array &$c, int $now): void
    {
        if ($c['conn']->outputPending() && $c['outSince'] === 0) {
            $c['outSince'] = $now;
        }
    }

    private function emitEvents(RedisConnection $conn, string $ip): void
    {
        foreach ($conn->drainEvents() as $event) {
            $event['ip'] = $ip;
            $event['port'] = $this->port;
            $this->logEvent($event);
        }
    }

    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $ip = $conns[$id]['ip'];
        @fclose($conns[$id]['sock']);
        unset($conns[$id]);
        if (isset($perIp[$ip]) && --$perIp[$ip] <= 0) {
            unset($perIp[$ip]);
        }
    }

    /** @param array<string,mixed> $entry */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'REDIS';
        $entry['proto'] = 'redis';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        // Fail-closed: only an event that positively set reportable is ever a candidate. Connects and
        // routine commands set false; a completed high-signal intent sets true (once per journey).
        $entry['reportable'] ??= false;
        ($this->logger)($entry);
    }

    private function logFault(string $ip, \Throwable $e, int $port): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => $port,
                'path' => '/redis/error',
                'reportable' => false,
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function ipOf(string $peer): string
    {
        $p = strrpos($peer, ':');

        return $p === false ? $peer : substr($peer, 0, $p);
    }

    private static function portOf(string $bind): int
    {
        $p = strrpos($bind, ':');

        return $p === false ? 6379 : (int) substr($bind, $p + 1);
    }
}

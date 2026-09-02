<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Zero-dependency TCP listener for one protocol on one bind address. A single-process,
 * non-blocking stream_select loop holds many idle/slow connections; it sends the banner on
 * connect, feeds inbound bytes to the ProtocolEmulator, writes back the framed reply, and
 * LOGS every connection + decoded command through the injected logger (so redis/ftp/ssh
 * commands land in the same hit log the dashboard shows).
 *
 * Runtime is PHP-only (no extension, no composer dep). Everything is bounded: max concurrent
 * connections, per-source-IP cap, idle timeout, and the emulator's own per-connection buffer
 * and request caps — a long-lived TCP surface must never become a self-DoS.
 */
final class Listener
{
    private const MAX_CONNS = 256;
    private const PER_IP_CONNS = 20;
    private const IDLE_TIMEOUT = 90;   // seconds
    private const READ_CHUNK = 8192;
    private const FRAME_INTERVAL = 0.12;   // taunt animation: seconds between streamed frames
    private const FRAME_TIMEOUT_US = 120000;

    /** @param callable(array<string,mixed>):void $logger */
    public function __construct(
        private ProtocolEmulator $emulator,
        private string $protocol,
        private $logger,
        private ?\Funnypot\App\ThreatIntel\OperatorBlocklist $block = null
    ) {
    }

    /** Bind and serve forever. $bind is "host:port", e.g. "0.0.0.0:6379". */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-listen {$this->protocol}: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-listen {$this->protocol} on {$bind}\n");

        /** @var array<int,array{sock:resource,sess:ProtocolSession,ip:string,last:int,wbuf:string}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['wbuf'] !== '') {
                    $write[] = $c['sock']; // pending output — wake when the socket drains
                }
            }
            $except = [];
            // While any connection is being trolled, wake on a short frame interval so the
            // animation streams smoothly; otherwise block up to a second like a normal listener.
            $trolling = false;
            foreach ($conns as $c) {
                if ($this->emulator->isTrolling($c['sess'])) {
                    $trolling = true;
                    break;
                }
            }
            if (@stream_select($read, $write, $except, $trolling ? 0 : 1, $trolling ? self::FRAME_TIMEOUT_US : 0) === false) {
                continue; // interrupted; loop again
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
                // On a non-blocking stream, '' means EOF only when feof() agrees; otherwise it is a
                // spurious readable / would-block and the connection must stay open.
                if ($data === false || ($data === '' && feof($r))) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($data === '') {
                    continue;
                }
                $conns[$id]['last'] = $now;
                $ip = $conns[$id]['ip'];
                // A fault handling ONE connection must never kill the whole listener process (which
                // serves every port-23 connection) — drop just this session, like the SSH server does.
                try {
                    $resp = $this->emulator->feed(
                        $data,
                        $conns[$id]['sess'],
                        function (string $cmd) use ($ip, $port): void {
                            $this->log('command', $ip, $port, $cmd);
                        }
                    );
                } catch (\Throwable $e) {
                    $this->log('error', $ip, $port, 'session dropped: ' . $e->getMessage());
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($resp !== '') {
                    $conns[$id]['wbuf'] .= $resp; // queued; flushed below (may be a partial write)
                }
                // Malformed style: an OSC-52 clipboard value read back from the client is threat intel.
                $sess = $conns[$id]['sess'];
                if ($sess->clipboardCapture !== null) {
                    $this->log('clipboard', $ip, $port, $sess->clipboardCapture);
                    $sess->clipboardCapture = null;
                }
                $this->flush($conns, $perIp, $id);
            }

            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (isset($conns[$id])) {
                    $this->flush($conns, $perIp, $id);
                }
            }

            // Push the next animation frame to every trolled connection whose interval has elapsed.
            if ($trolling) {
                $mt = microtime(true);
                foreach ($conns as $id => $c) {
                    // Malformed style trickles once per second (bounded ~120s); taunt animates fast.
                    $fi = MalformedStream::enabled() ? 1.0 : self::FRAME_INTERVAL;
                    if ($this->emulator->isTrolling($c['sess']) && $mt - $c['lastFrame'] >= $fi) {
                        $conns[$id]['wbuf'] .= $this->emulator->trollFrame($c['sess']);
                        $conns[$id]['lastFrame'] = $mt;
                        $this->flush($conns, $perIp, $id);
                    }
                }
            }

            // Idle sweep — reclaim connections that went quiet.
            foreach ($conns as $id => $c) {
                if ($now - $c['last'] > self::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

    /**
     * Write as much of a connection's queued output as the non-blocking socket accepts; keep the
     * remainder for the next writable turn. A dropped/partial write must never lose the response —
     * over docker's port-publishing a freshly-read socket is often not yet writable. Closes the
     * connection once the emulator asked to close and everything queued has drained.
     *
     * @param array<int,array{sock:resource,sess:ProtocolSession,ip:string,last:int,wbuf:string}> $conns
     * @param array<string,int>                                                                    $perIp
     */
    private function flush(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $buf = $conns[$id]['wbuf'];
        if ($buf !== '') {
            $n = @fwrite($conns[$id]['sock'], $buf);
            if ($n === false) {
                $this->close($conns, $perIp, $id);

                return;
            }
            $conns[$id]['wbuf'] = $n > 0 ? substr($buf, $n) : $buf;
        }
        if ($conns[$id]['wbuf'] === '' && $conns[$id]['sess']->close) {
            $this->close($conns, $perIp, $id);
        }
    }

    /**
     * @param resource                                                                   $server
     * @param array<int,array{sock:resource,sess:ProtocolSession,ip:string,last:int,wbuf:string}>    $conns
     * @param array<string,int>                                                          $perIp
     */
    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0, $peer);
        if ($sock === false) {
            return;
        }
        $ip = self::ipOf((string) $peer);
        // Operator manual block: refuse a blocked source at accept — no banner, zero bytes.
        if (($this->block !== null && $this->block->isBlocked($ip))
            || count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock); // blocked, or over a cap — refuse rather than exhaust

            return;
        }
        stream_set_blocking($sock, false);
        $sess = new ProtocolSession(crc32($ip)); // per-attacker seed for {{fake.*}}
        $sess->peerIp = $ip;                     // so the shell's netstat/w can show the attacker's conn
        $id = get_resource_id($sock);
        $conns[$id] = ['sock' => $sock, 'sess' => $sess, 'ip' => $ip, 'last' => $now, 'wbuf' => '', 'lastFrame' => 0.0];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->log('connect', $ip, $port, '');
        $conns[$id]['wbuf'] = $this->emulator->banner($sess);
        $this->flush($conns, $perIp, $id);
    }

    /**
     * @param array<int,array{sock:resource,sess:ProtocolSession,ip:string,last:int,wbuf:string}> $conns
     * @param array<string,int>                                                       $perIp
     */
    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        @fclose($conns[$id]['sock']);
        $ip = $conns[$id]['ip'];
        if (isset($perIp[$ip]) && --$perIp[$ip] <= 0) {
            unset($perIp[$ip]);
        }
        unset($conns[$id]);
    }

    private function log(string $event, string $ip, int $port, string $cmd): void
    {
        ($this->logger)([
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => strtoupper($this->protocol),
            'path' => substr($cmd, 0, 200),
            'proto' => $this->protocol,
            'port' => $port,
            'event' => $event,
            'matched' => true,
            'severity' => 'medium',
            'served' => $event === 'command',
            // FP-0247 (Fix A): TCP accept ⇒ source verified by the three-way handshake, so reportable.
            'reportable' => true,
        ]);
    }

    private static function ipOf(string $peer): string
    {
        $p = strrpos($peer, ':');

        return $p === false ? $peer : substr($peer, 0, $p);
    }

    private static function portOf(string $bind): int
    {
        $p = strrpos($bind, ':');

        return $p === false ? 0 : (int) substr($bind, $p + 1);
    }
}

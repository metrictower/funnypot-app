<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

use Funnypot\Protocol\MalformedStream;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Ssh\HostKey\HostKeySet;

/**
 * Zero-dependency, single-process TCP server for the pure-PHP SSH honeypot. Like the plain
 * {@see \Funnypot\Protocol\Listener} it holds many connections in one non-blocking stream_select
 * loop, but SSH needs a per-connection crypto state machine and buffered writes, so each socket
 * carries an {@see SshConnection} and an outbound queue. Every connection, credential attempt and
 * shell command is logged through the injected logger into the same store the dashboard reads.
 *
 * All bounds are enforced: max concurrent connections, per-source-IP cap, idle timeout, and the
 * connection's own inbound cap — a long-lived crypto surface must never become a self-DoS.
 */
final class SshServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 12;
    private const IDLE_TIMEOUT = 120;   // seconds
    private const READ_CHUNK = 16384;
    private const DRAIN_READS = 64;     // bounded receive-buffer drain on close
    private const FRAME_INTERVAL = 0.12;   // taunt animation: seconds between streamed frames
    private const FRAME_TIMEOUT_US = 120000;

    private int $rejectBudget;

    /**
     * @param callable(array<string,mixed>):void $logger
     * @param int|null $rejectBudget Anti-fingerprint credential reject (see SshConnection). null ⇒
     *                 read FUNNYPOT_SSH_REJECT_BUDGET, default 0 (accept-all — the honeypot welcomes
     *                 every login).
     */
    public function __construct(
        private HostKeySet $hostKeys,
        private $logger,
        private string $serverVersion = '',
        ?int $rejectBudget = null,
        private ?int $identitySeed = null,
        private ?string $secret = null
    ) {
        $this->rejectBudget = $rejectBudget ?? (int) (getenv('FUNNYPOT_SSH_REJECT_BUDGET') ?: 0);
        // Default the SSH ident to the distro-coherent one (matches the shell's os-release/uname); an
        // explicit non-empty serverVersion still wins.
        if ($this->serverVersion === '') {
            $this->serverVersion = \Funnypot\Shell\Host\HostIdentity::fromSeed($this->identitySeed ?? 0)->sshBanner();
        }
    }

    /** Bind and serve forever. $bind is "host:port", e.g. "0.0.0.0:2222". */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-ssh: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-ssh on {$bind}\n");

        /** @var array<int,array{sock:resource,conn:SshConnection,ip:string,last:int,wbuf:string}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['wbuf'] !== '') {
                    $write[] = $c['sock'];
                }
            }
            $except = [];
            // While any connection is being trolled, wake on a short frame interval so the
            // animation streams smoothly; otherwise block up to a second like a normal server.
            $trolling = false;
            foreach ($conns as $c) {
                if ($c['conn']->isTrolling()) {
                    $trolling = true;
                    break;
                }
            }
            if (@stream_select($read, $write, $except, $trolling ? 0 : 1, $trolling ? self::FRAME_TIMEOUT_US : 0) === false) {
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
                if ($data === '' || $data === false) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                $conns[$id]['last'] = $now;
                $conns[$id]['conn']->feed($data);
                $conns[$id]['wbuf'] .= $conns[$id]['conn']->takeOut();
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
                    if ($c['conn']->isTrolling() && $mt - $c['lastFrame'] >= $fi) {
                        $c['conn']->pushTrollFrame();
                        $conns[$id]['wbuf'] .= $c['conn']->takeOut();
                        $conns[$id]['lastFrame'] = $mt;
                        $this->flush($conns, $perIp, $id);
                    }
                }
            }

            foreach ($conns as $id => $c) {
                if ($now - $c['last'] > self::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

    /**
     * @param resource                                                                          $server
     * @param array<int,array{sock:resource,conn:SshConnection,ip:string,last:int,wbuf:string}> $conns
     * @param array<string,int>                                                                 $perIp
     */
    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0, $peer);
        if ($sock === false) {
            return;
        }
        $ip = self::ipOf((string) $peer);
        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }
        stream_set_blocking($sock, false);
        $session = new ProtocolSession(crc32($ip));
        $session->peerIp = $ip;
        $conn = new SshConnection(
            $this->hostKeys,
            $session,
            fn (string $event, string $detail) => $this->log($ip, $port, $event, $detail),
            $this->serverVersion,
            $this->rejectBudget,
            $this->identitySeed,
            $this->secret
        );
        $conn->onConnect();
        $id = get_resource_id($sock);
        $conns[$id] = ['sock' => $sock, 'conn' => $conn, 'ip' => $ip, 'last' => $now, 'wbuf' => $conn->takeOut(), 'lastFrame' => 0.0];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;
        $this->flush($conns, $perIp, $id);
    }

    /**
     * Write as much of the connection's outbound queue as the socket accepts; close once the
     * connection is finished and fully drained.
     *
     * @param array<int,array{sock:resource,conn:SshConnection,ip:string,last:int,wbuf:string}> $conns
     * @param array<string,int>                                                                 $perIp
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
        $conn = $conns[$id]['conn'];
        if ($conns[$id]['wbuf'] === '' && ($conn->isClosed() || $conn->shouldClose())) {
            $this->close($conns, $perIp, $id);
        }
    }

    /**
     * @param array<int,array{sock:resource,conn:SshConnection,ip:string,last:int,wbuf:string}> $conns
     * @param array<string,int>                                                                 $perIp
     */
    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $this->gracefulClose($conns[$id]['sock']);
        $ip = $conns[$id]['ip'];
        if (isset($perIp[$ip]) && --$perIp[$ip] <= 0) {
            unset($perIp[$ip]);
        }
        unset($conns[$id]);
    }

    /**
     * Close a client socket the way real OpenSSH does — with an orderly FIN, not a RST. The
     * kernel emits a RST if a socket is closed while unread bytes sit in its receive buffer, and
     * on teardown the client's own CHANNEL_CLOSE / trailing bytes routinely land there. A RST is a
     * subtle honeypot tell, so half-close the write side to push our FIN, then drain whatever the
     * peer sent before releasing the socket. The socket is non-blocking, and the drain is bounded,
     * so this never stalls the shared select loop; every call tolerates an already-dead socket.
     *
     * @param resource $sock
     */
    private function gracefulClose($sock): void
    {
        @stream_socket_shutdown($sock, STREAM_SHUT_WR);
        for ($i = 0; $i < self::DRAIN_READS; $i++) {
            $chunk = @fread($sock, self::READ_CHUNK);
            if ($chunk === '' || $chunk === false) {
                break;
            }
        }
        @fclose($sock);
    }

    private function log(string $ip, int $port, string $event, string $detail): void
    {
        ($this->logger)([
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => 'SSH',
            'path' => substr($detail, 0, 200),
            'proto' => 'ssh',
            'port' => $port,
            'event' => $event,
            'matched' => true,
            'severity' => $event === 'login' ? 'high' : 'medium',
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

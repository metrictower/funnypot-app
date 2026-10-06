<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Minecraft;

/**
 * Zero-dependency TCP server for the Minecraft honeypot (FP-0206, port 25565). Speaks VarInt-framed
 * Server-List-Ping + Login in pure PHP on a non-blocking stream_select loop ({@see MinecraftSession} +
 * {@see VarInt}), answers crawlers with a persona status JSON, and captures Log4Shell JNDI payloads sprayed
 * into the handshake address / login username — logging the C2, performing NO lookup. Mirrors the bespoke
 * binary-server pattern of {@see \Funnypot\Protocol\Mssql\MssqlServer}.
 *
 * INERT: no outbound dial of any kind (no JNDI/LDAP/RMI/DNS); no Java; a bad frame closes only that
 * connection, never the listener.
 */
final class MinecraftServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120;
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000;

    /** @param callable(array<string,mixed>):void $logger */
    public function __construct(
        private MinecraftConfig $config,
        private $logger
    ) {
    }

    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-minecraft: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        fwrite(STDERR, "funnypot-minecraft ({$this->config->versionName}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:MinecraftSession,ip:string,outbuf:string,last:int}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['outbuf'] !== '') {
                    $write[] = $c['sock'];
                }
            }
            $except = null;

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }
            $now = time();

            foreach ($read as $r) {
                if ($r === $server) {
                    $this->accept($server, $conns, $perIp, $now);
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
                try {
                    $conns[$id]['outbuf'] .= $conns[$id]['session']->receive($data);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'], $e);
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($conns[$id]['session']->close && $conns[$id]['outbuf'] === '') {
                    $this->close($conns, $perIp, $id);
                }
            }

            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (!isset($conns[$id]) || $conns[$id]['outbuf'] === '') {
                    continue;
                }
                $written = @fwrite($w, $conns[$id]['outbuf']);
                if ($written === false) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                $conns[$id]['outbuf'] = substr($conns[$id]['outbuf'], $written);
                if ($conns[$id]['outbuf'] === '' && $conns[$id]['session']->close) {
                    $this->close($conns, $perIp, $id);
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
     * @param resource $server
     * @param array<int,array{sock:resource,session:MinecraftSession,ip:string,outbuf:string,last:int}> $conns
     * @param array<string,int> $perIp
     */
    private function accept($server, array &$conns, array &$perIp, int $now): void
    {
        $sock = @stream_socket_accept($server, 0);
        if ($sock === false) {
            return;
        }
        stream_set_blocking($sock, false);
        $name = (string) @stream_socket_get_name($sock, true);
        $ip = ($colon = strrpos($name, ':')) !== false ? substr($name, 0, $colon) : $name;

        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }
        $id = get_resource_id($sock);
        $conns[$id] = [
            'sock' => $sock,
            'session' => new MinecraftSession($this->config, $this->logger, $ip),
            'ip' => $ip,
            'outbuf' => '',
            'last' => $now,
        ];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;
    }

    /**
     * @param array<int,array{sock:resource,session:MinecraftSession,ip:string,outbuf:string,last:int}> $conns
     * @param array<string,int> $perIp
     */
    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $ip = $conns[$id]['ip'];
        @fclose($conns[$id]['sock']);
        unset($conns[$id]);
        if (isset($perIp[$ip])) {
            $perIp[$ip]--;
            if ($perIp[$ip] <= 0) {
                unset($perIp[$ip]);
            }
        }
    }

    private function logFault(string $ip, \Throwable $e): void
    {
        ($this->logger)([
            'event' => 'error',
            'ip' => $ip,
            'proto' => 'minecraft',
            'path' => 'Minecraft frame fault: ' . $e->getMessage(),
            'reportable' => false,
        ]);
    }
}

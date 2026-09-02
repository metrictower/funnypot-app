<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mqtt;

/**
 * Zero-dependency, single-process TCP server for the low-interaction MQTT honeypot (port 1883).
 * Speaks just enough MQTT 3.1.1 / 5.0 in pure PHP, on a non-blocking stream_select event loop, to
 * keep a client talking and harvest the intel it offers.
 *
 * Deliberately inert: it brokers nothing, delivers nothing, and never grants a real session. It
 * accepts the CONNECT (CONNACK return code 0) purely so the client proceeds to reveal the topics it
 * subscribes to and the payloads it publishes.
 *
 * Capture path:
 * - CONNECT: protocol name/level, client id, and the username / password when the connect flags set
 *   them. Answer CONNACK "accepted" so the client keeps going.
 * - SUBSCRIBE: the topic filter(s) + packet id. Answer SUBACK granting QoS 0 for each.
 * - PUBLISH: topic + payload (payload length capped in the log). Answer PUBACK when QoS > 0.
 * - PINGREQ: answer PINGRESP so an idle client stays connected and keeps sending.
 *
 * Frame: MQTT fixed header = one control-byte (packet type high nibble + flags low nibble) followed
 * by a 1-4 byte Remaining Length varint, then that many bytes of variable header + payload.
 */
final class MqttServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick

    // Guards against a client that stops draining or a runaway declared packet length.
    private const INBUF_CAP = 262144;  // 256 KiB — recon MQTT packets are small
    private const MAX_PACKET = 131072; // 128 KiB — a single MQTT packet we will assemble

    // MQTT control packet types (packet type is the high nibble of the fixed-header byte).
    private const CONNECT = 1;
    private const CONNACK = 2;
    private const PUBLISH = 3;
    private const PUBACK = 4;
    private const SUBSCRIBE = 8;
    private const SUBACK = 9;
    private const PINGREQ = 12;
    private const PINGRESP = 13;
    private const DISCONNECT = 14;

    // SUBACK return code granting the subscription at QoS 0 (MQTT 3.1.1 3.9.3 / 5.0 reason code).
    private const GRANTED_QOS0 = 0x00;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private MqttConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:1883").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-mqtt: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-mqtt listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:MqttSession,ip:string}> $conns */
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

                // Guard against inbound buffer exhaustion — recon MQTT traffic is tiny.
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
            }

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
        $session = new MqttSession($ip, $clientPort, $id);
        // The client speaks first in MQTT (CONNECT), so nothing is queued on connect.

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "MQTT connection from {$ip}:{$clientPort}",
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
     * Frames the inbound stream into MQTT control packets and dispatches each one. Incomplete
     * trailing bytes are left in inbuf until the rest arrives. Safe to drive directly in tests.
     */
    public function processInbound(MqttSession $s): void
    {
        while (true) {
            if ($s->state === MqttSession::STATE_DONE) {
                return;
            }
            if (strlen($s->inbuf) < 2) {
                return; // need at least the control byte + one Remaining Length byte
            }

            $first = ord($s->inbuf[0]);
            $type = $first >> 4;
            $flags = $first & 0x0F;

            $vi = self::decodeVarint($s->inbuf, 1);
            if ($vi['status'] === 'incomplete') {
                return; // wait for the rest of the Remaining Length varint
            }
            if ($vi['status'] === 'malformed') {
                $this->logUnknown($s, 'malformed Remaining Length varint');
                $s->close = true;

                return;
            }

            $remLen = $vi['value'];
            if ($remLen > self::MAX_PACKET) {
                $this->logUnknown($s, sprintf('packet too large (%d bytes)', $remLen));
                $s->close = true;

                return;
            }

            $headerLen = 1 + $vi['bytes'];
            $total = $headerLen + $remLen;
            if (strlen($s->inbuf) < $total) {
                return; // wait for the full packet
            }

            $body = substr($s->inbuf, $headerLen, $remLen);
            $s->inbuf = substr($s->inbuf, $total);

            $this->handlePacket($s, $type, $flags, $body);
            if ($s->close || $s->state === MqttSession::STATE_DONE) {
                return;
            }
        }
    }

    private function handlePacket(MqttSession $s, int $type, int $flags, string $body): void
    {
        // MQTT requires CONNECT to be the first packet; anything else on a fresh connection is a
        // protocol violation a real broker drops.
        if ($s->state === MqttSession::STATE_WAIT_CONNECT && $type !== self::CONNECT) {
            $this->logUnknown($s, sprintf('first packet not CONNECT (type %d)', $type));
            $s->close = true;

            return;
        }

        switch ($type) {
            case self::CONNECT:
                if ($s->connectSeen) {
                    // A second CONNECT on one connection is a protocol violation.
                    $this->logUnknown($s, 'duplicate CONNECT');
                    $s->close = true;

                    return;
                }
                $this->handleConnect($s, $body);
                break;

            case self::SUBSCRIBE:
                $this->handleSubscribe($s, $body);
                break;

            case self::PUBLISH:
                $this->handlePublish($s, $body, $flags);
                break;

            case self::PINGREQ:
                // Keep an idle client connected so it keeps sending.
                $s->outbuf .= chr(self::PINGRESP << 4) . chr(0x00);
                break;

            case self::DISCONNECT:
                $s->state = MqttSession::STATE_DONE;
                $s->close = true;
                break;

            default:
                $this->logUnknown($s, sprintf('unmodelled MQTT packet type %d', $type));
                $s->close = true;
        }
    }

    /**
     * CONNECT: capture the protocol, client id and any offered credential, then answer a CONNACK
     * that accepts the connection so the client proceeds to subscribe / publish.
     */
    private function handleConnect(MqttSession $s, string $body): void
    {
        $c = self::parseConnect($body);
        if ($c === null) {
            $this->logUnknown($s, 'malformed CONNECT');
            $s->close = true;

            return;
        }

        $s->protocolName = $c['protocolName'];
        $s->protocolLevel = $c['protocolLevel'];
        $s->clientId = $c['clientId'];
        $s->username = $c['username'];
        $s->password = $c['password'];
        $s->keepAlive = $c['keepAlive'];
        $s->connectSeen = true;
        $s->state = MqttSession::STATE_CONNECTED;

        $hasCred = ($c['username'] !== null || $c['password'] !== null);
        $entry = [
            'event' => 'mqtt_connect',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $hasCred ? 'high' : 'medium',
            'path' => sprintf(
                'MQTT CONNECT client-id=%s proto=%s/%d%s',
                self::printable((string) $c['clientId']),
                self::printable((string) $c['protocolName']),
                $c['protocolLevel'],
                $hasCred ? sprintf(
                    ' user=%s pass=%s',
                    self::printable((string) $c['username']),
                    self::printable((string) $c['password'])
                ) : ''
            ),
            'client_id' => self::printable((string) $c['clientId']),
            'proto_name' => self::printable((string) $c['protocolName']),
            'proto_level' => $c['protocolLevel'],
        ];
        if ($c['username'] !== null) {
            $entry['username'] = self::printable($c['username']);
        }
        if ($c['password'] !== null) {
            $entry['password'] = self::printable($c['password']);
        }
        $this->logEvent($entry);

        $s->outbuf .= self::buildConnack($s->protocolLevel, $this->config->connackCode, $this->config->sessionPresent);
    }

    /**
     * SUBSCRIBE: capture the topic filter(s) + packet id, then answer a SUBACK granting QoS 0 for
     * each filter. Nothing is ever actually subscribed.
     */
    private function handleSubscribe(MqttSession $s, string $body): void
    {
        $sub = self::parseSubscribe($body, $s->protocolLevel);
        if ($sub === null) {
            $this->logUnknown($s, 'malformed SUBSCRIBE');
            $s->close = true;

            return;
        }

        $filters = array_map(static fn (array $t): string => self::printable($t['filter']), $sub['topics']);

        $this->logEvent([
            'event' => 'mqtt_subscribe',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf('MQTT SUBSCRIBE id=%d topics=[%s]', $sub['packetId'], implode(', ', $filters)),
            'packet_id' => $sub['packetId'],
            'topics' => $filters,
        ]);

        $codes = array_fill(0, count($sub['topics']), self::GRANTED_QOS0);
        $s->outbuf .= self::buildSuback($sub['packetId'], $codes, $s->protocolLevel);
    }

    /**
     * PUBLISH: capture the topic + payload (payload length capped in the log), then answer a PUBACK
     * when QoS > 0. Nothing is ever delivered to any subscriber.
     */
    private function handlePublish(MqttSession $s, string $body, int $flags): void
    {
        $qos = ($flags >> 1) & 0x03;
        $retain = $flags & 0x01;

        $pub = self::parsePublish($body, $qos, $s->protocolLevel);
        if ($pub === null) {
            $this->logUnknown($s, 'malformed PUBLISH');
            $s->close = true;

            return;
        }

        $payload = $pub['payload'];
        $cap = $this->config->payloadLogCap;
        $logged = strlen($payload) > $cap ? substr($payload, 0, $cap) : $payload;

        $this->logEvent([
            'event' => 'mqtt_publish',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'MQTT PUBLISH topic=%s qos=%d retain=%d len=%d',
                self::printable($pub['topic']),
                $qos,
                $retain,
                strlen($payload)
            ),
            'topic' => self::printable($pub['topic']),
            'qos' => $qos,
            'retain' => $retain,
            'payload_len' => strlen($payload),
            'payload' => self::printable($logged),
        ]);

        if ($qos > 0 && $pub['packetId'] !== null) {
            $s->outbuf .= self::buildPuback($pub['packetId']);
        }
    }

    // ---- Parsers -----------------------------------------------------------------------------

    /**
     * Parses an MQTT CONNECT variable header + payload. Handles both 3.1.1 (protocol level 4) and
     * 5.0 (level 5); the 5.0 property blocks are skipped, not modelled. Returns null on malformed
     * input.
     *
     * @return array{protocolName:string,protocolLevel:int,connectFlags:int,keepAlive:int,clientId:string,willTopic:?string,willPayload:?string,username:?string,password:?string}|null
     */
    public static function parseConnect(string $body): ?array
    {
        $off = 0;
        $protocolName = self::readString($body, $off);
        if ($protocolName === null) {
            return null;
        }
        if ($off >= strlen($body)) {
            return null;
        }
        $level = ord($body[$off]);
        $off++;
        if ($off >= strlen($body)) {
            return null;
        }
        $flags = ord($body[$off]);
        $off++;
        if ($off + 2 > strlen($body)) {
            return null;
        }
        $keepAlive = (ord($body[$off]) << 8) | ord($body[$off + 1]);
        $off += 2;

        // MQTT 5.0 CONNECT properties precede the payload.
        if ($level >= 5 && !self::skipProperties($body, $off)) {
            return null;
        }

        $clientId = self::readString($body, $off);
        if ($clientId === null) {
            return null;
        }

        $willTopic = null;
        $willPayload = null;
        if ($flags & 0x04) { // will flag
            if ($level >= 5 && !self::skipProperties($body, $off)) {
                return null; // will properties
            }
            $willTopic = self::readString($body, $off);
            if ($willTopic === null) {
                return null;
            }
            $willPayload = self::readString($body, $off); // binary, same 2-byte length framing
            if ($willPayload === null) {
                return null;
            }
        }

        $username = null;
        if ($flags & 0x80) { // username flag
            $username = self::readString($body, $off);
            if ($username === null) {
                return null;
            }
        }
        $password = null;
        if ($flags & 0x40) { // password flag
            $password = self::readString($body, $off); // binary, same 2-byte length framing
            if ($password === null) {
                return null;
            }
        }

        return [
            'protocolName' => $protocolName,
            'protocolLevel' => $level,
            'connectFlags' => $flags,
            'keepAlive' => $keepAlive,
            'clientId' => $clientId,
            'willTopic' => $willTopic,
            'willPayload' => $willPayload,
            'username' => $username,
            'password' => $password,
        ];
    }

    /**
     * Parses an MQTT SUBSCRIBE variable header + payload. Returns null on malformed input or when
     * no topic filter is present (an empty subscription is a protocol violation).
     *
     * @return array{packetId:int,topics:list<array{filter:string,qos:int}>}|null
     */
    public static function parseSubscribe(string $body, int $level): ?array
    {
        if (strlen($body) < 2) {
            return null;
        }
        $off = 0;
        $packetId = (ord($body[0]) << 8) | ord($body[1]);
        $off += 2;

        if ($level >= 5 && !self::skipProperties($body, $off)) {
            return null;
        }

        $topics = [];
        while ($off < strlen($body)) {
            $filter = self::readString($body, $off);
            if ($filter === null) {
                return null;
            }
            if ($off >= strlen($body)) {
                return null; // subscription options byte missing
            }
            $options = ord($body[$off]);
            $off++;
            $topics[] = ['filter' => $filter, 'qos' => $options & 0x03];
        }
        if ($topics === []) {
            return null;
        }

        return ['packetId' => $packetId, 'topics' => $topics];
    }

    /**
     * Parses an MQTT PUBLISH variable header + payload. The packet id is present only for QoS > 0.
     * Returns null on malformed input.
     *
     * @return array{topic:string,packetId:?int,payload:string}|null
     */
    public static function parsePublish(string $body, int $qos, int $level): ?array
    {
        $off = 0;
        $topic = self::readString($body, $off);
        if ($topic === null) {
            return null;
        }
        $packetId = null;
        if ($qos > 0) {
            if ($off + 2 > strlen($body)) {
                return null;
            }
            $packetId = (ord($body[$off]) << 8) | ord($body[$off + 1]);
            $off += 2;
        }
        if ($level >= 5 && !self::skipProperties($body, $off)) {
            return null;
        }

        return ['topic' => $topic, 'packetId' => $packetId, 'payload' => substr($body, $off)];
    }

    // ---- Response builders -------------------------------------------------------------------

    /**
     * CONNACK (MQTT 3.2). For protocol level 5 the response carries the acknowledge flags, the
     * reason code, and an empty property block; for 3.1.1 it is the flags + return code only.
     */
    public static function buildConnack(int $level, int $code, bool $sessionPresent): string
    {
        $ackFlags = $sessionPresent ? 0x01 : 0x00;
        $vh = chr($ackFlags) . chr($code);
        if ($level >= 5) {
            $vh .= chr(0x00); // property length 0
        }

        return chr(self::CONNACK << 4) . self::encodeVarint(strlen($vh)) . $vh;
    }

    /**
     * SUBACK (MQTT 3.9) echoing the packet id and carrying one return code per subscribed filter.
     *
     * @param list<int> $codes
     */
    public static function buildSuback(int $packetId, array $codes, int $level): string
    {
        $vh = pack('n', $packetId);
        if ($level >= 5) {
            $vh .= chr(0x00); // property length 0
        }
        $payload = '';
        foreach ($codes as $code) {
            $payload .= chr($code);
        }
        $body = $vh . $payload;

        return chr(self::SUBACK << 4) . self::encodeVarint(strlen($body)) . $body;
    }

    /**
     * PUBACK (MQTT 3.4) echoing the packet id. A 2-byte body means reason "success" with no
     * properties, which is valid for both 3.1.1 and 5.0.
     */
    public static function buildPuback(int $packetId): string
    {
        $body = pack('n', $packetId);

        return chr(self::PUBACK << 4) . self::encodeVarint(strlen($body)) . $body;
    }

    // ---- Byte helpers ------------------------------------------------------------------------

    /**
     * Reads an MQTT length-prefixed field { 2-byte big-endian length, bytes }, advancing $off past
     * it. Used for both UTF-8 strings and binary data, which share this framing. Returns null when
     * the buffer is too short.
     */
    private static function readString(string $buf, int &$off): ?string
    {
        if ($off + 2 > strlen($buf)) {
            return null;
        }
        $len = (ord($buf[$off]) << 8) | ord($buf[$off + 1]);
        $off += 2;
        if ($off + $len > strlen($buf)) {
            return null;
        }
        $s = substr($buf, $off, $len);
        $off += $len;

        return $s;
    }

    /**
     * Skips an MQTT 5.0 property block (a Remaining-Length-style varint length followed by that many
     * bytes), advancing $off past it. Returns false if the block runs past the buffer.
     */
    private static function skipProperties(string $buf, int &$off): bool
    {
        $vi = self::decodeVarint($buf, $off);
        if ($vi['status'] !== 'ok') {
            return false;
        }
        $off += $vi['bytes'] + $vi['value'];

        return $off <= strlen($buf);
    }

    /**
     * Decodes an MQTT variable-length integer at $offset. Returns a status of 'ok' with the value
     * and byte count, 'incomplete' when the buffer ends mid-varint, or 'malformed' when it exceeds
     * the 4-byte maximum.
     *
     * @return array{status:string,value?:int,bytes?:int}
     */
    private static function decodeVarint(string $buf, int $offset): array
    {
        $multiplier = 1;
        $value = 0;
        $bytes = 0;

        do {
            if ($offset + $bytes >= strlen($buf)) {
                return ['status' => 'incomplete'];
            }
            if ($bytes >= 4) {
                return ['status' => 'malformed']; // a 5th continuation byte exceeds the varint max
            }
            $b = ord($buf[$offset + $bytes]);
            $value += ($b & 0x7F) * $multiplier;
            $multiplier *= 128;
            $bytes++;
        } while (($b & 0x80) !== 0);

        return ['status' => 'ok', 'value' => $value, 'bytes' => $bytes];
    }

    /**
     * Encodes an integer as an MQTT variable-length integer (Remaining Length style).
     */
    public static function encodeVarint(int $n): string
    {
        $out = '';
        do {
            $b = $n % 128;
            $n = intdiv($n, 128);
            if ($n > 0) {
                $b |= 0x80;
            }
            $out .= chr($b);
        } while ($n > 0);

        return $out;
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(string $s): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $s) ?? '';
    }

    private function logUnknown(MqttSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'mqtt_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'MQTT unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'MQTT';
        $entry['proto'] = 'mqtt';
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
                'port' => 1883,
                'path' => 'MQTT internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 1883;
    }
}

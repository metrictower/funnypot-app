<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Stun;

/**
 * Zero-dependency, single-process UDP server for the low-interaction STUN honeypot (port 3478).
 * Speaks just enough of RFC 5389 in pure PHP — parse a Binding Request, answer with a Binding
 * Success Response carrying the client's observed address — on a non-blocking stream_select loop
 * over one UDP socket, to fingerprint scanners and NAT-discovery clients.
 *
 * Deliberately 100% inert: this is only NAT-mapping discovery. It NEVER implements TURN — no
 * allocation, no relay, no forwarding of packets to any third party. The only thing it ever tells a
 * client is the source address it saw, which is exactly what a plain STUN server does.
 *
 * Captured intel:
 * - the client's source ip:port (the mapped address we reflect)
 * - any SOFTWARE attribute the client advertised (the tool behind the probe)
 * - the STUN message type of anything that is not a Binding Request
 *
 * STUN is a well-known reflection/amplification vector (a Binding Response is normally larger than a
 * bare Binding Request), so two hard anti-amplification guards apply to every reply:
 * 1. No emitted datagram is ever larger than the request that triggered it (amplification factor
 *    <= 1). The SOFTWARE attribute, then the whole reply, is dropped before that bound is crossed —
 *    so a spoofed 20-byte Binding Request pulls nothing back at the forged victim.
 * 2. Replies are metered per source IP with a token bucket (a spoofed request forges its source as a
 *    victim, so every reply we emit lands on that victim).
 * Anything that is not a well-formed Binding Request is recorded and dropped, never answered.
 */
final class StunServer
{
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const READ_CHUNK = 65535;        // a single UDP datagram
    private const INBUF_CAP = 65535;         // a STUN message never legitimately exceeds this
    private const MAX_DGRAMS_PER_TICK = 64;  // bound the drain so a flood can't spin one tick forever
    private const MAX_ATTRS = 64;            // cap attributes parsed from one message

    // STUN framing (RFC 5389 6). The magic cookie fixes the wire byte order and gates non-STUN junk.
    private const MAGIC_COOKIE = "\x21\x12\xA4\x42";
    private const MAGIC_HI16 = 0x2112; // most-significant 16 bits, used to XOR the mapped port

    // Message types (RFC 5389 3): method Binding (0x001) with class Request / Success Response.
    private const MSG_BINDING_REQUEST = 0x0001;
    private const MSG_BINDING_SUCCESS = 0x0101;

    // Attribute types (RFC 5389 15 / 18.2).
    private const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    private const ATTR_SOFTWARE = 0x8022;

    // Address families inside a (XOR-)MAPPED-ADDRESS attribute (RFC 5389 15.1).
    private const FAMILY_IPV4 = 0x01;
    private const FAMILY_IPV6 = 0x02;

    /**
     * Per-source-IP token bucket throttling UDP responses (anti-reflection). A spoofed request forges
     * its source as a victim, so every reply we emit lands on that victim — capping replies per
     * apparent source bounds how hard the honeypot can be turned into a reflector.
     * @var array<string, array{tokens: float, last: float}>
     */
    private array $udpResponseBuckets = [];
    private const UDP_RESP_BURST = 20.0;      // bucket capacity
    private const UDP_RESP_RATE = 10.0;       // tokens refilled per second
    private const UDP_BUCKET_MAX_IPS = 4096;  // cap tracked IPs so the map can't grow unbounded

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private StunConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:3478").
     */
    public function run(string $bind): void
    {
        $sock = @stream_socket_server("udp://{$bind}", $errno, $errstr, STREAM_SERVER_BIND);
        if ($sock === false) {
            fwrite(STDERR, "funnypot-stun: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($sock, false);
        fwrite(STDERR, "funnypot-stun listening on {$bind} (UDP)\n");

        $id = 0;

        while (true) {
            $read = [$sock];
            $write = null;
            $except = null;

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }

            // Drain the readable socket in a bounded loop: a UDP socket signals readable once but may
            // hold several queued datagrams.
            for ($i = 0; $i < self::MAX_DGRAMS_PER_TICK; $i++) {
                $peer = '';
                $data = @stream_socket_recvfrom($sock, self::READ_CHUNK, 0, $peer);
                if ($data === false || $data === '' || $peer === '') {
                    break;
                }

                [$ip, $clientPort] = self::splitAddr((string) $peer);
                $session = new StunSession($ip, $clientPort, ++$id);
                $session->inbuf = $data;

                // Fault isolation: a malformed datagram must degrade (log + skip) — never escape the
                // loop and crash the listener.
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($ip, $e);
                    continue;
                }

                if ($session->outbuf === '') {
                    continue;
                }

                // Anti-reflection throttle: a spoofed source drains its bucket and its reply is dropped
                // rather than reflected at the forged victim.
                if (!$this->udpResponseAllowed($ip)) {
                    continue;
                }

                @stream_socket_sendto($sock, $session->outbuf, 0, (string) $peer);
            }
        }
    }

    /**
     * Parses the datagram held in $s->inbuf, captures the mapped address + any SOFTWARE, logs the
     * probe, and queues a size-capped Binding Success Response in $s->outbuf. Safe to drive directly
     * with raw bytes in tests.
     */
    public function processInbound(StunSession $s): void
    {
        $data = $s->inbuf;
        $s->inbuf = '';
        if ($data === '') {
            return;
        }
        if (strlen($data) > self::INBUF_CAP) {
            $this->logUnknown($s, sprintf('oversize datagram (%d bytes)', strlen($data)));

            return;
        }

        $msg = self::parseMessage($data);
        if ($msg === null) {
            // Bad magic cookie / malformed structure / non-STUN junk: record, never reply.
            $this->logUnknown($s, 'unparseable STUN message or bad magic cookie');

            return;
        }

        $s->messageType = $msg['messageType'];
        $s->transactionId = $msg['transactionId'];
        $s->software = $msg['software'];

        if ($msg['messageType'] !== self::MSG_BINDING_REQUEST) {
            // Indications, responses and other methods are not requests: never reply (that would be a
            // reflection primitive with no client waiting), only record.
            $this->logUnknown($s, sprintf('non Binding-Request message type 0x%04X', $msg['messageType']));

            return;
        }

        // A source address we cannot pack cannot be reflected as a mapped address; record and drop.
        if (@inet_pton($s->ip) === false) {
            $this->logUnknown($s, 'unresolvable source address');

            return;
        }

        $s->mappedAddress = $s->ip . ':' . $s->port;
        $this->logBinding($s);

        // ANTI-AMPLIFICATION: never emit a datagram larger than the one received. Build the believable
        // response (with SOFTWARE), then drop SOFTWARE, then drop the whole reply, before crossing the
        // request's size — so the reflection factor is always <= 1.
        $response = self::buildBindingResponse($msg['transactionId'], $s->ip, $s->port, $this->config->software);
        if (strlen($response) > strlen($data)) {
            $response = self::buildBindingResponse($msg['transactionId'], $s->ip, $s->port, '');
            if (strlen($response) > strlen($data)) {
                $response = '';
            }
        }

        $s->outbuf = $response;
    }

    // ---- Parsing ------------------------------------------------------------------------------

    /**
     * Parses a STUN message. Returns null on any malformed structure or a bad magic cookie so the
     * caller can log it as an unknown probe rather than faulting.
     *
     * @return array{messageType:int,messageLength:int,transactionId:string,attributes:array<int,string>,software:?string}|null
     */
    public static function parseMessage(string $data): ?array
    {
        if (strlen($data) < 20) {
            return null;
        }
        // The two most significant bits of a STUN message are zero (RFC 5389 6).
        if ((ord($data[0]) & 0xC0) !== 0) {
            return null;
        }

        $messageType = (ord($data[0]) << 8) | ord($data[1]);
        $messageLength = (ord($data[2]) << 8) | ord($data[3]);

        if (substr($data, 4, 4) !== self::MAGIC_COOKIE) {
            return null;
        }
        $transactionId = substr($data, 8, 12);

        // STUN attributes are always 4-byte aligned, so the message length is a multiple of four and
        // the declared body must be present.
        if ($messageLength % 4 !== 0 || 20 + $messageLength > strlen($data)) {
            return null;
        }

        $attributes = self::parseAttributes(substr($data, 20, $messageLength));
        if ($attributes === null) {
            return null;
        }

        return [
            'messageType' => $messageType,
            'messageLength' => $messageLength,
            'transactionId' => $transactionId,
            'attributes' => $attributes,
            'software' => $attributes[self::ATTR_SOFTWARE] ?? null,
        ];
    }

    /**
     * Parses the attribute list (type, length, value, 4-byte padding). Returns type => value, keeping
     * the first occurrence of each type. Returns null when an attribute claims a length past the body.
     *
     * @return array<int,string>|null
     */
    private static function parseAttributes(string $body): ?array
    {
        $attrs = [];
        $pos = 0;
        $n = strlen($body);
        $count = 0;

        while ($pos + 4 <= $n) {
            if (++$count > self::MAX_ATTRS) {
                break;
            }
            $type = (ord($body[$pos]) << 8) | ord($body[$pos + 1]);
            $len = (ord($body[$pos + 2]) << 8) | ord($body[$pos + 3]);
            $pos += 4;

            if ($pos + $len > $n) {
                return null; // truncated attribute value — malformed
            }
            $value = substr($body, $pos, $len);
            $pos += $len;
            $pos += (4 - ($len % 4)) % 4; // skip padding to the next 4-byte boundary

            if (!isset($attrs[$type])) {
                $attrs[$type] = $value;
            }
        }

        return $attrs;
    }

    // ---- Response building --------------------------------------------------------------------

    /**
     * Builds a Binding Success Response (0x0101) echoing the transaction id and carrying an
     * XOR-MAPPED-ADDRESS for the given source, optionally with a SOFTWARE attribute. This is the
     * uncapped response; the anti-amplification cap is applied by the caller.
     */
    public static function buildBindingResponse(string $transactionId, string $ip, int $port, string $software = ''): string
    {
        $attrs = self::xorMappedAddressAttr($ip, $port, $transactionId);
        if ($software !== '') {
            $attrs .= self::attribute(self::ATTR_SOFTWARE, $software);
        }

        return pack('n', self::MSG_BINDING_SUCCESS)
            . pack('n', strlen($attrs))
            . self::MAGIC_COOKIE
            . $transactionId
            . $attrs;
    }

    /**
     * Builds the XOR-MAPPED-ADDRESS attribute (RFC 5389 15.2): the port XORed with the high 16 bits of
     * the magic cookie and the address XORed with the magic cookie (IPv4) or the cookie + transaction
     * id (IPv6). Returns an empty string if the address cannot be packed.
     */
    public static function xorMappedAddressAttr(string $ip, int $port, string $transactionId): string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return '';
        }

        $xPort = pack('n', ($port & 0xFFFF) ^ self::MAGIC_HI16);

        if (strlen($packed) === 4) {
            $family = self::FAMILY_IPV4;
            $xAddr = $packed ^ self::MAGIC_COOKIE;
        } else {
            $family = self::FAMILY_IPV6;
            $mask = self::MAGIC_COOKIE . $transactionId; // 16 bytes
            $xAddr = $packed ^ substr($mask, 0, strlen($packed));
        }

        $value = "\x00" . chr($family) . $xPort . $xAddr;

        return self::attribute(self::ATTR_XOR_MAPPED_ADDRESS, $value);
    }

    /**
     * Decodes an XOR-MAPPED-ADDRESS attribute value back to a source ip:port. The transaction id is
     * only needed for the IPv6 mask. Returns null on a malformed / unknown-family value.
     *
     * @return array{ip:string,port:int}|null
     */
    public static function decodeXorMappedAddress(string $value, string $transactionId): ?array
    {
        if (strlen($value) < 8) {
            return null;
        }
        $family = ord($value[1]);
        $port = ((ord($value[2]) << 8) | ord($value[3])) ^ self::MAGIC_HI16;
        $xAddr = substr($value, 4);

        if ($family === self::FAMILY_IPV4) {
            if (strlen($xAddr) < 4) {
                return null;
            }
            $addr = substr($xAddr, 0, 4) ^ self::MAGIC_COOKIE;
        } elseif ($family === self::FAMILY_IPV6) {
            if (strlen($xAddr) < 16) {
                return null;
            }
            $mask = self::MAGIC_COOKIE . $transactionId;
            $addr = substr($xAddr, 0, 16) ^ substr($mask, 0, 16);
        } else {
            return null;
        }

        $ip = @inet_ntop($addr);
        if ($ip === false) {
            return null;
        }

        return ['ip' => $ip, 'port' => $port];
    }

    /** One STUN attribute: type(2), length(2), value, padded to a 4-byte boundary. */
    private static function attribute(int $type, string $value): string
    {
        $len = strlen($value);
        $pad = (4 - ($len % 4)) % 4;

        return pack('n', $type) . pack('n', $len) . $value . str_repeat("\x00", $pad);
    }

    // ---- Anti-reflection throttle -------------------------------------------------------------

    /**
     * Token-bucket admission for a UDP reply to $ip. Returns false when the apparent source has
     * drained its bucket, so the reply is dropped rather than reflected.
     */
    private function udpResponseAllowed(string $ip): bool
    {
        $now = microtime(true);

        if (!isset($this->udpResponseBuckets[$ip])) {
            // Bound the map: when full, drop the least-recently-refilled entry before adding one.
            if (count($this->udpResponseBuckets) >= self::UDP_BUCKET_MAX_IPS) {
                $oldestKey = null;
                $oldestAt = INF;
                foreach ($this->udpResponseBuckets as $k => $b) {
                    if ($b['last'] < $oldestAt) {
                        $oldestAt = $b['last'];
                        $oldestKey = $k;
                    }
                }
                if ($oldestKey !== null) {
                    unset($this->udpResponseBuckets[$oldestKey]);
                }
            }
            $this->udpResponseBuckets[$ip] = ['tokens' => self::UDP_RESP_BURST, 'last' => $now];
        }

        $bucket = &$this->udpResponseBuckets[$ip];
        $elapsed = max(0.0, $now - $bucket['last']);
        $bucket['tokens'] = min(self::UDP_RESP_BURST, $bucket['tokens'] + $elapsed * self::UDP_RESP_RATE);
        $bucket['last'] = $now;

        if ($bucket['tokens'] < 1.0) {
            return false;
        }
        $bucket['tokens'] -= 1.0;

        return true;
    }

    // ---- Logging ------------------------------------------------------------------------------

    private function logBinding(StunSession $s): void
    {
        $mapped = (string) $s->mappedAddress;
        $software = $s->software !== null ? self::printable($s->software) : '';

        $path = 'STUN Binding Request mapped=' . $mapped;
        if ($software !== '') {
            $path .= ' software=' . $software;
        }

        $this->logEvent([
            'event' => 'stun_binding',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'low',
            'path' => $path,
            'mapped' => $mapped,
            'software' => $software,
        ]);
    }

    private function logUnknown(StunSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'stun_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'STUN unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'STUN';
        $entry['proto'] = 'stun';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        ($this->logger)($entry);
    }

    /** Records a per-datagram fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => 3478,
                'path' => 'STUN internal fault: ' . $e->getMessage(),
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

    private static function splitAddr(string $addr): array
    {
        $lastColon = strrpos($addr, ':');
        if ($lastColon !== false) {
            return [substr($addr, 0, $lastColon), (int) substr($addr, $lastColon + 1)];
        }

        return [$addr, 3478];
    }
}

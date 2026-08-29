<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Coap;

/**
 * Zero-dependency, single-process UDP server for the low-interaction CoAP honeypot (port 5683,
 * RFC 7252 — the constrained-device IoT protocol). Speaks just enough CoAP in pure PHP to fingerprint
 * IoT scanners and capture the resource enumeration and payloads they push, on a non-blocking
 * stream_select loop over one UDP socket.
 *
 * Deliberately inert: it exposes no real device. GET /.well-known/core is answered with a fixed
 * link-format resource list; a GET of an advertised resource returns its cosmetic value, and anything
 * else degrades to 4.04 Not Found. Nothing is ever writable — a POST/PUT/DELETE is captured and
 * refused, never applied.
 *
 * Captured intel:
 * - the method (GET / POST / PUT / DELETE) and the Uri-Path an attacker probes (e.g. /.well-known/core,
 *   /large, device paths);
 * - any payload a POST/PUT tries to push.
 *
 * CoAP over UDP is a known DDoS reflection/amplification vector (a small GET /.well-known/core or
 * /large can pull a much larger response), so two hard anti-amplification guards apply to every reply:
 * 1. No emitted datagram is ever larger than the request that triggered it (amplification factor
 *    <= 1). A believable reply that would exceed the request is replaced with a payload-free response,
 *    or dropped, so the honeypot can never be turned into an amplifier — the /large target included.
 * 2. Replies are metered per source IP with a token bucket — a spoofed request forges its source as
 *    a victim, so every reply we emit lands on that victim.
 *
 * Every reply echoes the request's message id and token so it correlates like a real endpoint's.
 */
final class CoapServer
{
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const READ_CHUNK = 65535;        // a single UDP datagram
    private const INBUF_CAP = 65535;         // guard: a CoAP message never legitimately exceeds this
    private const MAX_DGRAMS_PER_TICK = 64;  // bound the drain so a flood can't spin one tick forever

    private const VERSION = 1;               // CoAP version (the 2-bit Ver field is always 1)
    private const DEFAULT_PORT = 5683;

    // Message types (2-bit T field).
    private const TYPE_CON = 0; // Confirmable
    private const TYPE_NON = 1; // Non-confirmable
    private const TYPE_ACK = 2; // Acknowledgement
    private const TYPE_RST = 3; // Reset

    // Request method codes (class 0).
    private const REQ_GET = 0x01;    // 0.01
    private const REQ_POST = 0x02;   // 0.02
    private const REQ_PUT = 0x03;    // 0.03
    private const REQ_DELETE = 0x04; // 0.04

    // Response codes we emit.
    private const RSP_CONTENT = 0x45;   // 2.05 Content
    private const RSP_NOT_FOUND = 0x84; // 4.04 Not Found

    // Option numbers (RFC 7252 §5.10).
    private const OPT_URI_PATH = 11;
    private const OPT_CONTENT_FORMAT = 12;
    private const OPT_URI_QUERY = 15;

    // Content-Format identifiers.
    private const CF_TEXT_PLAIN = 0;   // text/plain;charset=utf-8
    private const CF_LINK_FORMAT = 40; // application/link-format

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
        private CoapConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:5683").
     */
    public function run(string $bind): void
    {
        $sock = @stream_socket_server("udp://{$bind}", $errno, $errstr, STREAM_SERVER_BIND);
        if ($sock === false) {
            fwrite(STDERR, "funnypot-coap: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($sock, false);
        fwrite(STDERR, "funnypot-coap ({$this->config->deviceName}) listening on {$bind} (UDP)\n");

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
                $session = new CoapSession($ip, $clientPort, ++$id);
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
     * Parses the datagram held in $s->inbuf, captures the intel, logs the event, and queues a
     * size-capped response in $s->outbuf. Safe to drive directly with raw bytes in tests.
     */
    public function processInbound(CoapSession $s): void
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
        $s->requestLength = strlen($data);

        $req = self::parseMessage($data);
        if ($req === null) {
            $this->logUnknown($s, 'unparseable CoAP message');

            return;
        }

        $s->type = $req['type'];
        $s->code = $req['code'];
        $s->messageId = $req['messageId'];
        $s->token = $req['token'];
        $s->path = $req['uriPath'];
        $s->query = $req['uriQuery'];
        $s->payload = $req['payload'];
        $s->method = self::methodName($req['code']);

        if ($req['version'] !== self::VERSION) {
            $this->logUnknown($s, 'unsupported CoAP version ' . $req['version']);

            return;
        }

        // Empty message (code 0.00): a CON empty is a CoAP ping — a real endpoint answers with a RST.
        // Any other empty (NON/ACK/RST) is not a request: record only.
        if ($req['code'] === 0) {
            $this->logUnknown($s, sprintf('empty message (type %s)', self::typeName($req['type'])));
            if ($req['type'] === self::TYPE_CON) {
                $rst = self::encodeMessage(self::TYPE_RST, 0, $req['messageId'], '', [], '');
                $s->outbuf = $this->capReply($s, $rst, '');
            }

            return;
        }

        // Only method requests (code class 0) are requests we answer. A response class (2/4/5) inbound
        // is not a request: record, never reply (a bare reply is a reflection primitive).
        if ((($req['code'] >> 5) & 0x07) !== 0) {
            $this->logUnknown($s, sprintf('non-request code %s', self::codeName($req['code'])));

            return;
        }

        switch ($req['code']) {
            case self::REQ_GET:
                $this->handleGet($s, $req);
                break;

            case self::REQ_POST:
                $this->handlePost($s, $req);
                break;

            default:
                // PUT / DELETE / any other method: not modelled as writable.
                $this->handleOtherMethod($s, $req);
                break;
        }
    }

    // ---- Request handlers ---------------------------------------------------------------------

    /**
     * GET: the enumeration workhorse. Capture the resource probed, then answer /.well-known/core with
     * the link-format list, an advertised resource with its value, or 4.04 for anything else.
     *
     * @param array{type:int,code:int,messageId:int,token:string,uriPath:string,uriQuery:string,payload:string,...} $req
     */
    private function handleGet(CoapSession $s, array $req): void
    {
        $path = $req['uriPath'];

        $this->logEvent([
            'event' => 'coap_get',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $path === '/large' ? 'medium' : 'low',
            'path' => 'CoAP GET ' . $path . ($req['uriQuery'] !== '' ? '?' . $req['uriQuery'] : ''),
            'query' => $req['uriQuery'],
            'token' => bin2hex($req['token']),
        ]);

        if ($path === '/.well-known/core') {
            $primary = $this->buildResponse($req, self::RSP_CONTENT, $this->config->wellKnownCore, self::CF_LINK_FORMAT);
        } elseif (isset($this->config->resources[$path])) {
            $primary = $this->buildResponse($req, self::RSP_CONTENT, $this->config->resources[$path], self::CF_TEXT_PLAIN);
        } else {
            // 4.04 Not Found — tiny (header + token only), always within the anti-amplification cap.
            $s->outbuf = $this->capReply($s, $this->buildResponse($req, self::RSP_NOT_FOUND, '', null), '');

            return;
        }

        // ANTI-AMPLIFICATION: the believable content may exceed the request (the /large target always
        // does); fall back to a payload-free 2.05 that respects the cap, so the reply never amplifies.
        $fallback = $this->buildResponse($req, self::RSP_CONTENT, '', null);
        $s->outbuf = $this->capReply($s, $primary, $fallback);
    }

    /**
     * POST: capture the pushed payload, then acknowledge plausibly. INERT — the payload is recorded,
     * never stored or actuated.
     *
     * @param array{type:int,code:int,messageId:int,token:string,uriPath:string,uriQuery:string,payload:string,...} $req
     */
    private function handlePost(CoapSession $s, array $req): void
    {
        $this->logEvent([
            'event' => 'coap_post',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'medium',
            'path' => sprintf('CoAP POST %s (%d bytes payload)', $req['uriPath'], strlen($req['payload'])),
            'query' => $req['uriQuery'],
            'token' => bin2hex($req['token']),
            'payload' => self::printable(substr($req['payload'], 0, 256)),
        ]);

        // A bare 2.05 acknowledges the write without ever applying it, and is small enough to respect
        // the anti-amplification cap.
        $s->outbuf = $this->capReply($s, $this->buildResponse($req, self::RSP_CONTENT, '', null), '');
    }

    /**
     * PUT / DELETE / any other method: not modelled as writable. INERT — captured and refused with a
     * 4.04, never creating, changing, or deleting anything.
     *
     * @param array{type:int,code:int,messageId:int,token:string,uriPath:string,payload:string,...} $req
     */
    private function handleOtherMethod(CoapSession $s, array $req): void
    {
        $this->logEvent([
            'event' => 'coap_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'low',
            'path' => sprintf('CoAP %s %s', self::methodName($req['code']), $req['uriPath']),
            'token' => bin2hex($req['token']),
        ]);

        $s->outbuf = $this->capReply($s, $this->buildResponse($req, self::RSP_NOT_FOUND, '', null), '');
    }

    /**
     * Builds a response message echoing the request's type-appropriate ack, message id and token, with
     * an optional Content-Format option and body.
     *
     * @param array{type:int,messageId:int,token:string,...} $req
     */
    private function buildResponse(array $req, int $code, string $body, ?int $contentFormat): string
    {
        $options = [];
        if ($contentFormat !== null) {
            $options[] = [self::OPT_CONTENT_FORMAT, self::encodeUint($contentFormat)];
        }

        return self::encodeMessage(self::responseType($req['type']), $code, $req['messageId'], $req['token'], $options, $body);
    }

    /** A CON request draws a piggybacked ACK; a NON request draws a NON reply. */
    private static function responseType(int $requestType): int
    {
        return $requestType === self::TYPE_CON ? self::TYPE_ACK : self::TYPE_NON;
    }

    /**
     * ANTI-AMPLIFICATION cap for a reply to the request in $s. Returns $primary when it is no larger
     * than the request, else $fallback when that fits, else '' — so the reflection factor is <= 1.
     */
    private function capReply(CoapSession $s, string $primary, string $fallback): string
    {
        if (strlen($primary) <= $s->requestLength) {
            return $primary;
        }
        if ($fallback !== '' && strlen($fallback) <= $s->requestLength) {
            return $fallback;
        }

        return '';
    }

    // ---- Parsing ------------------------------------------------------------------------------

    /**
     * Parses a CoAP message (RFC 7252 §3): the 4-byte header, token, options (delta/length nibble
     * encoding), and any 0xFF-marked payload. Returns null on any malformed structure so the caller
     * can log it as an unknown probe rather than faulting.
     *
     * @return array{version:int,type:int,tokenLen:int,code:int,messageId:int,token:string,options:list<array{number:int,value:string}>,uriPath:string,uriQuery:string,contentFormat:?int,payload:string}|null
     */
    public static function parseMessage(string $data): ?array
    {
        $n = strlen($data);
        if ($n < 4) {
            return null;
        }

        $b0 = ord($data[0]);
        $version = ($b0 >> 6) & 0x03;
        $type = ($b0 >> 4) & 0x03;
        $tkl = $b0 & 0x0F;
        if ($tkl > 8) {
            return null; // token lengths 9-15 are reserved — a message format error
        }
        $code = ord($data[1]);
        $messageId = (ord($data[2]) << 8) | ord($data[3]);

        $pos = 4;
        if ($pos + $tkl > $n) {
            return null;
        }
        $token = substr($data, $pos, $tkl);
        $pos += $tkl;

        $options = [];
        $payload = '';
        $prev = 0;
        while ($pos < $n) {
            $b = ord($data[$pos]);
            if ($b === 0xFF) {
                $payload = substr($data, $pos + 1);
                if ($payload === '') {
                    return null; // a payload marker with no payload is a message format error
                }
                break;
            }

            $deltaNib = ($b >> 4) & 0x0F;
            $lenNib = $b & 0x0F;
            $pos++;

            $delta = self::readExtended($data, $pos, $n, $deltaNib);
            if ($delta === null) {
                return null;
            }
            $len = self::readExtended($data, $pos, $n, $lenNib);
            if ($len === null) {
                return null;
            }

            if ($pos + $len > $n) {
                return null;
            }
            $value = substr($data, $pos, $len);
            $pos += $len;

            $number = $prev + $delta;
            $prev = $number;
            $options[] = ['number' => $number, 'value' => $value];
        }

        // Assemble the CoAP request URI pieces from their options.
        $segments = [];
        $queries = [];
        $contentFormat = null;
        foreach ($options as $o) {
            if ($o['number'] === self::OPT_URI_PATH) {
                $segments[] = $o['value'];
            } elseif ($o['number'] === self::OPT_URI_QUERY) {
                $queries[] = $o['value'];
            } elseif ($o['number'] === self::OPT_CONTENT_FORMAT) {
                $contentFormat = self::decodeUint($o['value']);
            }
        }

        return [
            'version' => $version,
            'type' => $type,
            'tokenLen' => $tkl,
            'code' => $code,
            'messageId' => $messageId,
            'token' => $token,
            'options' => $options,
            'uriPath' => '/' . implode('/', $segments),
            'uriQuery' => implode('&', $queries),
            'contentFormat' => $contentFormat,
            'payload' => $payload,
        ];
    }

    /**
     * Resolves an option delta-or-length nibble, consuming any extended bytes at $pos. Returns null on
     * a truncated extension or the reserved value 15 (which is only ever the payload marker, handled
     * separately by the caller).
     */
    private static function readExtended(string $data, int &$pos, int $n, int $nibble): ?int
    {
        if ($nibble < 13) {
            return $nibble;
        }
        if ($nibble === 13) {
            if ($pos + 1 > $n) {
                return null;
            }
            $v = ord($data[$pos]) + 13;
            $pos += 1;

            return $v;
        }
        if ($nibble === 14) {
            if ($pos + 2 > $n) {
                return null;
            }
            $v = ((ord($data[$pos]) << 8) | ord($data[$pos + 1])) + 269;
            $pos += 2;

            return $v;
        }

        return null; // nibble 15 is reserved
    }

    // ---- Encoding -----------------------------------------------------------------------------

    /**
     * Encodes a CoAP message: the 4-byte header, token, options in delta/length nibble encoding, and a
     * 0xFF-marked payload when non-empty. Options are given as [number, value] pairs in any order.
     *
     * @param list<array{0:int,1:string}> $options
     */
    public static function encodeMessage(int $type, int $code, int $messageId, string $token, array $options, string $payload): string
    {
        $token = substr($token, 0, 8);
        $tkl = strlen($token);

        $out = chr((self::VERSION << 6) | (($type & 0x03) << 4) | ($tkl & 0x0F));
        $out .= chr($code & 0xFF);
        $out .= chr(($messageId >> 8) & 0xFF) . chr($messageId & 0xFF);
        $out .= $token;

        // Options are delta-encoded against the previous option number, so they must be emitted in
        // ascending order (PHP 8 sort is stable, keeping equal-numbered options in insertion order).
        usort($options, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
        $prev = 0;
        foreach ($options as [$number, $value]) {
            $delta = $number - $prev;
            $len = strlen($value);
            [$deltaNib, $deltaExt] = self::extendedBytes($delta);
            [$lenNib, $lenExt] = self::extendedBytes($len);
            $out .= chr(($deltaNib << 4) | $lenNib) . $deltaExt . $lenExt . $value;
            $prev = $number;
        }

        if ($payload !== '') {
            $out .= "\xFF" . $payload;
        }

        return $out;
    }

    /**
     * Splits a delta or length into its 4-bit nibble and any extended bytes (RFC 7252 §3.1).
     *
     * @return array{0:int,1:string}
     */
    private static function extendedBytes(int $v): array
    {
        if ($v < 13) {
            return [$v, ''];
        }
        if ($v < 269) {
            return [13, chr($v - 13)];
        }

        return [14, pack('n', $v - 269)];
    }

    /** Minimal big-endian encoding of a CoAP uint option value (0 => empty, per §3.2). */
    private static function encodeUint(int $v): string
    {
        if ($v <= 0) {
            return '';
        }
        $bytes = '';
        while ($v > 0) {
            $bytes = chr($v & 0xFF) . $bytes;
            $v >>= 8;
        }

        return $bytes;
    }

    /** Decodes a CoAP uint option value (big-endian, empty => 0). */
    private static function decodeUint(string $bytes): int
    {
        $v = 0;
        $len = strlen($bytes);
        for ($i = 0; $i < $len; $i++) {
            $v = ($v << 8) | ord($bytes[$i]);
        }

        return $v;
    }

    // ---- Naming (intel readability) -----------------------------------------------------------

    private static function methodName(int $code): string
    {
        return match ($code) {
            self::REQ_GET => 'GET',
            self::REQ_POST => 'POST',
            self::REQ_PUT => 'PUT',
            self::REQ_DELETE => 'DELETE',
            default => self::codeName($code),
        };
    }

    /** CoAP code in c.dd form (class in the top 3 bits, detail in the low 5). */
    private static function codeName(int $code): string
    {
        return sprintf('%d.%02d', ($code >> 5) & 0x07, $code & 0x1F);
    }

    private static function typeName(int $type): string
    {
        return match ($type) {
            self::TYPE_CON => 'CON',
            self::TYPE_NON => 'NON',
            self::TYPE_ACK => 'ACK',
            self::TYPE_RST => 'RST',
            default => '?',
        };
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

    private function logUnknown(CoapSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'coap_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'CoAP unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'COAP';
        $entry['proto'] = 'coap';
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
                'port' => self::DEFAULT_PORT,
                'path' => 'CoAP internal fault: ' . $e->getMessage(),
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

        return [$addr, self::DEFAULT_PORT];
    }
}

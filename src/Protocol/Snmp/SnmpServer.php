<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Snmp;

use Funnypot\Protocol\UdpResponseBucket;

/**
 * Zero-dependency, single-process UDP server for the low-interaction SNMP honeypot (port 161).
 * Speaks just enough SNMP v1 / v2c (ASN.1/BER) in pure PHP to fingerprint scanners and harvest the
 * community strings brute-forcers spray, on a non-blocking stream_select loop over one UDP socket.
 *
 * Deliberately inert: it exposes no real management data. The system group (sysDescr, sysObjectID,
 * sysUpTime, sysName, ...) is answered from fixed persona strings; every other OID degrades to a
 * no-such-object varbind, and a SET is captured and refused, never applied.
 *
 * Captured intel:
 * - the community string offered (the SNMP "password" — public/private/etc.)
 * - the SNMP version and PDU type (GET / GETNEXT / GETBULK / SET)
 * - the requested OIDs
 *
 * SNMP is a notorious DDoS reflection/amplification vector, so two hard anti-amplification guards
 * apply to every reply:
 * 1. GETBULK is never expanded — its repetition count is ignored and it is answered like a single
 *    GETNEXT, so a bulk request can never pull a large table.
 * 2. No emitted datagram is ever larger than the request that triggered it (amplification factor
 *    <= 1). A believable full response that would exceed the request is replaced with a size-safe
 *    echo, or dropped, so the honeypot can never be turned into an amplifier.
 * On top of that, replies are metered per source IP with a token bucket (a spoofed request forges
 * its source as a victim, so every reply we emit lands on that victim).
 */
final class SnmpServer
{
    use UdpResponseBucket;

    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const READ_CHUNK = 65535;        // a single UDP datagram
    private const INBUF_CAP = 65535;         // guard: an SNMP message never legitimately exceeds this
    private const MAX_DGRAMS_PER_TICK = 64;  // bound the drain so a flood can't spin one tick forever
    private const MAX_OIDS = 256;            // cap varbinds parsed from one request

    // SNMP versions on the wire.
    private const VERSION_V1 = 0;
    private const VERSION_V2C = 1;

    // ASN.1/BER universal types.
    private const T_INTEGER = 0x02;
    private const T_OCTET_STRING = 0x04;
    private const T_NULL = 0x05;
    private const T_OID = 0x06;
    private const T_SEQUENCE = 0x30;

    // SNMP application types.
    private const T_TIMETICKS = 0x43;

    // SNMP v2c varbind exception values (context-specific, primitive).
    private const EXC_NO_SUCH_OBJECT = "\x80\x00";
    private const EXC_END_OF_MIB_VIEW = "\x82\x00";

    // PDU tags (context-specific, constructed).
    private const PDU_GET = 0xA0;
    private const PDU_GETNEXT = 0xA1;
    private const PDU_RESPONSE = 0xA2;
    private const PDU_SET = 0xA3;
    private const PDU_TRAP_V1 = 0xA4;
    private const PDU_GETBULK = 0xA5;
    private const PDU_INFORM = 0xA6;
    private const PDU_TRAP_V2 = 0xA7;
    private const PDU_REPORT = 0xA8;

    // Error-status values (MS/RFC 1157 & 3416).
    private const ERR_NO_ERROR = 0;
    private const ERR_NO_SUCH_NAME = 2; // v1
    private const ERR_NOT_WRITABLE = 17; // v2c

    // System group OIDs (MIB-2 1.3.6.1.2.1.1).
    private const OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0';
    private const OID_SYS_OBJECT_ID = '1.3.6.1.2.1.1.2.0';
    private const OID_SYS_UPTIME = '1.3.6.1.2.1.1.3.0';
    private const OID_SYS_CONTACT = '1.3.6.1.2.1.1.4.0';
    private const OID_SYS_NAME = '1.3.6.1.2.1.1.5.0';
    private const OID_SYS_LOCATION = '1.3.6.1.2.1.1.6.0';
    private const OID_SYS_SERVICES = '1.3.6.1.2.1.1.7.0';

    // Per-source-IP token bucket throttling UDP responses (anti-reflection); see UdpResponseBucket.
    // A spoofed request forges its source as a victim, so every reply we emit lands on that victim —
    // capping replies per apparent source bounds how hard the honeypot can be turned into a reflector.
    private const UDP_RESP_BURST = 20.0;      // bucket capacity
    private const UDP_RESP_RATE = 10.0;       // tokens refilled per second
    private const UDP_BUCKET_MAX_IPS = 4096;  // cap tracked IPs so the map can't grow unbounded
    // FP-0248: a new/evicted-and-re-admitted IP is seeded DEPLETED, not a full burst — see the trait's
    // doc block for why this defeats spoofed-source-rotation LRU cycling and why 2.0 (not 1.0).
    private const UDP_RESP_SEED = 2.0;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private SnmpConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:161").
     */
    public function run(string $bind): void
    {
        $sock = @stream_socket_server("udp://{$bind}", $errno, $errstr, STREAM_SERVER_BIND);
        if ($sock === false) {
            fwrite(STDERR, "funnypot-snmp: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($sock, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-snmp ({$this->config->sysName}) listening on {$bind} (UDP)\n");

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
                $session = new SnmpSession($ip, $clientPort, ++$id);
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
     * Parses the datagram held in $s->inbuf, captures the community + OIDs, logs the query, and queues
     * a size-capped response in $s->outbuf. Safe to drive directly with raw bytes in tests.
     */
    public function processInbound(SnmpSession $s): void
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

        $req = self::parseMessage($data);
        if ($req === null) {
            $this->logUnknown($s, 'unparseable SNMP message');

            return;
        }

        $s->version = $req['version'];
        $s->community = $req['community'];
        $s->pduTag = $req['pduTag'];
        $s->oids = $req['oids'];

        if ($req['version'] !== self::VERSION_V1 && $req['version'] !== self::VERSION_V2C) {
            // v3 and anything else is out of scope: record the probe, never reply.
            $this->logUnknown($s, 'unsupported SNMP version ' . $req['version']);

            return;
        }

        $tag = $req['pduTag'];

        // Responses, traps and reports are not requests: never reply (that would be a reflection
        // primitive with no client waiting), only record.
        if (in_array($tag, [self::PDU_RESPONSE, self::PDU_TRAP_V1, self::PDU_TRAP_V2, self::PDU_REPORT], true)) {
            $this->logUnknown($s, sprintf('non-request PDU 0x%02X', $tag));

            return;
        }

        // Record the captured intel for every request PDU we recognise.
        $this->logQuery($s, $req);

        if (!in_array($tag, [self::PDU_GET, self::PDU_GETNEXT, self::PDU_GETBULK, self::PDU_SET], true)) {
            // e.g. InformRequest — recognised but not modelled; captured above, no reply.
            return;
        }

        $response = $this->buildResponse($req);

        // ANTI-AMPLIFICATION: never emit a datagram larger than the one received. A believable full
        // response (e.g. a real sysDescr) that would exceed the request is replaced with a size-safe
        // echo, and if even that would not fit, dropped — so the reflection factor is always <= 1.
        if (strlen($response) > strlen($data)) {
            $response = $this->buildSizeSafeEcho($req);
            if (strlen($response) > strlen($data)) {
                $response = '';
            }
        }

        $s->outbuf = $response;
    }

    // ---- Parsing ------------------------------------------------------------------------------

    /**
     * Parses an SNMP v1/v2c message. Returns null on any malformed structure so the caller can log it
     * as an unknown probe rather than faulting.
     *
     * @return array{version:int,community:string,pduTag:int,requestIdBytes:string,field1:int,field2:int,oids:list<string>}|null
     */
    public static function parseMessage(string $data): ?array
    {
        $pos = 0;
        $top = self::readTlv($data, $pos);
        if ($top === null || $top[0] !== self::T_SEQUENCE) {
            return null;
        }
        $body = $top[1];

        $p = 0;
        $vTlv = self::readTlv($body, $p);
        if ($vTlv === null || $vTlv[0] !== self::T_INTEGER) {
            return null;
        }
        $version = self::decodeInt($vTlv[1]);

        $cTlv = self::readTlv($body, $p);
        if ($cTlv === null || $cTlv[0] !== self::T_OCTET_STRING) {
            return null;
        }
        $community = $cTlv[1];

        $pduTlv = self::readTlv($body, $p);
        if ($pduTlv === null || $pduTlv[0] < 0xA0 || $pduTlv[0] > 0xA8) {
            return null;
        }
        $pduTag = $pduTlv[0];
        $pdu = $pduTlv[1];

        // The v1 Trap PDU has a different fixed shape (enterprise/agent-addr/...); we never reply to
        // it, so capture only version + community + tag and stop.
        if ($pduTag === self::PDU_TRAP_V1) {
            return [
                'version' => $version, 'community' => $community, 'pduTag' => $pduTag,
                'requestIdBytes' => '', 'field1' => 0, 'field2' => 0, 'oids' => [],
            ];
        }

        $pp = 0;
        $ridTlv = self::readTlv($pdu, $pp);
        if ($ridTlv === null || $ridTlv[0] !== self::T_INTEGER) {
            return null;
        }
        $requestIdBytes = $ridTlv[1];

        $f1Tlv = self::readTlv($pdu, $pp);
        if ($f1Tlv === null || $f1Tlv[0] !== self::T_INTEGER) {
            return null;
        }
        $field1 = self::decodeInt($f1Tlv[1]);

        $f2Tlv = self::readTlv($pdu, $pp);
        if ($f2Tlv === null || $f2Tlv[0] !== self::T_INTEGER) {
            return null;
        }
        $field2 = self::decodeInt($f2Tlv[1]);

        $vblTlv = self::readTlv($pdu, $pp);
        if ($vblTlv === null || $vblTlv[0] !== self::T_SEQUENCE) {
            return null;
        }
        $vbl = $vblTlv[1];

        $oids = [];
        $vp = 0;
        while ($vp < strlen($vbl) && count($oids) < self::MAX_OIDS) {
            $vbTlv = self::readTlv($vbl, $vp);
            if ($vbTlv === null || $vbTlv[0] !== self::T_SEQUENCE) {
                return null;
            }
            $q = 0;
            $nameTlv = self::readTlv($vbTlv[1], $q);
            if ($nameTlv === null || $nameTlv[0] !== self::T_OID) {
                return null;
            }
            $oids[] = self::decodeOid($nameTlv[1]);
            // The value half of a request varbind is NULL; it carries no intel, so it is ignored.
        }

        return [
            'version' => $version, 'community' => $community, 'pduTag' => $pduTag,
            'requestIdBytes' => $requestIdBytes, 'field1' => $field1, 'field2' => $field2, 'oids' => $oids,
        ];
    }

    /**
     * Reads one BER TLV at $pos, advancing $pos past it. Returns [tag, value] or null on any bounds
     * error / unsupported (indefinite / absurd) length.
     *
     * @return array{0:int,1:string}|null
     */
    private static function readTlv(string $buf, int &$pos): ?array
    {
        $n = strlen($buf);
        if ($pos + 2 > $n) {
            return null;
        }
        $tag = ord($buf[$pos]);
        $lenByte = ord($buf[$pos + 1]);
        $p = $pos + 2;

        if ($lenByte < 0x80) {
            $len = $lenByte;
        } else {
            $numBytes = $lenByte & 0x7F;
            if ($numBytes === 0 || $numBytes > 4) {
                return null; // indefinite form or an implausibly long length
            }
            if ($p + $numBytes > $n) {
                return null;
            }
            $len = 0;
            for ($i = 0; $i < $numBytes; $i++) {
                $len = ($len << 8) | ord($buf[$p + $i]);
            }
            $p += $numBytes;
        }

        if ($len < 0 || $p + $len > $n) {
            return null;
        }
        $value = substr($buf, $p, $len);
        $pos = $p + $len;

        return [$tag, $value];
    }

    /** Decodes a big-endian two's-complement BER INTEGER. */
    private static function decodeInt(string $bytes): int
    {
        if ($bytes === '') {
            return 0;
        }
        $len = strlen($bytes);
        $v = 0;
        for ($i = 0; $i < $len; $i++) {
            $v = ($v << 8) | ord($bytes[$i]);
        }
        if ((ord($bytes[0]) & 0x80) !== 0 && $len < 8) {
            $v -= (1 << (8 * $len)); // sign-extend negatives
        }

        return $v;
    }

    /** Decodes a BER OBJECT IDENTIFIER value into dotted form. */
    public static function decodeOid(string $bytes): string
    {
        if ($bytes === '') {
            return '';
        }
        $b0 = ord($bytes[0]);
        if ($b0 < 40) {
            $parts = [0, $b0];
        } elseif ($b0 < 80) {
            $parts = [1, $b0 - 40];
        } else {
            $parts = [2, $b0 - 80];
        }

        $val = 0;
        for ($i = 1; $i < strlen($bytes); $i++) {
            $c = ord($bytes[$i]);
            $val = ($val << 7) | ($c & 0x7F);
            if (($c & 0x80) === 0) {
                $parts[] = $val;
                $val = 0;
            }
        }

        return implode('.', $parts);
    }

    // ---- Response building --------------------------------------------------------------------

    /**
     * Builds the SNMP GetResponse for a parsed request from the fixed system-group MIB. This is the
     * uncapped, believable response; the anti-amplification cap is applied by the caller.
     *
     * @param array{version:int,community:string,pduTag:int,requestIdBytes:string,field1:int,field2:int,oids:list<string>} $req
     */
    public function buildResponse(array $req): string
    {
        $tag = $req['pduTag'];
        $v2 = ($req['version'] === self::VERSION_V2C);
        $mib = $this->mib();

        $errStatus = self::ERR_NO_ERROR;
        $errIndex = 0;
        $varbinds = [];

        if ($tag === self::PDU_GET) {
            $i = 0;
            foreach ($req['oids'] as $oid) {
                $i++;
                if (isset($mib[$oid])) {
                    $varbinds[] = self::varbind($oid, $mib[$oid]);
                } elseif ($v2) {
                    $varbinds[] = self::varbind($oid, self::EXC_NO_SUCH_OBJECT);
                } else {
                    if ($errStatus === self::ERR_NO_ERROR) {
                        $errStatus = self::ERR_NO_SUCH_NAME;
                        $errIndex = $i;
                    }
                    $varbinds[] = self::varbind($oid, "\x05\x00");
                }
            }
        } elseif ($tag === self::PDU_GETNEXT || $tag === self::PDU_GETBULK) {
            // GETBULK is answered as a single GETNEXT per varbind: its repetition count is deliberately
            // ignored so a bulk request can never expand the reply into a table (anti-amplification).
            $i = 0;
            foreach ($req['oids'] as $oid) {
                $i++;
                $next = self::nextOid($mib, $oid);
                if ($next !== null) {
                    $varbinds[] = self::varbind($next, $mib[$next]);
                } elseif ($v2) {
                    $varbinds[] = self::varbind($oid, self::EXC_END_OF_MIB_VIEW);
                } else {
                    if ($errStatus === self::ERR_NO_ERROR) {
                        $errStatus = self::ERR_NO_SUCH_NAME;
                        $errIndex = $i;
                    }
                    $varbinds[] = self::varbind($oid, "\x05\x00");
                }
            }
        } else { // PDU_SET
            // INERT: a write is never applied. Refuse the whole set and echo NULL values.
            $errStatus = $v2 ? self::ERR_NOT_WRITABLE : self::ERR_NO_SUCH_NAME;
            $errIndex = count($req['oids']) > 0 ? 1 : 0;
            foreach ($req['oids'] as $oid) {
                $varbinds[] = self::varbind($oid, "\x05\x00");
            }
        }

        // v1 error semantics: on an error the whole varbind list is echoed with NULL values.
        if (!$v2 && $errStatus !== self::ERR_NO_ERROR) {
            $varbinds = [];
            foreach ($req['oids'] as $oid) {
                $varbinds[] = self::varbind($oid, "\x05\x00");
            }
        }

        return $this->wrapResponse($req, $errStatus, $errIndex, $varbinds);
    }

    /**
     * A minimal GetResponse echoing the request OIDs with empty (NULL / noSuchObject) values. It is
     * never larger than the request — the varbind values match the request's own NULL values and the
     * error fields are single-byte — so it is the safe fallback when a full response would amplify.
     *
     * @param array{version:int,community:string,pduTag:int,requestIdBytes:string,field1:int,field2:int,oids:list<string>} $req
     */
    private function buildSizeSafeEcho(array $req): string
    {
        $v2 = ($req['version'] === self::VERSION_V2C);
        $errStatus = $v2 ? self::ERR_NO_ERROR : self::ERR_NO_SUCH_NAME;
        $errIndex = $v2 ? 0 : (count($req['oids']) > 0 ? 1 : 0);

        $varbinds = [];
        foreach ($req['oids'] as $oid) {
            $varbinds[] = self::varbind($oid, $v2 ? self::EXC_NO_SUCH_OBJECT : "\x05\x00");
        }

        return $this->wrapResponse($req, $errStatus, $errIndex, $varbinds);
    }

    /**
     * Wraps a response PDU: version + community echoed, request-id echoed byte-for-byte, the given
     * error fields, and the varbind list.
     *
     * @param array{version:int,community:string,requestIdBytes:string,...} $req
     * @param list<string> $varbinds
     */
    private function wrapResponse(array $req, int $errStatus, int $errIndex, array $varbinds): string
    {
        $vbl = self::berTlv(self::T_SEQUENCE, implode('', $varbinds));
        $pdu = self::berTlv(
            self::PDU_RESPONSE,
            self::berTlv(self::T_INTEGER, $req['requestIdBytes'])
            . self::berInteger($errStatus)
            . self::berInteger($errIndex)
            . $vbl
        );

        return self::berTlv(
            self::T_SEQUENCE,
            self::berInteger($req['version'])
            . self::berTlv(self::T_OCTET_STRING, $req['community'])
            . $pdu
        );
    }

    /**
     * The fixed system-group MIB: dotted OID => encoded value TLV. Every value is cosmetic persona,
     * never real management data.
     *
     * @return array<string,string>
     */
    private function mib(): array
    {
        return [
            self::OID_SYS_DESCR => self::berTlv(self::T_OCTET_STRING, $this->config->sysDescr),
            self::OID_SYS_OBJECT_ID => self::berTlv(self::T_OID, self::encodeOid($this->config->sysObjectId)),
            self::OID_SYS_UPTIME => self::berUnsigned(self::T_TIMETICKS, $this->config->sysUpTimeTicks()),
            self::OID_SYS_CONTACT => self::berTlv(self::T_OCTET_STRING, $this->config->sysContact),
            self::OID_SYS_NAME => self::berTlv(self::T_OCTET_STRING, $this->config->sysName),
            self::OID_SYS_LOCATION => self::berTlv(self::T_OCTET_STRING, $this->config->sysLocation),
            self::OID_SYS_SERVICES => self::berInteger($this->config->sysServices),
        ];
    }

    /**
     * The first MIB OID strictly greater than $oid (lexicographic on the numeric arcs), or null when
     * $oid is at or past the end of the modelled tree.
     *
     * @param array<string,string> $mib
     */
    private static function nextOid(array $mib, string $oid): ?string
    {
        $keys = array_keys($mib);
        usort($keys, [self::class, 'oidCmp']);
        foreach ($keys as $k) {
            if (self::oidCmp($k, $oid) > 0) {
                return $k;
            }
        }

        return null;
    }

    /** Numeric lexicographic comparison of two dotted OIDs. */
    private static function oidCmp(string $a, string $b): int
    {
        $pa = array_map('intval', explode('.', $a));
        $pb = array_map('intval', explode('.', $b));
        $n = min(count($pa), count($pb));
        for ($i = 0; $i < $n; $i++) {
            if ($pa[$i] !== $pb[$i]) {
                return $pa[$i] <=> $pb[$i];
            }
        }

        return count($pa) <=> count($pb);
    }

    /** SEQUENCE { OID name, value } for one varbind. */
    private static function varbind(string $oid, string $valueTlv): string
    {
        return self::berTlv(self::T_SEQUENCE, self::berTlv(self::T_OID, self::encodeOid($oid)) . $valueTlv);
    }

    // ---- BER encoding helpers -----------------------------------------------------------------

    private static function berTlv(int $tag, string $value): string
    {
        return chr($tag) . self::berLen(strlen($value)) . $value;
    }

    private static function berLen(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xFF) . $bytes;
            $len >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /** Minimal two's-complement BER INTEGER. */
    private static function berInteger(int $n): string
    {
        $bytes = '';
        while (true) {
            $bytes = chr($n & 0xFF) . $bytes;
            $n >>= 8; // arithmetic shift: sign is preserved for negatives
            $top = ord($bytes[0]);
            if ($n === 0 && ($top & 0x80) === 0) {
                break;
            }
            if ($n === -1 && ($top & 0x80) !== 0) {
                break;
            }
        }

        return chr(self::T_INTEGER) . self::berLen(strlen($bytes)) . $bytes;
    }

    /** Minimal unsigned encoding for an application primitive (TimeTicks / Gauge / Counter). */
    private static function berUnsigned(int $tag, int $n): string
    {
        $n &= 0xFFFFFFFF;
        if ($n === 0) {
            $body = "\x00";
        } else {
            $body = '';
            while ($n > 0) {
                $body = chr($n & 0xFF) . $body;
                $n >>= 8;
            }
        }

        return chr($tag) . self::berLen(strlen($body)) . $body;
    }

    /** Encodes a dotted OID into its BER value bytes (no tag/length). */
    public static function encodeOid(string $dotted): string
    {
        $parts = array_map('intval', explode('.', $dotted));
        if (count($parts) < 2) {
            $parts = array_pad($parts, 2, 0);
        }
        $body = self::base128($parts[0] * 40 + $parts[1]);
        for ($i = 2; $i < count($parts); $i++) {
            $body .= self::base128($parts[$i]);
        }

        return $body;
    }

    private static function base128(int $v): string
    {
        $out = chr($v & 0x7F);
        $v >>= 7;
        while ($v > 0) {
            $out = chr(($v & 0x7F) | 0x80) . $out;
            $v >>= 7;
        }

        return $out;
    }

    // ---- Anti-reflection throttle -------------------------------------------------------------
    // udpResponseAllowed() lives in the shared UdpResponseBucket trait (`use` above).

    // ---- Logging ------------------------------------------------------------------------------

    /**
     * @param array{version:int,community:string,pduTag:int,oids:list<string>,...} $req
     */
    private function logQuery(SnmpSession $s, array $req): void
    {
        $isSet = $req['pduTag'] === self::PDU_SET;
        $verName = $req['version'] === self::VERSION_V1 ? 'v1' : 'v2c';
        $community = self::printable($req['community']);
        $oidList = implode(', ', array_slice($req['oids'], 0, 16));

        $this->logEvent([
            'event' => $isSet ? 'snmp_set' : 'snmp_get',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $isSet ? 'high' : $this->communitySeverity($req['community']),
            'path' => sprintf(
                'SNMP %s %s community=%s oids=[%s]',
                $verName,
                self::pduName($req['pduTag']),
                $community,
                $oidList
            ),
            'community' => $community,
            'oids' => implode(',', $req['oids']),
        ]);
    }

    /** A write community or a known privileged name is higher-value intel than a bare read probe. */
    private function communitySeverity(string $community): string
    {
        $privileged = ['private', 'write', 'secret', 'manager', 'admin', 'security'];

        return in_array(strtolower($community), $privileged, true) ? 'high' : 'medium';
    }

    private static function pduName(int $tag): string
    {
        return match ($tag) {
            self::PDU_GET => 'GET',
            self::PDU_GETNEXT => 'GETNEXT',
            self::PDU_GETBULK => 'GETBULK',
            self::PDU_SET => 'SET',
            self::PDU_INFORM => 'INFORM',
            default => sprintf('PDU(0x%02X)', $tag),
        };
    }

    private function logUnknown(SnmpSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'snmp_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'SNMP unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'SNMP';
        $entry['proto'] = 'snmp';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        // FP-0247 (Fix A): single-datagram UDP is spoofable — fail-closed. Only a verified round-trip
        // may upgrade this (see SipServer's $validRoundTrip). `??=` so a future per-event upgrade wins.
        $entry['reportable'] ??= false;
        ($this->logger)($entry);
    }

    /** Records a per-datagram fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => 161,
                'path' => 'SNMP internal fault: ' . $e->getMessage(),
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

        return [$addr, 161];
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 161;
    }
}

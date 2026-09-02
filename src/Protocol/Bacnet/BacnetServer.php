<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Bacnet;

/**
 * Zero-dependency, single-process UDP server for the low-interaction BACnet/IP honeypot (port 47808,
 * 0xBAC0). Speaks just enough of the building-automation stack (BVLC + NPDU + APDU, ASHRAE 135) in
 * pure PHP to fingerprint OT/ICS scanners and capture the device/point enumeration recon they run,
 * on a non-blocking stream_select loop over one UDP socket.
 *
 * Deliberately inert: it exposes no real building data. Who-Is is answered with an I-Am built from
 * fixed persona; ReadProperty of the advertised Device object returns cosmetic strings, and every
 * other object/property degrades to a BACnet error. Nothing is ever writable — a write reaches us as
 * an unmodelled confirmed service, is captured, and is refused, never applied.
 *
 * Captured intel:
 * - Who-Is discovery scans and the device-instance range being swept.
 * - ReadProperty enumeration: the object type/instance and property id an attacker is probing.
 *
 * BACnet/IP is a known DDoS reflection/amplification vector, so two hard anti-amplification guards
 * apply to every reply:
 * 1. No emitted datagram is ever larger than the request that triggered it (amplification factor
 *    <= 1). A believable reply that would exceed the request is replaced with a size-safe fallback
 *    (a tiny abort/error, exactly what a non-segmenting device sends when a reply will not fit), or
 *    dropped, so the honeypot can never be turned into an amplifier.
 * 2. Replies are metered per source IP with a token bucket — a spoofed request forges its source as
 *    a victim, so every reply we emit lands on that victim.
 */
final class BacnetServer
{
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const READ_CHUNK = 65535;        // a single UDP datagram
    private const INBUF_CAP = 65535;         // guard: a BACnet/IP message never legitimately exceeds this
    private const MAX_DGRAMS_PER_TICK = 64;  // bound the drain so a flood can't spin one tick forever

    private const DEFAULT_PORT = 47808;

    // BVLC (BACnet Virtual Link Control) header.
    private const BVLC_TYPE = 0x81;                 // BACnet/IP
    private const BVLC_ORIGINAL_UNICAST = 0x0A;
    private const BVLC_ORIGINAL_BROADCAST = 0x0B;
    private const BVLC_FORWARDED = 0x04;            // prefixed with a 6-byte originating B/IP address

    private const NPDU_VERSION = 0x01;

    // APDU type (high nibble of the first APDU byte).
    private const APDU_CONFIRMED_REQ = 0x0;
    private const APDU_UNCONFIRMED_REQ = 0x1;
    private const APDU_COMPLEX_ACK = 0x3;
    private const APDU_ERROR = 0x5;
    private const APDU_REJECT = 0x6;
    private const APDU_ABORT = 0x7;

    // Unconfirmed service choices.
    private const SVC_I_AM = 0x00;
    private const SVC_WHO_IS = 0x08;

    // Confirmed service choices.
    private const SVC_READ_PROPERTY = 0x0C;

    // BACnet object types.
    private const OBJ_DEVICE = 8;

    // BACnet property identifiers we model on the Device object.
    private const PROP_OBJECT_IDENTIFIER = 75;
    private const PROP_OBJECT_NAME = 77;
    private const PROP_OBJECT_TYPE = 79;
    private const PROP_OBJECT_LIST = 76;
    private const PROP_MODEL_NAME = 70;
    private const PROP_VENDOR_NAME = 121;
    private const PROP_VENDOR_IDENTIFIER = 120;
    private const PROP_FIRMWARE_REVISION = 44;
    private const PROP_APP_SOFTWARE_VERSION = 12;
    private const PROP_SYSTEM_STATUS = 112;
    private const PROP_PROTOCOL_VERSION = 98;
    private const PROP_PROTOCOL_REVISION = 139;
    private const PROP_DESCRIPTION = 28;

    // BACnet application data-type tag numbers (application class).
    private const TAG_UNSIGNED = 2;
    private const TAG_CHARACTER_STRING = 7;
    private const TAG_ENUMERATED = 9;
    private const TAG_OBJECT_ID = 12;

    // Error / reject / abort codes (ASHRAE 135 Clause 18).
    private const ERROR_CLASS_OBJECT = 1;
    private const ERROR_CLASS_PROPERTY = 2;
    private const ERROR_CODE_UNKNOWN_OBJECT = 31;
    private const ERROR_CODE_UNKNOWN_PROPERTY = 32;
    private const ABORT_BUFFER_OVERFLOW = 1;
    private const REJECT_UNRECOGNIZED_SERVICE = 9;

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
        private BacnetConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:47808").
     */
    public function run(string $bind): void
    {
        $sock = @stream_socket_server("udp://{$bind}", $errno, $errstr, STREAM_SERVER_BIND);
        if ($sock === false) {
            fwrite(STDERR, "funnypot-bacnet: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($sock, false);
        fwrite(STDERR, "funnypot-bacnet ({$this->config->objectName}) listening on {$bind} (UDP)\n");

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
                $session = new BacnetSession($ip, $clientPort, ++$id);
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
    public function processInbound(BacnetSession $s): void
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
        if (strlen($data) < 4 || ord($data[0]) !== self::BVLC_TYPE) {
            $this->logUnknown($s, 'not a BACnet/IP message (bad BVLC type)');

            return;
        }

        $s->requestLength = strlen($data);
        $s->bvlcFunction = ord($data[1]);

        $apduOffset = self::apduOffset($data);
        if ($apduOffset === null || $apduOffset >= strlen($data)) {
            // BBMD management, a network-layer (routing) message, or an unparseable envelope: no APDU
            // to model. Capture the probe, never reply (a bare reply is a reflection primitive).
            $this->logUnknown($s, sprintf('no APDU (BVLC function 0x%02X)', $s->bvlcFunction));

            return;
        }

        $apdu = substr($data, $apduOffset);
        $s->apduType = (ord($apdu[0]) >> 4) & 0x0F;

        $response = '';
        switch ($s->apduType) {
            case self::APDU_UNCONFIRMED_REQ:
                $response = $this->handleUnconfirmed($s, $apdu);
                break;

            case self::APDU_CONFIRMED_REQ:
                $response = $this->handleConfirmed($s, $apdu);
                break;

            default:
                // ACKs, errors, aborts and rejects inbound are responses, not requests: record only.
                $this->logUnknown($s, sprintf('non-request APDU type 0x%X', $s->apduType));

                return;
        }

        $s->outbuf = $response;
    }

    // ---- Unconfirmed services -----------------------------------------------------------------

    private function handleUnconfirmed(BacnetSession $s, string $apdu): string
    {
        if (strlen($apdu) < 2) {
            $this->logUnknown($s, 'truncated unconfirmed-request');

            return '';
        }
        $s->service = ord($apdu[1]);

        if ($s->service === self::SVC_WHO_IS) {
            return $this->handleWhoIs($s, substr($apdu, 2));
        }

        // I-Am, Who-Has, notifications, etc. are peer announcements — capture, never reply.
        $this->logUnknown($s, sprintf('unconfirmed service 0x%02X', $s->service));

        return '';
    }

    /**
     * Who-Is: a discovery broadcast. Capture the (optional) device-instance range and answer with an
     * I-Am, unless the request is too small to hold one (anti-amplification), in which case the probe
     * is still logged but no reply is emitted.
     */
    private function handleWhoIs(BacnetSession $s, string $serviceData): string
    {
        // Optional: context tag 0 (low limit) + context tag 1 (high limit), each an unsigned int.
        $pos = 0;
        $low = self::readTag($serviceData, $pos);
        $high = self::readTag($serviceData, $pos);
        if ($low !== null && $low['context'] && $low['tag'] === 0) {
            $s->whoIsLow = self::decodeUnsigned($low['value']);
        }
        if ($high !== null && $high['context'] && $high['tag'] === 1) {
            $s->whoIsHigh = self::decodeUnsigned($high['value']);
        }

        $range = ($s->whoIsLow !== null && $s->whoIsHigh !== null)
            ? "range={$s->whoIsLow}-{$s->whoIsHigh}"
            : 'range=global';

        $this->logEvent([
            'event' => 'bacnet_whois',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'low',
            'path' => "BACnet Who-Is {$range}",
        ]);

        // Honour the range: a targeted Who-Is outside our instance draws no I-Am, like a real device.
        if ($s->whoIsLow !== null && $s->whoIsHigh !== null
            && ($this->config->deviceInstance < $s->whoIsLow || $this->config->deviceInstance > $s->whoIsHigh)) {
            return '';
        }

        // An I-Am has no smaller believable substitute, so a Who-Is too small to hold one draws no
        // reply (a device that cannot answer under the anti-amplification cap simply stays silent).
        return $this->capReply($s, $this->buildIAm(), '');
    }

    /**
     * Builds the I-Am unconfirmed-request announcing the persona device. Unicast back to the
     * requester (a real device broadcasts, but a unicast reply is believable and never a reflection
     * primitive).
     */
    private function buildIAm(): string
    {
        $apdu = chr((self::APDU_UNCONFIRMED_REQ << 4)) . chr(self::SVC_I_AM)
            . self::appObjectId(self::OBJ_DEVICE, $this->config->deviceInstance)
            . self::appUnsigned($this->config->maxApdu)
            . self::appEnumerated($this->config->segmentation)
            . self::appUnsigned($this->config->vendorId);

        return self::wrapUnicast($apdu);
    }

    // ---- Confirmed services -------------------------------------------------------------------

    private function handleConfirmed(BacnetSession $s, string $apdu): string
    {
        // Confirmed-Request: pduFlags(1), maxSegs/maxApdu(1), invokeId(1), serviceChoice(1), data.
        if (strlen($apdu) < 4) {
            $this->logUnknown($s, 'truncated confirmed-request');

            return '';
        }
        $s->invokeId = ord($apdu[2]);
        $s->service = ord($apdu[3]);
        $serviceData = substr($apdu, 4);

        if ($s->service === self::SVC_READ_PROPERTY) {
            return $this->handleReadProperty($s, $serviceData);
        }

        // Any other confirmed service (WriteProperty, ReadPropertyMultiple, ...) is not modelled.
        // INERT: it is captured and refused — a write is never applied — with a Reject a real device
        // sends for a service it will not perform.
        $this->logUnknown($s, sprintf('confirmed service 0x%02X (refused)', $s->service));

        return $this->capReply($s, $this->buildReject($s->invokeId, self::REJECT_UNRECOGNIZED_SERVICE), '');
    }

    /**
     * ReadProperty: the enumeration workhorse. Capture the object + property being probed, then return
     * a believable value for the advertised Device object or a BACnet error for anything else.
     */
    private function handleReadProperty(BacnetSession $s, string $serviceData): string
    {
        $pos = 0;
        $objTag = self::readTag($serviceData, $pos);
        $propTag = self::readTag($serviceData, $pos);
        if ($objTag === null || !$objTag['context'] || $objTag['tag'] !== 0 || strlen($objTag['value']) !== 4
            || $propTag === null || !$propTag['context'] || $propTag['tag'] !== 1) {
            $this->logUnknown($s, 'malformed ReadProperty request');

            return '';
        }

        [$objType, $objInstance] = self::decodeObjectId($objTag['value']);
        $propertyId = self::decodeUnsigned($propTag['value']);
        $s->readObjectType = $objType;
        $s->readObjectInstance = $objInstance;
        $s->readPropertyId = $propertyId;

        // Optional context tag 2: property array index — echoed back on success.
        $idxTag = self::readTag($serviceData, $pos);
        if ($idxTag !== null && $idxTag['context'] && $idxTag['tag'] === 2) {
            $s->readArrayIndex = self::decodeUnsigned($idxTag['value']);
        }

        $this->logEvent([
            'event' => 'bacnet_read',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'medium',
            'path' => sprintf(
                'BACnet ReadProperty obj=%s:%d prop=%s',
                self::objectTypeName($objType),
                $objInstance,
                self::propertyName($propertyId)
            ),
        ]);

        $invokeId = $s->invokeId ?? 0;

        // Only the advertised Device object exists; any other object is unknown (captures point recon).
        if ($objType !== self::OBJ_DEVICE || $objInstance !== $this->config->deviceInstance) {
            return $this->capReply(
                $s,
                $this->buildError($invokeId, self::ERROR_CLASS_OBJECT, self::ERROR_CODE_UNKNOWN_OBJECT),
                ''
            );
        }

        $value = $this->devicePropertyValue($propertyId);
        if ($value === null) {
            return $this->capReply(
                $s,
                $this->buildError($invokeId, self::ERROR_CLASS_PROPERTY, self::ERROR_CODE_UNKNOWN_PROPERTY),
                ''
            );
        }

        // The believable ComplexACK carrying the value. When it will not fit under the
        // anti-amplification cap, fall back to an Abort(buffer-overflow) — exactly what a
        // non-segmenting device returns when a response is too large for one APDU.
        $ack = $this->buildReadPropertyAck($invokeId, $objType, $objInstance, $propertyId, $s->readArrayIndex, $value);

        return $this->capReply($s, $ack, $this->buildAbort($invokeId, self::ABORT_BUFFER_OVERFLOW));
    }

    /**
     * The application-tagged value for a modelled Device-object property, or null when the property is
     * not modelled (answered as unknown-property). Every value is cosmetic persona, never real data.
     */
    private function devicePropertyValue(int $propertyId): ?string
    {
        $c = $this->config;

        return match ($propertyId) {
            self::PROP_OBJECT_IDENTIFIER => self::appObjectId(self::OBJ_DEVICE, $c->deviceInstance),
            self::PROP_OBJECT_NAME => self::appCharString($c->objectName),
            self::PROP_OBJECT_TYPE => self::appEnumerated(self::OBJ_DEVICE),
            self::PROP_OBJECT_LIST => self::appObjectId(self::OBJ_DEVICE, $c->deviceInstance), // list of one
            self::PROP_MODEL_NAME => self::appCharString($c->modelName),
            self::PROP_VENDOR_NAME => self::appCharString($c->vendorName),
            self::PROP_VENDOR_IDENTIFIER => self::appUnsigned($c->vendorId),
            self::PROP_FIRMWARE_REVISION => self::appCharString($c->firmwareRevision),
            self::PROP_APP_SOFTWARE_VERSION => self::appCharString($c->applicationSoftwareVersion),
            self::PROP_SYSTEM_STATUS => self::appEnumerated(0), // operational
            self::PROP_PROTOCOL_VERSION => self::appUnsigned(1),
            self::PROP_PROTOCOL_REVISION => self::appUnsigned(14),
            self::PROP_DESCRIPTION => self::appCharString($c->description),
            default => null,
        };
    }

    // ---- Response framing ---------------------------------------------------------------------

    /**
     * ComplexACK for a ReadProperty: echoes the object id + property id (+ array index), then wraps
     * the value in the context-3 opening/closing tags.
     */
    private function buildReadPropertyAck(int $invokeId, int $objType, int $objInstance, int $propertyId, ?int $arrayIndex, string $valueApp): string
    {
        $body = chr((self::APDU_COMPLEX_ACK << 4)) . chr($invokeId & 0xFF) . chr(self::SVC_READ_PROPERTY)
            . self::ctxObjectId(0, $objType, $objInstance)
            . self::ctxUnsigned(1, $propertyId);
        if ($arrayIndex !== null) {
            $body .= self::ctxUnsigned(2, $arrayIndex);
        }
        $body .= self::openingTag(3) . $valueApp . self::closingTag(3);

        return self::wrapUnicast($body);
    }

    /** Error-PDU: service choice echoed, then error-class + error-code as application enumerateds. */
    private function buildError(int $invokeId, int $errorClass, int $errorCode): string
    {
        $apdu = chr((self::APDU_ERROR << 4)) . chr($invokeId & 0xFF) . chr(self::SVC_READ_PROPERTY)
            . self::appEnumerated($errorClass)
            . self::appEnumerated($errorCode);

        return self::wrapUnicast($apdu);
    }

    /** Reject-PDU: invoke id + a single reject-reason byte. */
    private function buildReject(int $invokeId, int $reason): string
    {
        $apdu = chr((self::APDU_REJECT << 4)) . chr($invokeId & 0xFF) . chr($reason & 0xFF);

        return self::wrapUnicast($apdu);
    }

    /** Abort-PDU (server-initiated): invoke id + abort-reason byte. */
    private function buildAbort(int $invokeId, int $reason): string
    {
        // High nibble 7 = Abort; bit 3 (SRV) set marks a server-initiated abort.
        $apdu = chr((self::APDU_ABORT << 4) | 0x08) . chr($invokeId & 0xFF) . chr($reason & 0xFF);

        return self::wrapUnicast($apdu);
    }

    /**
     * Wraps an APDU in a minimal NPDU (version + zero control, no addressing) and a BVLC
     * Original-Unicast-NPDU header. The reply goes straight back to the requesting socket.
     */
    private static function wrapUnicast(string $apdu): string
    {
        $npdu = chr(self::NPDU_VERSION) . "\x00" . $apdu;

        return chr(self::BVLC_TYPE) . chr(self::BVLC_ORIGINAL_UNICAST) . pack('n', strlen($npdu) + 4) . $npdu;
    }

    /**
     * ANTI-AMPLIFICATION cap for a reply to the datagram in $s->inbuf's source. Returns $primary when
     * it is no larger than the request, else $fallback when that fits, else '' — so the reflection
     * factor is always <= 1.
     */
    private function capReply(BacnetSession $s, string $primary, string $fallback): string
    {
        $reqLen = $s->requestLength;
        if (strlen($primary) <= $reqLen) {
            return $primary;
        }
        if ($fallback !== '' && strlen($fallback) <= $reqLen) {
            return $fallback;
        }

        return '';
    }

    // ---- BACnet tag parsing -------------------------------------------------------------------

    /**
     * Offset at which the APDU begins in a BACnet/IP datagram, or null when there is no APDU (an
     * unsupported BVLC function, a network-layer routing message, or a malformed envelope).
     */
    private static function apduOffset(string $d): ?int
    {
        $n = strlen($d);
        $func = ord($d[1]);
        $off = match ($func) {
            self::BVLC_ORIGINAL_UNICAST, self::BVLC_ORIGINAL_BROADCAST => 4,
            self::BVLC_FORWARDED => 10, // 6-byte originating B/IP address follows the BVLC header
            default => null,
        };
        if ($off === null || $off + 2 > $n) {
            return null;
        }
        if (ord($d[$off]) !== self::NPDU_VERSION) {
            return null;
        }
        $control = ord($d[$off + 1]);
        $off += 2;

        if ($control & 0x80) {
            return null; // network-layer message: no APDU
        }
        if ($control & 0x20) { // destination network address present: DNET(2), DLEN(1), DADR(DLEN)
            if ($off + 3 > $n) {
                return null;
            }
            $dlen = ord($d[$off + 2]);
            $off += 3 + $dlen;
        }
        if ($control & 0x08) { // source network address present: SNET(2), SLEN(1), SADR(SLEN)
            if ($off + 3 > $n) {
                return null;
            }
            $slen = ord($d[$off + 2]);
            $off += 3 + $slen;
        }
        if ($control & 0x20) { // hop count follows when a destination is present
            $off += 1;
        }

        return $off <= $n ? $off : null;
    }

    /**
     * Locates and returns the APDU bytes of a BACnet/IP datagram (exposed for tests). Null when the
     * datagram carries no APDU.
     */
    public static function extractApdu(string $datagram): ?string
    {
        if (strlen($datagram) < 4 || ord($datagram[0]) !== self::BVLC_TYPE) {
            return null;
        }
        $off = self::apduOffset($datagram);
        if ($off === null || $off >= strlen($datagram)) {
            return null;
        }

        return substr($datagram, $off);
    }

    /**
     * Reads one BACnet tag at $pos, advancing $pos past it. Returns a descriptor with the tag number,
     * class (context/application), whether it is an opening/closing tag, and the primitive value
     * bytes. Null on any bounds error.
     *
     * @return array{tag:int,context:bool,opening:bool,closing:bool,value:string}|null
     */
    public static function readTag(string $buf, int &$pos): ?array
    {
        $n = strlen($buf);
        if ($pos >= $n) {
            return null;
        }
        $t = ord($buf[$pos]);
        $pos++;

        $tagNumber = ($t >> 4) & 0x0F;
        $context = (($t >> 3) & 0x01) === 1;
        $lvt = $t & 0x07;

        if ($tagNumber === 0x0F) { // extended tag number in the following byte
            if ($pos >= $n) {
                return null;
            }
            $tagNumber = ord($buf[$pos]);
            $pos++;
        }

        if ($lvt === 6) {
            return ['tag' => $tagNumber, 'context' => true, 'opening' => true, 'closing' => false, 'value' => ''];
        }
        if ($lvt === 7) {
            return ['tag' => $tagNumber, 'context' => true, 'opening' => false, 'closing' => true, 'value' => ''];
        }

        if ($lvt <= 4) {
            $len = $lvt;
        } elseif ($lvt === 5) { // extended length
            if ($pos >= $n) {
                return null;
            }
            $len = ord($buf[$pos]);
            $pos++;
            if ($len === 254) {
                if ($pos + 2 > $n) {
                    return null;
                }
                $len = (ord($buf[$pos]) << 8) | ord($buf[$pos + 1]);
                $pos += 2;
            } elseif ($len === 255) {
                if ($pos + 4 > $n) {
                    return null;
                }
                $len = (ord($buf[$pos]) << 24) | (ord($buf[$pos + 1]) << 16) | (ord($buf[$pos + 2]) << 8) | ord($buf[$pos + 3]);
                $pos += 4;
            }
        } else {
            return null;
        }

        if ($len < 0 || $pos + $len > $n) {
            return null;
        }
        $value = substr($buf, $pos, $len);
        $pos += $len;

        return ['tag' => $tagNumber, 'context' => $context, 'opening' => false, 'closing' => false, 'value' => $value];
    }

    /** Decodes a big-endian unsigned integer from tag value bytes. */
    public static function decodeUnsigned(string $bytes): int
    {
        $v = 0;
        $len = strlen($bytes);
        for ($i = 0; $i < $len; $i++) {
            $v = ($v << 8) | ord($bytes[$i]);
        }

        return $v;
    }

    /**
     * Decodes a 4-byte BACnetObjectIdentifier: top 10 bits = object type, low 22 bits = instance.
     *
     * @return array{0:int,1:int}
     */
    public static function decodeObjectId(string $four): array
    {
        $v = self::decodeUnsigned($four);

        return [($v >> 22) & 0x3FF, $v & 0x3FFFFF];
    }

    // ---- BACnet tag encoding ------------------------------------------------------------------

    /** Application unsigned integer: minimal big-endian bytes with an application tag-2 header. */
    private static function appUnsigned(int $v): string
    {
        return self::appPrimitive(self::TAG_UNSIGNED, self::minBytes($v));
    }

    /** Application enumerated: minimal big-endian bytes with an application tag-9 header. */
    private static function appEnumerated(int $v): string
    {
        return self::appPrimitive(self::TAG_ENUMERATED, self::minBytes($v));
    }

    /** Application character string: a leading encoding byte (0 = ANSI X3.4 / UTF-8) then the text. */
    private static function appCharString(string $s): string
    {
        return self::appPrimitive(self::TAG_CHARACTER_STRING, "\x00" . $s);
    }

    /** Application BACnetObjectIdentifier: a fixed 4-byte (type<<22 | instance) with a tag-12 header. */
    private static function appObjectId(int $type, int $instance): string
    {
        $v = (($type & 0x3FF) << 22) | ($instance & 0x3FFFFF);

        return self::appPrimitive(self::TAG_OBJECT_ID, pack('N', $v));
    }

    /** Context unsigned integer under the given context tag number. */
    private static function ctxUnsigned(int $tagNumber, int $v): string
    {
        return self::ctxPrimitive($tagNumber, self::minBytes($v));
    }

    /** Context BACnetObjectIdentifier (used in a ReadProperty request/ack for the object id). */
    private static function ctxObjectId(int $tagNumber, int $type, int $instance): string
    {
        $v = (($type & 0x3FF) << 22) | ($instance & 0x3FFFFF);

        return self::ctxPrimitive($tagNumber, pack('N', $v));
    }

    /** An application-class primitive: tag header (tag number, class 0, length) then the value. */
    private static function appPrimitive(int $tagNumber, string $value): string
    {
        return self::tagHeader($tagNumber, false, strlen($value)) . $value;
    }

    /** A context-class primitive: tag header (tag number, class 1, length) then the value. */
    private static function ctxPrimitive(int $tagNumber, string $value): string
    {
        return self::tagHeader($tagNumber, true, strlen($value)) . $value;
    }

    private static function openingTag(int $tagNumber): string
    {
        return chr((($tagNumber & 0x0F) << 4) | 0x0E); // context class, LVT 6 = opening
    }

    private static function closingTag(int $tagNumber): string
    {
        return chr((($tagNumber & 0x0F) << 4) | 0x0F); // context class, LVT 7 = closing
    }

    /**
     * Encodes a BACnet tag header. Tag numbers 0..14 pack into the high nibble; the class bit and the
     * length/value/type occupy the low nibble, spilling to the extended-length form when length >= 5.
     */
    private static function tagHeader(int $tagNumber, bool $context, int $len): string
    {
        $classBit = $context ? 0x08 : 0x00;

        if ($len <= 4) {
            return chr((($tagNumber & 0x0F) << 4) | $classBit | $len);
        }

        $first = chr((($tagNumber & 0x0F) << 4) | $classBit | 0x05); // LVT 5 = extended length
        if ($len < 254) {
            return $first . chr($len);
        }
        if ($len < 0x10000) {
            return $first . chr(254) . pack('n', $len);
        }

        return $first . chr(255) . pack('N', $len);
    }

    /** Minimal big-endian byte string for an unsigned value (at least one byte). */
    private static function minBytes(int $v): string
    {
        if ($v <= 0) {
            return "\x00";
        }
        $bytes = '';
        while ($v > 0) {
            $bytes = chr($v & 0xFF) . $bytes;
            $v >>= 8;
        }

        return $bytes;
    }

    // ---- Naming (intel readability) -----------------------------------------------------------

    private static function objectTypeName(int $type): string
    {
        return match ($type) {
            0 => 'analog-input',
            1 => 'analog-output',
            2 => 'analog-value',
            3 => 'binary-input',
            4 => 'binary-output',
            5 => 'binary-value',
            8 => 'device',
            13 => 'multi-state-input',
            14 => 'multi-state-output',
            19 => 'multi-state-value',
            default => sprintf('type-%d', $type),
        };
    }

    private static function propertyName(int $prop): string
    {
        return match ($prop) {
            self::PROP_APP_SOFTWARE_VERSION => 'application-software-version',
            self::PROP_DESCRIPTION => 'description',
            self::PROP_FIRMWARE_REVISION => 'firmware-revision',
            self::PROP_MODEL_NAME => 'model-name',
            self::PROP_OBJECT_IDENTIFIER => 'object-identifier',
            self::PROP_OBJECT_LIST => 'object-list',
            self::PROP_OBJECT_NAME => 'object-name',
            self::PROP_OBJECT_TYPE => 'object-type',
            85 => 'present-value',
            self::PROP_PROTOCOL_REVISION => 'protocol-revision',
            self::PROP_PROTOCOL_VERSION => 'protocol-version',
            self::PROP_SYSTEM_STATUS => 'system-status',
            self::PROP_VENDOR_IDENTIFIER => 'vendor-identifier',
            self::PROP_VENDOR_NAME => 'vendor-name',
            default => sprintf('prop-%d', $prop),
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

    private function logUnknown(BacnetSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'bacnet_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'BACnet unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'BACNET';
        $entry['proto'] = 'bacnet';
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
                'port' => self::DEFAULT_PORT,
                'path' => 'BACnet internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
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

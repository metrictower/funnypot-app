<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Kerberos;

/**
 * Zero-dependency, single-process TCP server for the low-interaction Kerberos KDC honeypot (port 88).
 * Parses just enough of the AS-REQ ([APPLICATION 10], RFC 4120) in pure PHP — with a minimal ASN.1
 * DER reader — to capture the recon that user-enumeration and AS-REP-roasting tools run against a
 * domain controller, on a non-blocking stream_select event loop.
 *
 * Kerberos over TCP frames each message with a 4-byte big-endian length prefix followed by the DER
 * KRB message. From an AS-REQ we harvest the client principal (cname), the realm, and the requested
 * service (sname, typically krbtgt/REALM) — this is the enumeration / roasting probe.
 *
 * Deliberately inert: a ticket is NEVER issued. Every AS-REQ is answered with a KRB-ERROR
 * ([APPLICATION 30]) — KDC_ERR_PREAUTH_REQUIRED (25) for a modelled account (a real KDC returns this
 * for an account that exists, which baits the attacker into spraying / roasting it) or
 * KDC_ERR_C_PRINCIPAL_UNKNOWN (6) for anything else. Nothing is ever authenticated.
 */
final class KerberosServer
{
    private const DEFAULT_PORT = 88;
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 60; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms
    private const INBUF_CAP = 65536;
    private const MAX_MESSAGE_LEN = 65535; // a KRB message on TCP is small; bound the length prefix
    private const MAX_NAME_PARTS = 8;      // cap name-string components parsed from one principal
    private const MAX_STRING_LEN = 256;    // cap a captured name component's length

    // Kerberos application / universal ASN.1 tags used on the wire.
    private const TAG_AS_REQ = 0x6A;          // [APPLICATION 10]
    private const TAG_KRB_ERROR = 0x7E;       // [APPLICATION 30]
    private const T_SEQUENCE = 0x30;
    private const T_INTEGER = 0x02;
    private const T_GENERALSTRING = 0x1B;
    private const T_IA5STRING = 0x16;         // some clients encode KerberosString as IA5String
    private const T_GENERALIZEDTIME = 0x18;

    // KDC-REQ / KDC-REQ-BODY / PrincipalName explicit context tags ([APPLICATION]/[n] constructed).
    private const CTX_MSG_TYPE = 0xA2;   // KDC-REQ [2] msg-type
    private const CTX_REQ_BODY = 0xA4;   // KDC-REQ [4] req-body
    private const CTX_CNAME = 0xA1;      // KDC-REQ-BODY [1] cname
    private const CTX_REALM = 0xA2;      // KDC-REQ-BODY [2] realm
    private const CTX_SNAME = 0xA3;      // KDC-REQ-BODY [3] sname
    private const CTX_NAME_TYPE = 0xA0;  // PrincipalName [0] name-type
    private const CTX_NAME_STRING = 0xA1; // PrincipalName [1] name-string

    private const MSG_AS_REQ = 10;
    private const MSG_KRB_ERROR = 30;

    private const KDC_ERR_C_PRINCIPAL_UNKNOWN = 6;
    private const KDC_ERR_PREAUTH_REQUIRED = 25;

    private const NT_SRV_INST = 2; // service principal (krbtgt) name-type

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private KerberosConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:88").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-kerberos: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-kerberos ({$this->config->realm}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:KerberosSession,ip:string}> $conns */
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

                // Guard against inbound buffer exhaustion — a KRB message is tiny.
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
                if ($session->outbuf === '' && $session->close) {
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
        $session = new KerberosSession($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'severity' => 'low',
            'path' => "Kerberos connection from {$ip}:{$clientPort}",
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
     * Frames the inbound stream into length-prefixed KRB messages and dispatches each one. Safe to
     * drive directly with raw bytes in tests.
     */
    public function processInbound(KerberosSession $s): void
    {
        while (true) {
            if ($s->close) {
                return;
            }
            if (strlen($s->inbuf) < 4) {
                return; // need the 4-byte length prefix first
            }

            $len = (ord($s->inbuf[0]) << 24) | (ord($s->inbuf[1]) << 16) | (ord($s->inbuf[2]) << 8) | ord($s->inbuf[3]);
            // The top bit of the length is reserved (RFC 4120 §7.2.2) and must be zero; a set bit or an
            // absurd length is not a message we model.
            if ($len <= 0 || $len > self::MAX_MESSAGE_LEN) {
                $this->logUnknown($s, "bad message length prefix {$len}");
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < 4 + $len) {
                return; // wait for the rest of this message
            }

            $msg = substr($s->inbuf, 4, $len);
            $s->inbuf = substr($s->inbuf, 4 + $len);

            $this->handleMessage($s, $msg);
            if ($s->close) {
                return;
            }
        }
    }

    private function handleMessage(KerberosSession $s, string $msg): void
    {
        if ($msg === '') {
            $this->logUnknown($s, 'empty KRB message');
            $s->close = true;

            return;
        }

        $tag = ord($msg[0]);
        if ($tag !== self::TAG_AS_REQ) {
            // TGS-REQ / AP-REQ / anything else: this tier only models the AS-REQ enumeration surface.
            $this->logUnknown($s, sprintf('non-AS-REQ message (application tag 0x%02X)', $tag));
            $s->close = true;

            return;
        }

        $parsed = self::parseAsReq($msg);
        if ($parsed === null) {
            $this->logUnknown($s, 'unparseable AS-REQ');
            $s->close = true;

            return;
        }

        $s->cname = $parsed['cname'];
        $s->realm = $parsed['realm'];
        $s->sname = $parsed['sname'];

        $account = $parsed['cnameParts'][0] ?? '';
        $known = $account !== '' && $this->config->isKnownPrincipal($account);
        $errorCode = $known ? self::KDC_ERR_PREAUTH_REQUIRED : self::KDC_ERR_C_PRINCIPAL_UNKNOWN;

        $cnameShown = self::printable($parsed['cname'] ?? '');
        $realmShown = self::printable($parsed['realm'] ?? '');
        $snameShown = self::printable($parsed['sname'] ?? '');

        $this->logEvent([
            'event' => 'krb_asreq',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $known ? 'high' : 'medium',
            'path' => sprintf(
                'Kerberos AS-REQ cname=%s@%s sname=%s -> %s',
                $cnameShown !== '' ? $cnameShown : '(none)',
                $realmShown !== '' ? $realmShown : '(none)',
                $snameShown !== '' ? $snameShown : '(none)',
                self::errorName($errorCode)
            ),
            'body' => sprintf('cname=%s realm=%s sname=%s', $cnameShown, $realmShown, $snameShown),
        ]);

        // Echo the client's realm / requested service back in the error, defaulting to our persona
        // realm and the krbtgt service when the request omitted them.
        $realm = ($parsed['realm'] !== null && $parsed['realm'] !== '') ? $parsed['realm'] : $this->config->realm;
        $snameParts = $parsed['snameParts'] !== [] ? $parsed['snameParts'] : ['krbtgt', $realm];
        $snameType = $parsed['snameType'] ?? self::NT_SRV_INST;

        $err = self::buildKrbError($errorCode, $realm, $snameParts, $snameType);
        $s->outbuf .= pack('N', strlen($err)) . $err;
    }

    // ---- AS-REQ parsing (minimal ASN.1 DER) --------------------------------------------------

    /**
     * Parses an AS-REQ ([APPLICATION 10]) and returns the captured recon fields, or null when the
     * message is not a well-formed AS-REQ. Only the fields worth capturing are decoded; the rest of
     * the KDC-REQ-BODY (kdc-options, nonce, etype, ...) is ignored.
     *
     * @return array{msgType:?int,cname:?string,cnameParts:list<string>,cnameType:?int,realm:?string,sname:?string,snameParts:list<string>,snameType:?int}|null
     */
    public static function parseAsReq(string $msg): ?array
    {
        $pos = 0;
        $top = self::readTlv($msg, $pos);
        if ($top === null || $top[0] !== self::TAG_AS_REQ) {
            return null;
        }

        // [APPLICATION 10] wraps a KDC-REQ SEQUENCE.
        $p = 0;
        $seq = self::readTlv($top[1], $p);
        if ($seq === null || $seq[0] !== self::T_SEQUENCE) {
            return null;
        }
        $kdcReq = self::fields($seq[1]);

        $msgType = self::intField($kdcReq[self::CTX_MSG_TYPE] ?? null);

        // [4] req-body: a KDC-REQ-BODY SEQUENCE.
        if (!isset($kdcReq[self::CTX_REQ_BODY])) {
            return null;
        }
        $bp = 0;
        $bodyTlv = self::readTlv($kdcReq[self::CTX_REQ_BODY], $bp);
        if ($bodyTlv === null || $bodyTlv[0] !== self::T_SEQUENCE) {
            return null;
        }
        $body = self::fields($bodyTlv[1]);

        [$cname, $cnameType, $cnameParts] = isset($body[self::CTX_CNAME])
            ? self::parsePrincipal($body[self::CTX_CNAME])
            : [null, null, []];

        $realm = isset($body[self::CTX_REALM]) ? self::stringField($body[self::CTX_REALM]) : null;

        [$sname, $snameType, $snameParts] = isset($body[self::CTX_SNAME])
            ? self::parsePrincipal($body[self::CTX_SNAME])
            : [null, null, []];

        return [
            'msgType' => $msgType,
            'cname' => $cname,
            'cnameParts' => $cnameParts,
            'cnameType' => $cnameType,
            'realm' => $realm,
            'sname' => $sname,
            'snameParts' => $snameParts,
            'snameType' => $snameType,
        ];
    }

    /**
     * Parses a PrincipalName wrapped in an explicit context tag. Returns [joinedName, nameType,
     * parts]. The name is the components joined by "/" (e.g. krbtgt/CORP.LOCAL), or null when empty.
     *
     * @return array{0:?string,1:?int,2:list<string>}
     */
    private static function parsePrincipal(string $wrapped): array
    {
        $p = 0;
        $seq = self::readTlv($wrapped, $p);
        if ($seq === null || $seq[0] !== self::T_SEQUENCE) {
            return [null, null, []];
        }
        $f = self::fields($seq[1]);

        $type = self::intField($f[self::CTX_NAME_TYPE] ?? null);

        $parts = [];
        if (isset($f[self::CTX_NAME_STRING])) {
            $sp = 0;
            $strSeq = self::readTlv($f[self::CTX_NAME_STRING], $sp);
            if ($strSeq !== null && $strSeq[0] === self::T_SEQUENCE) {
                $q = 0;
                while ($q < strlen($strSeq[1]) && count($parts) < self::MAX_NAME_PARTS) {
                    $str = self::readTlv($strSeq[1], $q);
                    if ($str === null) {
                        break;
                    }
                    if ($str[0] === self::T_GENERALSTRING || $str[0] === self::T_IA5STRING) {
                        $parts[] = substr($str[1], 0, self::MAX_STRING_LEN);
                    }
                }
            }
        }

        return [$parts === [] ? null : implode('/', $parts), $type, $parts];
    }

    /** Decodes a context-wrapped INTEGER field to int, or null when absent / not an INTEGER. */
    private static function intField(?string $wrapped): ?int
    {
        if ($wrapped === null) {
            return null;
        }
        $p = 0;
        $tlv = self::readTlv($wrapped, $p);
        if ($tlv === null || $tlv[0] !== self::T_INTEGER) {
            return null;
        }

        return self::decodeInt($tlv[1]);
    }

    /** Decodes a context-wrapped KerberosString (GeneralString / IA5String), or null. */
    private static function stringField(?string $wrapped): ?string
    {
        if ($wrapped === null) {
            return null;
        }
        $p = 0;
        $tlv = self::readTlv($wrapped, $p);
        if ($tlv === null || ($tlv[0] !== self::T_GENERALSTRING && $tlv[0] !== self::T_IA5STRING)) {
            return null;
        }

        return substr($tlv[1], 0, self::MAX_STRING_LEN);
    }

    /**
     * Reads every top-level TLV of a SEQUENCE body into a tag => value map. Kerberos context tags are
     * unique within a structure, so a map is sufficient and order-independent.
     *
     * @return array<int,string>
     */
    private static function fields(string $seq): array
    {
        $out = [];
        $p = 0;
        while ($p < strlen($seq)) {
            $tlv = self::readTlv($seq, $p);
            if ($tlv === null) {
                break;
            }
            $out[$tlv[0]] = $tlv[1];
        }

        return $out;
    }

    /**
     * Reads one DER TLV at $pos, advancing $pos past it. Returns [tag, value] or null on any bounds
     * error / unsupported (multi-byte tag, indefinite / absurd length) form. Multi-byte tags are
     * rejected deliberately — Kerberos never uses tag numbers above 30.
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
        if (($tag & 0x1F) === 0x1F) {
            return null; // high-tag-number (multi-byte) form — not used by Kerberos
        }
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

    /** Decodes a big-endian two's-complement DER INTEGER. */
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

    // ---- KRB-ERROR response building ---------------------------------------------------------

    /**
     * Builds a KRB-ERROR ([APPLICATION 30]) DER message (without the TCP length prefix). Structurally
     * complete and valid, carrying only what an error legitimately needs: pvno, msg-type, server time,
     * the error code, and the service realm / name. No ticket, no cname, no e-data — the honeypot never
     * hands back anything an attacker could authenticate with.
     *
     * @param list<string> $snameParts
     */
    public static function buildKrbError(int $errorCode, string $realm, array $snameParts, int $snameType): string
    {
        $now = time();
        $susec = (int) ((microtime(true) - $now) * 1_000_000);
        if ($susec < 0 || $susec > 999_999) {
            $susec = 0;
        }

        $content =
            self::derCtx(0, self::derInteger(5))                    // pvno = 5
            . self::derCtx(1, self::derInteger(self::MSG_KRB_ERROR)) // msg-type = 30
            . self::derCtx(4, self::derGeneralizedTime($now))       // stime
            . self::derCtx(5, self::derInteger($susec))             // susec
            . self::derCtx(6, self::derInteger($errorCode))         // error-code
            . self::derCtx(9, self::derGeneralString($realm))       // realm (service realm)
            . self::derCtx(10, self::derPrincipal($snameType, $snameParts)); // sname

        return self::der(self::TAG_KRB_ERROR, self::der(self::T_SEQUENCE, $content));
    }

    /**
     * Parses a KRB-ERROR message (the inverse of buildKrbError). Exposed so tests can verify the
     * emitted error round-trips; also confirms the DER reader handles the response shape.
     *
     * @return array{msgType:?int,errorCode:?int,realm:?string,sname:?string}|null
     */
    public static function parseKrbError(string $msg): ?array
    {
        $pos = 0;
        $top = self::readTlv($msg, $pos);
        if ($top === null || $top[0] !== self::TAG_KRB_ERROR) {
            return null;
        }
        $p = 0;
        $seq = self::readTlv($top[1], $p);
        if ($seq === null || $seq[0] !== self::T_SEQUENCE) {
            return null;
        }
        $f = self::fields($seq[1]);

        $realm = isset($f[0xA9]) ? self::stringField($f[0xA9]) : null;
        [$sname] = isset($f[0xAA]) ? self::parsePrincipal($f[0xAA]) : [null, null, []];

        return [
            'msgType' => self::intField($f[0xA1] ?? null),
            'errorCode' => self::intField($f[0xA6] ?? null),
            'realm' => $realm,
            'sname' => $sname,
        ];
    }

    /** SEQUENCE { [0] INTEGER name-type, [1] SEQUENCE OF GeneralString name-string }. */
    private static function derPrincipal(int $type, array $parts): string
    {
        $strs = '';
        foreach ($parts as $part) {
            $strs .= self::derGeneralString((string) $part);
        }

        return self::der(
            self::T_SEQUENCE,
            self::derCtx(0, self::derInteger($type)) . self::derCtx(1, self::der(self::T_SEQUENCE, $strs))
        );
    }

    /** An explicitly-tagged context member [n] wrapping an already-encoded TLV. */
    private static function derCtx(int $n, string $innerTlv): string
    {
        return self::der(0xA0 | $n, $innerTlv);
    }

    private static function der(int $tag, string $value): string
    {
        return chr($tag) . self::derLen(strlen($value)) . $value;
    }

    private static function derLen(int $len): string
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

    /** Minimal two's-complement DER INTEGER. */
    private static function derInteger(int $n): string
    {
        $bytes = '';
        while (true) {
            $bytes = chr($n & 0xFF) . $bytes;
            $n >>= 8; // arithmetic shift preserves sign
            $top = ord($bytes[0]);
            if ($n === 0 && ($top & 0x80) === 0) {
                break;
            }
            if ($n === -1 && ($top & 0x80) !== 0) {
                break;
            }
        }

        return chr(self::T_INTEGER) . self::derLen(strlen($bytes)) . $bytes;
    }

    private static function derGeneralString(string $s): string
    {
        return self::der(self::T_GENERALSTRING, $s);
    }

    private static function derGeneralizedTime(int $unix): string
    {
        return self::der(self::T_GENERALIZEDTIME, gmdate('YmdHis', $unix) . 'Z');
    }

    // ---- Logging -----------------------------------------------------------------------------

    private static function errorName(int $code): string
    {
        return match ($code) {
            self::KDC_ERR_C_PRINCIPAL_UNKNOWN => 'KDC_ERR_C_PRINCIPAL_UNKNOWN',
            self::KDC_ERR_PREAUTH_REQUIRED => 'KDC_ERR_PREAUTH_REQUIRED',
            default => sprintf('error(%d)', $code),
        };
    }

    private function logUnknown(KerberosSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'krb_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'Kerberos unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'KERBEROS';
        $entry['proto'] = 'kerberos';
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
                'port' => self::DEFAULT_PORT,
                'path' => 'Kerberos internal fault: ' . $e->getMessage(),
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

        return $colon !== false ? (int) substr($bind, $colon + 1) : self::DEFAULT_PORT;
    }
}

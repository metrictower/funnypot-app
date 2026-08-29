<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ldap;

/**
 * Zero-dependency, single-process TCP server for the low-interaction LDAP honeypot (port 389).
 * Parses just enough BER-encoded LDAP (RFC 4511) in pure PHP, on a non-blocking stream_select
 * event loop, to harvest the intel a directory scanner or brute-forcer offers.
 *
 * Deliberately inert: it never authenticates, never grants a session, and never returns a
 * directory entry. The exchange is bindRequest -> bindResponse(invalidCredentials by default,
 * configurable to success) and searchRequest -> searchResultDone(success, zero entries).
 *
 * Captured:
 * - bind DN + version + the simple-authentication password (a credential attempt)
 * - the SASL mechanism name when a bind uses SASL instead of simple auth
 * - the search base DN + the filter, rendered to its RFC 4515 string form as a recon fingerprint
 *
 * Frame: none of its own. Each LDAPMessage is a self-delimiting BER SEQUENCE, so the inbound
 * stream is split on the outer SEQUENCE's length field.
 */
final class LdapServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick

    // Guards against a client that stops draining or a runaway declared message length.
    private const INBUF_CAP = 262144;  // 256 KiB — LDAP bind/search messages are small
    private const MAX_MESSAGE = 131072; // 128 KiB — a single LDAPMessage we will assemble

    // ASN.1 BER universal tags.
    private const TAG_BOOLEAN = 0x01;
    private const TAG_INTEGER = 0x02;
    private const TAG_OCTET_STRING = 0x04;
    private const TAG_ENUMERATED = 0x0A;
    private const TAG_SEQUENCE = 0x30;

    // LDAP protocolOp tags: [APPLICATION n], constructed unless noted (RFC 4511 4.2-4.5).
    private const OP_BIND_REQUEST = 0x60;   // [APPLICATION 0]
    private const OP_BIND_RESPONSE = 0x61;  // [APPLICATION 1]
    private const OP_UNBIND_REQUEST = 0x42; // [APPLICATION 2] NULL (primitive)
    private const OP_SEARCH_REQUEST = 0x63; // [APPLICATION 3]
    private const OP_SEARCH_DONE = 0x65;    // [APPLICATION 5]

    // AuthenticationChoice context tags inside a bindRequest (RFC 4511 4.2).
    private const AUTH_SIMPLE = 0x80; // [0] OCTET STRING (the password, primitive)
    private const AUTH_SASL = 0xA3;   // [3] SaslCredentials (constructed)

    // Filter CHOICE context tags (RFC 4511 4.5.1); implicitly tagged, so they replace the tag of
    // the underlying type.
    private const FILTER_AND = 0xA0;
    private const FILTER_OR = 0xA1;
    private const FILTER_NOT = 0xA2;
    private const FILTER_EQUALITY = 0xA3;
    private const FILTER_SUBSTRINGS = 0xA4;
    private const FILTER_GE = 0xA5;
    private const FILTER_LE = 0xA6;
    private const FILTER_PRESENT = 0x87; // [7] AttributeDescription (primitive)
    private const FILTER_APPROX = 0xA8;
    private const FILTER_EXTENSIBLE = 0xA9;

    // Substring component context tags (RFC 4511 4.5.1).
    private const SUB_INITIAL = 0x80;
    private const SUB_ANY = 0x81;
    private const SUB_FINAL = 0x82;

    // LDAP result codes (RFC 4511 4.1.9).
    private const RESULT_SUCCESS = 0;
    private const RESULT_INVALID_CREDENTIALS = 49;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private LdapConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:389").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-ldap: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-ldap listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:LdapSession,ip:string}> $conns */
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

                // Protect against inbound buffer exhaustion.
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
                    // Deliver any queued response best-effort before dropping the socket.
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
        $session = new LdapSession($ip, $clientPort, $id);
        // The client speaks first in LDAP (bindRequest), so nothing is queued on connect.

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "LDAP connection from {$ip}:{$clientPort}",
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
     * Splits the inbound stream on each self-delimiting LDAPMessage (a BER SEQUENCE) and dispatches
     * it. Incomplete trailing bytes are left in inbuf until the rest arrives. Safe to drive directly
     * with raw bytes in tests.
     */
    public function processInbound(LdapSession $s): void
    {
        while (true) {
            if (strlen($s->inbuf) < 2) {
                return; // need at least a tag + one length byte
            }
            if (ord($s->inbuf[0]) !== self::TAG_SEQUENCE) {
                // Not an LDAPMessage: a TLS ClientHello (0x16) for LDAPS, or junk. Log and drop.
                $this->logUnknown($s, sprintf('non-LDAP leading byte 0x%02X', ord($s->inbuf[0])));
                $s->close = true;

                return;
            }

            $lenByte = ord($s->inbuf[1]);
            if ($lenByte & 0x80) {
                $numBytes = $lenByte & 0x7F;
                // Indefinite form (0) is illegal in LDAP's DER; >4 length octets is absurd here.
                if ($numBytes === 0 || $numBytes > 4) {
                    $this->logUnknown($s, 'malformed BER length');
                    $s->close = true;

                    return;
                }
                if (strlen($s->inbuf) < 2 + $numBytes) {
                    return; // the length octets themselves have not all arrived
                }
                $contentLen = 0;
                for ($i = 0; $i < $numBytes; $i++) {
                    $contentLen = ($contentLen << 8) | ord($s->inbuf[2 + $i]);
                }
                $headerLen = 2 + $numBytes;
            } else {
                $contentLen = $lenByte;
                $headerLen = 2;
            }

            $total = $headerLen + $contentLen;
            if ($total > self::MAX_MESSAGE) {
                $this->logUnknown($s, sprintf('LDAPMessage too large (%d bytes)', $total));
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < $total) {
                return; // wait for the whole message
            }

            $message = substr($s->inbuf, 0, $total);
            $s->inbuf = substr($s->inbuf, $total);

            $this->handleMessage($s, $message);
            if ($s->close) {
                return;
            }
        }
    }

    /**
     * Parses one complete LDAPMessage (SEQUENCE { messageID INTEGER, protocolOp CHOICE }) and
     * dispatches on the protocolOp tag.
     */
    public function handleMessage(LdapSession $s, string $message): void
    {
        $seq = self::readTlv($message, 0);
        if ($seq === null || $seq['tag'] !== self::TAG_SEQUENCE) {
            $this->logUnknown($s, 'not an LDAPMessage SEQUENCE');
            $s->close = true;

            return;
        }

        $idTlv = self::readTlv($message, $seq['valueOff']);
        if ($idTlv === null || $idTlv['tag'] !== self::TAG_INTEGER) {
            $this->logUnknown($s, 'missing messageID');
            $s->close = true;

            return;
        }
        $messageId = self::readInteger($message, $idTlv['valueOff'], $idTlv['len']);
        $s->lastMessageId = $messageId;

        $op = self::readTlv($message, $idTlv['next']);
        if ($op === null) {
            $this->logUnknown($s, 'missing protocolOp');
            $s->close = true;

            return;
        }

        switch ($op['tag']) {
            case self::OP_BIND_REQUEST:
                $this->handleBind($s, $message, $op, $messageId);
                break;

            case self::OP_SEARCH_REQUEST:
                $this->handleSearch($s, $message, $op, $messageId);
                break;

            case self::OP_UNBIND_REQUEST:
                // The client is done; there is no unbind response. Close cleanly.
                $s->close = true;
                break;

            default:
                $this->logUnknown($s, sprintf('unmodelled protocolOp 0x%02X', $op['tag']));
                $s->close = true;
        }
    }

    /**
     * bindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER, name LDAPDN, authentication CHOICE }.
     * Captures the version, bind DN and (for simple auth) the password, logs the attempt, then
     * answers invalidCredentials by default (or success in accept mode). Never authenticates.
     */
    private function handleBind(LdapSession $s, string $message, array $op, int $messageId): void
    {
        $p = $op['valueOff'];
        $end = $op['next'];

        $verTlv = self::nextTlv($message, $p, $end);
        $version = ($verTlv !== null && $verTlv['tag'] === self::TAG_INTEGER)
            ? self::readInteger($message, $verTlv['valueOff'], $verTlv['len'])
            : 0;

        $nameTlv = self::nextTlv($message, $p, $end);
        $bindDn = ($nameTlv !== null && $nameTlv['tag'] === self::TAG_OCTET_STRING)
            ? substr($message, $nameTlv['valueOff'], $nameTlv['len'])
            : '';

        $authTlv = self::nextTlv($message, $p, $end);
        $password = '';
        $sasl = '';
        $authType = 'unknown';
        if ($authTlv !== null) {
            if ($authTlv['tag'] === self::AUTH_SIMPLE) {
                $authType = 'simple';
                $password = substr($message, $authTlv['valueOff'], $authTlv['len']);
            } elseif ($authTlv['tag'] === self::AUTH_SASL) {
                $authType = 'sasl';
                // The first field of SaslCredentials is the mechanism name (an OCTET STRING).
                $mechTlv = self::readTlv($message, $authTlv['valueOff']);
                if ($mechTlv !== null && $mechTlv['tag'] === self::TAG_OCTET_STRING) {
                    $sasl = substr($message, $mechTlv['valueOff'], $mechTlv['len']);
                }
            }
        }

        $s->version = $version;
        $s->bindDn = $bindDn;
        $s->bindPassword = $password;
        $s->saslMechanism = $sasl;

        $dnText = self::printable($bindDn);
        if ($authType === 'sasl') {
            $path = sprintf('LDAP bind v%d dn=%s sasl=%s', $version, $dnText, self::printable($sasl));
        } else {
            $path = sprintf(
                'LDAP bind v%d dn=%s password=%s',
                $version,
                $dnText,
                self::printable($password)
            );
        }

        $this->logEvent([
            'event' => 'ldap_bind',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => ($password !== '' || $sasl !== '') ? 'high' : 'medium',
            'path' => $path,
            'dn' => $dnText,
            'password' => self::printable($password),
            'auth' => $authType,
            'version' => $version,
        ]);

        // Default deny keeps brute-forcers trying; accept mode is a bare success code — still no
        // session, still no directory data, so the box stays inert.
        $resultCode = $this->config->acceptBinds ? self::RESULT_SUCCESS : self::RESULT_INVALID_CREDENTIALS;
        $s->outbuf .= self::buildBindResponse($messageId, $resultCode);
    }

    /**
     * searchRequest ::= [APPLICATION 3] SEQUENCE { baseObject, scope, derefAliases, sizeLimit,
     * timeLimit, typesOnly, filter, attributes }. Captures the base DN + filter, then answers a
     * searchResultDone(success) with no entries — a real directory is never touched.
     */
    private function handleSearch(LdapSession $s, string $message, array $op, int $messageId): void
    {
        $p = $op['valueOff'];
        $end = $op['next'];

        $baseTlv = self::nextTlv($message, $p, $end);
        $baseDn = ($baseTlv !== null && $baseTlv['tag'] === self::TAG_OCTET_STRING)
            ? substr($message, $baseTlv['valueOff'], $baseTlv['len'])
            : '';

        // Walk past scope, derefAliases, sizeLimit, timeLimit, typesOnly to reach the filter.
        self::nextTlv($message, $p, $end); // scope ENUMERATED
        self::nextTlv($message, $p, $end); // derefAliases ENUMERATED
        self::nextTlv($message, $p, $end); // sizeLimit INTEGER
        self::nextTlv($message, $p, $end); // timeLimit INTEGER
        self::nextTlv($message, $p, $end); // typesOnly BOOLEAN

        $filterTlv = self::nextTlv($message, $p, $end);
        $filter = $filterTlv !== null ? self::decodeFilter($message, $filterTlv) : '';

        $s->searchBase = $baseDn;
        $s->searchFilter = $filter;

        $this->logEvent([
            'event' => 'ldap_search',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf('LDAP search base="%s" filter=%s', self::printable($baseDn), $filter),
            'base' => self::printable($baseDn),
            'filter' => $filter,
        ]);

        // No searchResultEntry is ever emitted — only a done with success.
        $s->outbuf .= self::buildSearchDone($messageId, self::RESULT_SUCCESS);
    }

    // ---- Response builders -------------------------------------------------------------------

    /**
     * bindResponse ::= [APPLICATION 1] LDAPResult { resultCode, matchedDN, diagnosticMessage }.
     */
    public static function buildBindResponse(int $messageId, int $resultCode, string $matchedDn = '', string $diagnostic = ''): string
    {
        $result = self::berEnumerated($resultCode)
            . self::berOctetString($matchedDn)
            . self::berOctetString($diagnostic);

        return self::ldapMessage($messageId, self::berTlv(self::OP_BIND_RESPONSE, $result));
    }

    /**
     * searchResDone ::= [APPLICATION 5] LDAPResult. Carries no entries — the search is answered
     * done with the given result code and empty matchedDN / diagnostic.
     */
    public static function buildSearchDone(int $messageId, int $resultCode = self::RESULT_SUCCESS): string
    {
        $result = self::berEnumerated($resultCode)
            . self::berOctetString('')
            . self::berOctetString('');

        return self::ldapMessage($messageId, self::berTlv(self::OP_SEARCH_DONE, $result));
    }

    /** Wraps a protocolOp in an LDAPMessage SEQUENCE { messageID, protocolOp }. */
    private static function ldapMessage(int $messageId, string $protocolOp): string
    {
        return self::berTlv(self::TAG_SEQUENCE, self::berInteger($messageId) . $protocolOp);
    }

    // ---- Filter decoding (RFC 4515 string form) ----------------------------------------------

    /**
     * Renders a BER-encoded LDAP Filter to its RFC 4515 string form for capture, e.g.
     * "(&(objectClass=person)(uid=admin))". Unmodelled choices render as "(?)".
     *
     * @param array{tag:int,len:int,valueOff:int,next:int} $tlv
     */
    public static function decodeFilter(string $buf, array $tlv): string
    {
        switch ($tlv['tag']) {
            case self::FILTER_AND:
                return '(&' . self::decodeFilterList($buf, $tlv['valueOff'], $tlv['next']) . ')';

            case self::FILTER_OR:
                return '(|' . self::decodeFilterList($buf, $tlv['valueOff'], $tlv['next']) . ')';

            case self::FILTER_NOT:
                $inner = self::readTlv($buf, $tlv['valueOff']);

                return '(!' . ($inner !== null ? self::decodeFilter($buf, $inner) : '') . ')';

            case self::FILTER_EQUALITY:
                return '(' . self::assertion($buf, $tlv['valueOff'], '=') . ')';

            case self::FILTER_GE:
                return '(' . self::assertion($buf, $tlv['valueOff'], '>=') . ')';

            case self::FILTER_LE:
                return '(' . self::assertion($buf, $tlv['valueOff'], '<=') . ')';

            case self::FILTER_APPROX:
                return '(' . self::assertion($buf, $tlv['valueOff'], '~=') . ')';

            case self::FILTER_PRESENT:
                $attr = substr($buf, $tlv['valueOff'], $tlv['len']);

                return '(' . self::filterEscape($attr) . '=*)';

            case self::FILTER_SUBSTRINGS:
                return self::decodeSubstrings($buf, $tlv['valueOff']);

            case self::FILTER_EXTENSIBLE:
                return '(extensibleMatch)';

            default:
                return '(?)';
        }
    }

    /**
     * Renders the child filters of an and/or SET OF Filter between $start and $end.
     */
    private static function decodeFilterList(string $buf, int $start, int $end): string
    {
        $out = '';
        $p = $start;
        while ($p < $end) {
            $t = self::readTlv($buf, $p);
            if ($t === null) {
                break;
            }
            $out .= self::decodeFilter($buf, $t);
            $p = $t['next'];
        }

        return $out;
    }

    /**
     * Renders an AttributeValueAssertion { attributeDesc, assertionValue } as "attr<op>value".
     */
    private static function assertion(string $buf, int $vOff, string $op): string
    {
        $attrTlv = self::readTlv($buf, $vOff);
        if ($attrTlv === null) {
            return '?' . $op . '?';
        }
        $attr = substr($buf, $attrTlv['valueOff'], $attrTlv['len']);

        $valTlv = self::readTlv($buf, $attrTlv['next']);
        $val = $valTlv !== null ? substr($buf, $valTlv['valueOff'], $valTlv['len']) : '';

        return self::filterEscape($attr) . $op . self::filterEscape($val);
    }

    /**
     * Renders a SubstringFilter { type, substrings } as "attr=initial*any*final", any part optional.
     */
    private static function decodeSubstrings(string $buf, int $vOff): string
    {
        $typeTlv = self::readTlv($buf, $vOff);
        if ($typeTlv === null) {
            return '(?)';
        }
        $attr = substr($buf, $typeTlv['valueOff'], $typeTlv['len']);

        $seq = self::readTlv($buf, $typeTlv['next']);
        $initial = '';
        $anys = [];
        $final = '';
        if ($seq !== null) {
            $p = $seq['valueOff'];
            $end = $seq['next'];
            while ($p < $end) {
                $t = self::readTlv($buf, $p);
                if ($t === null) {
                    break;
                }
                $part = substr($buf, $t['valueOff'], $t['len']);
                if ($t['tag'] === self::SUB_INITIAL) {
                    $initial = $part;
                } elseif ($t['tag'] === self::SUB_ANY) {
                    $anys[] = $part;
                } elseif ($t['tag'] === self::SUB_FINAL) {
                    $final = $part;
                }
                $p = $t['next'];
            }
        }

        $segments = [self::filterEscape($initial)];
        foreach ($anys as $a) {
            $segments[] = self::filterEscape($a);
        }
        $segments[] = self::filterEscape($final);

        return '(' . self::filterEscape($attr) . '=' . implode('*', $segments) . ')';
    }

    // ---- BER helpers -------------------------------------------------------------------------

    /**
     * Reads one BER TLV at $off. Returns its tag, content length, content offset and the offset
     * just past the element, or null if the buffer is too short or the length is malformed.
     *
     * @return array{tag:int,len:int,valueOff:int,next:int}|null
     */
    public static function readTlv(string $buf, int $off): ?array
    {
        if ($off < 0 || $off + 2 > strlen($buf)) {
            return null;
        }
        $tag = ord($buf[$off]);
        $p = $off + 1;
        $lenByte = ord($buf[$p]);
        $p++;

        if ($lenByte & 0x80) {
            $numBytes = $lenByte & 0x7F;
            if ($numBytes === 0 || $numBytes > 4 || $p + $numBytes > strlen($buf)) {
                return null;
            }
            $len = 0;
            for ($i = 0; $i < $numBytes; $i++) {
                $len = ($len << 8) | ord($buf[$p]);
                $p++;
            }
        } else {
            $len = $lenByte;
        }

        if ($p + $len > strlen($buf)) {
            return null;
        }

        return ['tag' => $tag, 'len' => $len, 'valueOff' => $p, 'next' => $p + $len];
    }

    /**
     * Reads the next TLV at cursor $p (bounded by $end), advancing $p past it. Returns null when
     * nothing remains or the element is malformed.
     *
     * @return array{tag:int,len:int,valueOff:int,next:int}|null
     */
    private static function nextTlv(string $buf, int &$p, int $end): ?array
    {
        if ($p >= $end) {
            return null;
        }
        $t = self::readTlv($buf, $p);
        if ($t === null) {
            return null;
        }
        $p = $t['next'];

        return $t;
    }

    /** Reads an unsigned integer from a BER INTEGER / ENUMERATED content region. */
    private static function readInteger(string $buf, int $valueOff, int $len): int
    {
        $n = 0;
        for ($i = 0; $i < $len; $i++) {
            $n = ($n << 8) | ord($buf[$valueOff + $i]);
        }

        return $n;
    }

    private static function berTlv(int $tag, string $value): string
    {
        return chr($tag) . self::berLength(strlen($value)) . $value;
    }

    private static function berLength(int $len): string
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

    private static function berInteger(int $n): string
    {
        return self::berTlv(self::TAG_INTEGER, self::intBytes($n));
    }

    private static function berEnumerated(int $n): string
    {
        return self::berTlv(self::TAG_ENUMERATED, self::intBytes($n));
    }

    private static function berOctetString(string $value): string
    {
        return self::berTlv(self::TAG_OCTET_STRING, $value);
    }

    /** Minimal two's-complement encoding of a non-negative integer, adding a leading 0 if needed. */
    private static function intBytes(int $n): string
    {
        if ($n === 0) {
            return "\x00";
        }
        $bytes = '';
        $v = $n;
        while ($v > 0) {
            $bytes = chr($v & 0xFF) . $bytes;
            $v >>= 8;
        }
        // Keep it positive: a leading byte with the high bit set would read as negative.
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }

        return $bytes;
    }

    // ---- String helpers ----------------------------------------------------------------------

    /**
     * Escapes a value for the RFC 4515 filter string form: the specials * ( ) \ NUL and any
     * non-printable byte become \HH. Keeps captured filters both faithful and log-safe.
     */
    private static function filterEscape(string $s): string
    {
        $out = '';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            $o = ord($c);
            if ($c === '*' || $c === '(' || $c === ')' || $c === '\\' || $o < 0x20 || $o > 0x7E) {
                $out .= sprintf('\\%02x', $o);
            } else {
                $out .= $c;
            }
        }

        return $out;
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(string $s): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $s) ?? '';
    }

    private function logUnknown(LdapSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'ldap_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'LDAP unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'LDAP';
        $entry['proto'] = 'ldap';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        ($this->logger)($entry);
    }

    /** Records a per-connection fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => 389,
                'path' => 'LDAP internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 389;
    }
}

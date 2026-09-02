<?php

declare(strict_types=1);

namespace Funnypot\Protocol\S7comm;

/**
 * Zero-dependency, single-process TCP server for the low-interaction Siemens S7comm honeypot
 * (ISO-on-TCP / RFC 1006, port 102). Speaks just enough of COTP and S7comm in pure PHP, on a
 * non-blocking stream_select event loop, to answer the connection handshake a PLC scanner performs
 * and to log the memory- and identity-enumeration it runs.
 *
 * Wire framing: every message is a TPKT header (version 0x03, reserved, 2-byte big-endian length)
 * wrapping a COTP PDU. The connection opens with a COTP Connection Request (CR, 0xE0) which is
 * answered with a Connection Confirm (CC, 0xD0) echoing the TPDU references. S7comm PDUs then ride
 * inside COTP Data (DT, 0xF0) PDUs, each beginning with protocol id 0x32.
 *
 * Deliberately inert. The honeypot models three recon surfaces and nothing else:
 * - Setup Communication (Job, function 0xF0): answered with a negotiated PDU size.
 * - Read / Write Var (Job, 0x04 / 0x05): the requested area / DB / address is captured (PLC-memory
 *   recon); reads return zero-filled fakes and writes are logged but never applied.
 * - SZL / system-status read (Userdata, SZL-ID 0x0011 / 0x001C): answered with a believable module
 *   order number and firmware / component identity so the scanner fingerprints a plausible CPU.
 * Any real process value, authentication or state change is out of scope by construction.
 */
final class S7commServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms
    private const INBUF_CAP = 65536; // an S7comm exchange is far smaller; guard against buffer exhaustion

    // TPKT / COTP (RFC 1006 / ISO 8073).
    private const TPKT_VERSION = 0x03;
    private const COTP_CR = 0xE0; // Connection Request (top nibble)
    private const COTP_CC = 0xD0; // Connection Confirm
    private const COTP_DT = 0xF0; // Data TPDU

    // COTP variable-part parameter codes.
    private const COTP_PARAM_TPDU_SIZE = 0xC0;
    private const COTP_PARAM_SRC_TSAP = 0xC1;
    private const COTP_PARAM_DST_TSAP = 0xC2;

    // S7comm protocol id and ROSCTR (remote operating service control) message kinds.
    private const S7_PROTOCOL_ID = 0x32;
    private const ROSCTR_JOB = 0x01;
    private const ROSCTR_ACK = 0x02;
    private const ROSCTR_ACK_DATA = 0x03;
    private const ROSCTR_USERDATA = 0x07;

    // S7comm Job function codes.
    private const FUNC_SETUP_COMM = 0xF0;
    private const FUNC_READ_VAR = 0x04;
    private const FUNC_WRITE_VAR = 0x05;

    // Userdata function group (low nibble) and subfunction for reading a System Status List.
    private const UD_FUNCGROUP_CPU = 0x4;
    private const UD_SUBFUNC_READ_SZL = 0x01;

    // The two SZL lists a scanner reads to fingerprint the CPU.
    private const SZL_MODULE_ID = 0x0011;    // module identification (order number / versions)
    private const SZL_COMPONENT_ID = 0x001C; // component identification (names / serial / copyright)

    // S7ANY addressing item markers (Job Read/Write Var).
    private const VAR_SPEC = 0x12;
    private const VAR_SYNTAX_S7ANY = 0x10;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private S7commConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:102").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-s7comm: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-s7comm ({$this->config->moduleTypeName}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:S7commSession,ip:string}> $conns */
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

                // Guard against inbound buffer exhaustion — the exchange is tiny.
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
        $session = new S7commSession($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "S7comm connection from {$ip}:{$clientPort}",
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
     * Frames the inbound stream into TPKT PDUs and dispatches each one. Safe to drive directly with
     * raw bytes in tests.
     */
    public function processInbound(S7commSession $s): void
    {
        while (true) {
            if ($s->state === S7commSession::STATE_DONE) {
                return;
            }
            if (strlen($s->inbuf) < 4) {
                return; // need a full TPKT header first
            }
            if (ord($s->inbuf[0]) !== self::TPKT_VERSION) {
                // Not TPKT (a TLS ClientHello 0x16, HTTP, or junk). Nothing to model — record and drop.
                $this->logUnknown($s, sprintf('non-TPKT byte 0x%02X', ord($s->inbuf[0])));
                $s->close = true;

                return;
            }

            $len = (ord($s->inbuf[2]) << 8) | ord($s->inbuf[3]);
            if ($len < 7 || $len > self::INBUF_CAP) {
                $this->logUnknown($s, "bad TPKT length {$len}");
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < $len) {
                return; // wait for the rest of this PDU
            }

            $pdu = substr($s->inbuf, 0, $len);
            $s->inbuf = substr($s->inbuf, $len);

            $this->handlePdu($s, $pdu);
            if ($s->close || $s->state === S7commSession::STATE_DONE) {
                return;
            }
        }
    }

    private function handlePdu(S7commSession $s, string $pdu): void
    {
        // TPKT (4) then COTP: LI(1), PDU type(1), ...
        if (strlen($pdu) < 6) {
            $this->logUnknown($s, 'short COTP header');
            $s->close = true;

            return;
        }
        $li = ord($pdu[4]);
        $cotpType = ord($pdu[5]);

        if ($s->state === S7commSession::STATE_WAIT_COTP_CR) {
            if (($cotpType & 0xF0) === self::COTP_CR) {
                $this->handleConnectionRequest($s, $pdu, $li);
            } else {
                $this->logUnknown($s, sprintf('expected COTP Connection Request, got 0x%02X', $cotpType));
                $s->close = true;
            }

            return;
        }

        // Post-handshake: S7comm rides inside a COTP Data TPDU.
        if ($cotpType === self::COTP_DT) {
            $this->handleData($s, $pdu, $li);

            return;
        }

        $this->logUnknown($s, sprintf('unexpected COTP PDU type 0x%02X', $cotpType));
        $s->close = true;
    }

    /**
     * Parses the COTP Connection Request, captures the TSAPs, logs the connect, and queues a
     * Connection Confirm echoing the client's references with the TSAPs swapped back.
     */
    private function handleConnectionRequest(S7commSession $s, string $pdu, int $li): void
    {
        // COTP CR fixed part: LI(1), CR|CDT(1), DST-REF(2), SRC-REF(2), class/option(1), then params.
        if (strlen($pdu) < 11) {
            $this->logUnknown($s, 'short COTP Connection Request');
            $s->close = true;

            return;
        }
        $dstRef = self::be16($pdu, 6);
        $srcRef = self::be16($pdu, 8);

        // Variable part: LI counts the header after the LI byte; the 6 fixed bytes are type + refs +
        // class, so the parameters are what remains, bounded by the frame.
        $paramLen = max(0, $li - 6);
        $params = substr($pdu, 11, $paramLen);
        $this->parseCotpParams($s, $params);

        $this->logEvent([
            'event' => 's7_connect',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'medium',
            'path' => sprintf(
                'S7comm COTP connect src-tsap=%s dst-tsap=%s',
                $s->srcTsap !== null ? sprintf('0x%04X', $s->srcTsap) : '-',
                $s->dstTsap !== null ? sprintf('0x%04X', $s->dstTsap) : '-'
            ),
            'src_tsap' => $s->srcTsap !== null ? sprintf('0x%04X', $s->srcTsap) : '',
            'dst_tsap' => $s->dstTsap !== null ? sprintf('0x%04X', $s->dstTsap) : '',
        ]);

        // A real PLC confirms with DST-REF echoing the client's SRC-REF and its own assigned SRC-REF
        // (the client's DST-REF is zero in a CR, so a fixed reference is assigned), and mirrors the
        // TSAP parameters with source and destination swapped.
        $ccSrcRef = $dstRef !== 0 ? $dstRef : 0x0001;
        $s->outbuf .= $this->buildConnectionConfirm($srcRef, $ccSrcRef, $s);
        $s->state = S7commSession::STATE_CONNECTED;
    }

    /** Walks the COTP variable part and records TPDU size and the two TSAPs. */
    private function parseCotpParams(S7commSession $s, string $params): void
    {
        $off = 0;
        $n = strlen($params);
        while ($off + 2 <= $n) {
            $code = ord($params[$off]);
            $plen = ord($params[$off + 1]);
            if ($off + 2 + $plen > $n) {
                break;
            }
            $val = substr($params, $off + 2, $plen);
            switch ($code) {
                case self::COTP_PARAM_TPDU_SIZE:
                    if ($plen >= 1) {
                        $s->tpduSizeCode = ord($val[0]);
                    }
                    break;
                case self::COTP_PARAM_SRC_TSAP:
                    if ($plen >= 2) {
                        $s->srcTsap = self::be16($val, 0);
                    }
                    break;
                case self::COTP_PARAM_DST_TSAP:
                    if ($plen >= 2) {
                        $s->dstTsap = self::be16($val, 0);
                    }
                    break;
            }
            $off += 2 + $plen;
        }
    }

    /**
     * Builds a TPKT + COTP Connection Confirm. Mirrors the client's TPDU size and swaps its TSAPs so
     * the confirm looks like a real PLC completing the ISO-on-TCP handshake.
     */
    private function buildConnectionConfirm(int $dstRef, int $srcRef, S7commSession $s): string
    {
        $params = '';
        if ($s->tpduSizeCode !== null) {
            $params .= chr(self::COTP_PARAM_TPDU_SIZE) . "\x01" . chr($s->tpduSizeCode);
        }
        // Confirm's src-tsap is what the client asked to reach (its dst-tsap), and vice versa.
        if ($s->dstTsap !== null) {
            $params .= chr(self::COTP_PARAM_SRC_TSAP) . "\x02" . pack('n', $s->dstTsap);
        }
        if ($s->srcTsap !== null) {
            $params .= chr(self::COTP_PARAM_DST_TSAP) . "\x02" . pack('n', $s->srcTsap);
        }

        // LI counts everything in the COTP header after the LI byte: type + DST-REF + SRC-REF + class
        // + variable params = 6 + params.
        $li = 6 + strlen($params);
        $cotp = chr($li) . chr(self::COTP_CC) . pack('n', $dstRef) . pack('n', $srcRef) . "\x00" . $params;

        return self::tpkt($cotp);
    }

    /**
     * Unwraps a COTP Data TPDU and dispatches the S7comm PDU it carries.
     */
    private function handleData(S7commSession $s, string $pdu, int $li): void
    {
        // COTP DT header: LI(1), 0xF0, TPDU-NR/EOT(1). The S7comm PDU starts after LI byte + LI bytes.
        $s7 = substr($pdu, 5 + $li);
        if (strlen($s7) < 10 || ord($s7[0]) !== self::S7_PROTOCOL_ID) {
            $this->logUnknown($s, 'COTP Data without an S7comm PDU');
            $s->close = true;

            return;
        }

        $rosctr = ord($s7[1]);
        $pduRef = self::be16($s7, 4);
        $paramLen = self::be16($s7, 6);
        $dataLen = self::be16($s7, 8);
        $headerLen = ($rosctr === self::ROSCTR_ACK || $rosctr === self::ROSCTR_ACK_DATA) ? 12 : 10;

        $param = substr($s7, $headerLen, $paramLen);
        $data = substr($s7, $headerLen + $paramLen, $dataLen);

        switch ($rosctr) {
            case self::ROSCTR_JOB:
                $this->handleJob($s, $pduRef, $param, $data);
                break;

            case self::ROSCTR_USERDATA:
                $this->handleUserdata($s, $pduRef, $param, $data);
                break;

            default:
                // Acks / unrecognised control kinds carry no recon and warrant no reply; record only.
                $this->logUnknown($s, sprintf('S7comm ROSCTR 0x%02X', $rosctr));
        }
    }

    /**
     * Dispatches an S7comm Job PDU: Setup Communication, Read Var or Write Var.
     */
    private function handleJob(S7commSession $s, int $pduRef, string $param, string $data): void
    {
        if ($param === '') {
            $this->logUnknown($s, 'empty S7comm Job parameter');

            return;
        }
        $func = ord($param[0]);

        switch ($func) {
            case self::FUNC_SETUP_COMM:
                $this->handleSetupCommunication($s, $pduRef, $param);
                break;

            case self::FUNC_READ_VAR:
                $this->handleReadVar($s, $pduRef, $param);
                break;

            case self::FUNC_WRITE_VAR:
                $this->handleWriteVar($s, $pduRef, $param);
                break;

            default:
                // An unmodelled function is recon in itself; record it but keep the connection open so
                // the attacker's later, modelled probes are still captured.
                $this->logUnknown($s, sprintf('S7comm Job function 0x%02X', $func));
        }
    }

    /**
     * Setup Communication (function 0xF0): capture the requested PDU size and answer with a negotiated
     * one, so the client proceeds to the reads and SZL queries we care about.
     */
    private function handleSetupCommunication(S7commSession $s, int $pduRef, string $param): void
    {
        $requestedPdu = strlen($param) >= 8 ? self::be16($param, 6) : $this->config->maxPduSize;
        $negotiated = min($requestedPdu > 0 ? $requestedPdu : $this->config->maxPduSize, $this->config->maxPduSize);
        $s->negotiatedPduSize = $negotiated;

        $this->logEvent([
            'event' => 's7_job',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'medium',
            'path' => sprintf('S7comm Setup Communication requested_pdu=%d negotiated_pdu=%d', $requestedPdu, $negotiated),
            'function' => 'setup',
        ]);

        // Ack_Data parameter mirrors the Setup Communication shape with the negotiated PDU size.
        $respParam = chr(self::FUNC_SETUP_COMM) . "\x00"
            . pack('n', $this->config->maxAmqCalling)
            . pack('n', $this->config->maxAmqCalled)
            . pack('n', $negotiated);

        $s->outbuf .= $this->buildS7Reply(self::ROSCTR_ACK_DATA, $pduRef, $respParam, '');
    }

    /**
     * Read Var (function 0x04): capture the enumerated area / DB / address, then answer with
     * zero-filled fakes. No real memory is ever read.
     */
    private function handleReadVar(S7commSession $s, int $pduRef, string $param): void
    {
        $items = self::parseVarItems($param);
        foreach ($items as $item) {
            $s->reads[] = ['op' => 'read'] + $item;
        }

        $this->logEvent([
            'event' => 's7_job',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'high',
            'path' => 'S7comm Read Var: ' . self::describeItems($items),
            'function' => 'read',
            'items' => self::describeItems($items),
        ]);

        // Data section: one data item per requested item, filled with zeros (inert — never real data).
        $dataItems = [];
        foreach ($items as $item) {
            $dataItems[] = $this->buildReadDataItem($item['transport'], $item['count']);
        }
        $dataBlock = self::concatDataItems($dataItems);

        $respParam = chr(self::FUNC_READ_VAR) . chr(count($items));
        $s->outbuf .= $this->buildS7Reply(self::ROSCTR_ACK_DATA, $pduRef, $respParam, $dataBlock);
    }

    /**
     * Write Var (function 0x05): capture the targeted area / DB / address, then acknowledge success
     * for each item. INERT — the write is logged but never applied.
     */
    private function handleWriteVar(S7commSession $s, int $pduRef, string $param): void
    {
        $items = self::parseVarItems($param);
        foreach ($items as $item) {
            $s->reads[] = ['op' => 'write'] + $item;
        }

        $this->logEvent([
            'event' => 's7_job',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'high',
            'path' => 'S7comm Write Var (inert, not applied): ' . self::describeItems($items),
            'function' => 'write',
            'items' => self::describeItems($items),
        ]);

        // Write response data: a single return-code byte per item. 0xFF = success, so the attacker
        // believes the write landed while nothing real changed.
        $dataBlock = str_repeat("\xff", count($items));

        $respParam = chr(self::FUNC_WRITE_VAR) . chr(count($items));
        $s->outbuf .= $this->buildS7Reply(self::ROSCTR_ACK_DATA, $pduRef, $respParam, $dataBlock);
    }

    /**
     * Parses the item list of a Read/Write Var parameter into structured addresses. Only S7ANY
     * (syntax 0x10) items are decoded in full; other syntaxes are captured as raw markers.
     *
     * @return list<array{area:int,db:int,byte:int,bit:int,count:int,transport:int}>
     */
    public static function parseVarItems(string $param): array
    {
        // param: function(1), itemCount(1), then itemCount items.
        if (strlen($param) < 2) {
            return [];
        }
        $itemCount = ord($param[1]);
        $off = 2;
        $items = [];
        $n = strlen($param);

        for ($i = 0; $i < $itemCount && $i < 256; $i++) {
            if ($off + 2 > $n || ord($param[$off]) !== self::VAR_SPEC) {
                break;
            }
            $addrLen = ord($param[$off + 1]);
            $body = substr($param, $off + 2, $addrLen);
            $off += 2 + $addrLen;

            // S7ANY body: syntax(1)=0x10, transport(1), count(2), db(2), area(1), address(3, bit-addr).
            if (strlen($body) >= 10 && ord($body[0]) === self::VAR_SYNTAX_S7ANY) {
                $transport = ord($body[1]);
                $count = self::be16($body, 2);
                $db = self::be16($body, 4);
                $area = ord($body[6]);
                $addr = (ord($body[7]) << 16) | (ord($body[8]) << 8) | ord($body[9]);
                $items[] = [
                    'area' => $area,
                    'db' => $db,
                    'byte' => $addr >> 3,
                    'bit' => $addr & 0x7,
                    'count' => $count,
                    'transport' => $transport,
                ];
            } else {
                // Non-S7ANY addressing (symbolic / 1200 optimised): record its presence only.
                $items[] = ['area' => -1, 'db' => 0, 'byte' => 0, 'bit' => 0, 'count' => 0, 'transport' => 0];
            }
        }

        return $items;
    }

    /**
     * Builds one Read Var response data item of zeros for the requested transport size and element
     * count. The bytes are synthetic (all zero), never real process data.
     */
    private function buildReadDataItem(int $transport, int $count): string
    {
        $count = max(1, $count);
        $cap = $this->config->maxPduSize; // never build an item larger than a negotiated PDU

        if ($transport === 0x01) { // BIT
            $bits = min($count, $cap * 8);
            $dataBytes = str_repeat("\x00", (int) ceil($bits / 8));

            // Return code 0xFF (success), data transport 0x03 (BIT), length in bits.
            return "\xff\x03" . pack('n', $bits) . $dataBytes;
        }

        $byteLen = min($count * self::transportSize($transport), $cap);
        $byteLen = max(1, $byteLen);
        $dataBytes = str_repeat("\x00", $byteLen);

        // Return code 0xFF (success), data transport 0x04 (BYTE/WORD/DWORD), length in bits.
        return "\xff\x04" . pack('n', $byteLen * 8) . $dataBytes;
    }

    /**
     * Concatenates response data items, inserting a fill byte after every item but the last so each
     * item begins on an even boundary (the S7comm convention real clients expect).
     *
     * @param list<string> $items
     */
    private static function concatDataItems(array $items): string
    {
        $out = '';
        $last = count($items) - 1;
        foreach ($items as $i => $item) {
            $out .= $item;
            if ($i !== $last && (strlen($item) % 2) !== 0) {
                $out .= "\x00";
            }
        }

        return $out;
    }

    /**
     * Userdata PDU: the System Status List reads a scanner uses to fingerprint the CPU. A CPU-function
     * Read SZL is captured and answered with the persona identity; anything else is recorded as
     * unmodelled.
     */
    private function handleUserdata(S7commSession $s, int $pduRef, string $param, string $data): void
    {
        // Userdata parameter: head(00 01 12), length(1), method(1), type|funcgroup(1), subfunc(1),
        // sequence(1), ...
        if (strlen($param) < 8 || substr($param, 0, 3) !== "\x00\x01\x12") {
            $this->logUnknown($s, 'malformed S7comm Userdata parameter');

            return;
        }
        $typeFg = ord($param[5]);
        $subfunc = ord($param[6]);
        $seq = ord($param[7]);
        $funcgroup = $typeFg & 0x0F;

        if ($funcgroup !== self::UD_FUNCGROUP_CPU || $subfunc !== self::UD_SUBFUNC_READ_SZL) {
            $this->logUnknown($s, sprintf('S7comm Userdata funcgroup=0x%X subfunc=0x%02X', $funcgroup, $subfunc));

            return;
        }

        // Data: return code(1), transport(1), length(2), SZL-ID(2), SZL-index(2).
        $szlId = strlen($data) >= 8 ? self::be16($data, 4) : 0;
        $szlIndex = strlen($data) >= 8 ? self::be16($data, 6) : 0;
        $s->szlReads[] = ['id' => $szlId, 'index' => $szlIndex];

        $this->logEvent([
            'event' => 's7_szl',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'high',
            'path' => sprintf('S7comm SZL read id=0x%04X index=0x%04X (%s)', $szlId, $szlIndex, self::szlName($szlId)),
            'szl_id' => sprintf('0x%04X', $szlId),
            'szl_index' => sprintf('0x%04X', $szlIndex),
        ]);

        $s->outbuf .= $this->buildSzlReply($pduRef, $szlId, $szlIndex, $subfunc, $seq);
    }

    /**
     * Builds a believable SZL read response for SZL-ID 0x0011 (module identification) or 0x001C
     * (component identification). Unknown lists get an empty (zero-record) SZL block, mirroring a CPU
     * that has no data for that list.
     */
    private function buildSzlReply(int $pduRef, int $szlId, int $szlIndex, int $subfunc, int $seq): string
    {
        [$recordLen, $records] = $this->buildSzlRecords($szlId, $szlIndex);
        $recordCount = $recordLen > 0 ? intdiv(strlen($records), $recordLen) : 0;

        // SZL data block: SZL-ID(2), SZL-index(2), record length(2), record count(2), records.
        $szlData = pack('n', $szlId) . pack('n', $szlIndex) . pack('n', $recordLen) . pack('n', $recordCount) . $records;

        // Data item: return code 0xFF (success), transport 0x09 (octet string), byte length, payload.
        $dataItem = "\xff\x09" . pack('n', strlen($szlData)) . $szlData;

        // Userdata response parameter: head + length(0x08) + method(0x12 response) + type|funcgroup
        // (0x84 = response + CPU functions) + subfunc + seq + data-unit-ref + last-data-unit + error(2).
        $respParam = "\x00\x01\x12\x08\x12\x84" . chr($subfunc) . chr($seq) . "\x00\x00\x00\x00";

        return $this->buildS7Reply(self::ROSCTR_USERDATA, $pduRef, $respParam, $dataItem);
    }

    /**
     * Builds the fixed-width SZL records for a list. Returns [recordLength, packedRecords].
     *
     * @return array{0:int,1:string}
     */
    private function buildSzlRecords(int $szlId, int $szlIndex): array
    {
        if ($szlId === self::SZL_MODULE_ID) {
            // Module identification record: index(2), MlfB order number(20), BGType(2), version(2)x2.
            $index = 0x0001;
            if ($szlIndex !== 0 && $szlIndex !== $index) {
                return [28, '']; // a specific, non-modelled index -> no records
            }
            $record = pack('n', $index)
                . self::fixedAscii($this->config->orderNumber, 20)
                . "\x00\x00" // BGType
                . pack('n', $this->config->hardwareVersion & 0xFFFF)
                . chr($this->config->firmwareMajor & 0xFF) . chr($this->config->firmwareMinor & 0xFF);

            return [28, $record];
        }

        if ($szlId === self::SZL_COMPONENT_ID) {
            // Component identification record: index(2) + 32-byte value.
            $components = [
                0x0001 => $this->config->systemName,
                0x0002 => $this->config->moduleName,
                0x0003 => $this->config->plantId,
                0x0004 => $this->config->copyright,
                0x0005 => $this->config->serialNumber,
                0x0007 => $this->config->moduleTypeName,
            ];

            $records = '';
            foreach ($components as $idx => $value) {
                if ($szlIndex !== 0 && $szlIndex !== $idx) {
                    continue;
                }
                $records .= pack('n', $idx) . self::fixedAscii($value, 32);
            }

            return [34, $records];
        }

        return [0, '']; // unmodelled SZL list -> believable empty block
    }

    /**
     * Wraps an S7comm reply: TPKT + COTP Data + S7 header (Ack_Data carries the 12-byte header with
     * error class/code; Userdata responses use the 10-byte header).
     */
    private function buildS7Reply(int $rosctr, int $pduRef, string $param, string $data): string
    {
        $header = chr(self::S7_PROTOCOL_ID) . chr($rosctr) . "\x00\x00" . pack('n', $pduRef)
            . pack('n', strlen($param)) . pack('n', strlen($data));

        if ($rosctr === self::ROSCTR_ACK || $rosctr === self::ROSCTR_ACK_DATA) {
            $header .= "\x00\x00"; // error class + error code (no error)
        }

        return self::tpktCotpData($header . $param . $data);
    }

    // ---- Descriptors / naming -----------------------------------------------------------------

    /**
     * @param list<array{area:int,db:int,byte:int,bit:int,count:int,transport:int}> $items
     */
    private static function describeItems(array $items): string
    {
        if ($items === []) {
            return '(no items)';
        }
        $parts = [];
        foreach (array_slice($items, 0, 16) as $item) {
            if ($item['area'] === -1) {
                $parts[] = 'symbolic/optimised';
                continue;
            }
            $area = self::areaName($item['area']);
            $loc = $item['area'] === 0x84 || $item['area'] === 0x85
                ? sprintf('%s%d.DBX%d.%d', $area, $item['db'], $item['byte'], $item['bit'])
                : sprintf('%s%d.%d', $area, $item['byte'], $item['bit']);
            $parts[] = sprintf('%s x%d %s', $loc, $item['count'], self::transportName($item['transport']));
        }

        return implode(', ', $parts);
    }

    public static function areaName(int $area): string
    {
        return match ($area) {
            0x81 => 'I',   // process image inputs
            0x82 => 'Q',   // process image outputs
            0x83 => 'M',   // markers / flags (Merker)
            0x84 => 'DB',  // data block
            0x85 => 'DI',  // instance data block
            0x86 => 'L',   // local data
            0x1C => 'C',   // S7 counter
            0x1D => 'T',   // S7 timer
            default => sprintf('area0x%02X', $area),
        };
    }

    private static function transportName(int $t): string
    {
        return match ($t) {
            0x01 => 'BIT',
            0x02 => 'BYTE',
            0x03 => 'CHAR',
            0x04 => 'WORD',
            0x05 => 'INT',
            0x06 => 'DWORD',
            0x07 => 'DINT',
            0x08 => 'REAL',
            default => sprintf('transport0x%02X', $t),
        };
    }

    private static function transportSize(int $t): int
    {
        return match ($t) {
            0x02, 0x03 => 1, // BYTE / CHAR
            0x04, 0x05 => 2, // WORD / INT
            0x06, 0x07, 0x08 => 4, // DWORD / DINT / REAL
            default => 1,
        };
    }

    private static function szlName(int $szlId): string
    {
        return match ($szlId) {
            self::SZL_MODULE_ID => 'Module identification',
            self::SZL_COMPONENT_ID => 'Component identification',
            default => 'SZL list',
        };
    }

    // ---- Byte helpers -------------------------------------------------------------------------

    /** Truncates/space-pads $s to exactly $len bytes (SZL fields are fixed width, space filled). */
    private static function fixedAscii(string $s, int $len): string
    {
        if (strlen($s) >= $len) {
            return substr($s, 0, $len);
        }

        return $s . str_repeat(' ', $len - strlen($s));
    }

    private static function be16(string $b, int $off): int
    {
        if ($off + 2 > strlen($b)) {
            return 0;
        }

        return (ord($b[$off]) << 8) | ord($b[$off + 1]);
    }

    private static function tpkt(string $payload): string
    {
        // TPKT header: version(0x03), reserved(0x00), length(2 BE) counting the 4-byte header.
        return "\x03\x00" . pack('n', strlen($payload) + 4) . $payload;
    }

    private static function tpktCotpData(string $s7): string
    {
        // COTP Data TPDU header "02 f0 80" precedes every S7comm PDU.
        return self::tpkt("\x02\xf0\x80" . $s7);
    }

    // ---- Logging ------------------------------------------------------------------------------

    private function logUnknown(S7commSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 's7_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'S7comm unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'S7COMM';
        $entry['proto'] = 's7comm';
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
                'port' => 102,
                'path' => 'S7comm internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 102;
    }
}

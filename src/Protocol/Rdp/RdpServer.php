<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rdp;

/**
 * Zero-dependency, single-process TCP server for the low-interaction RDP honeypot.
 * Speaks just enough of MS-RDPBCGR (RDP connection sequence) and MS-NLMP (NTLM) in pure PHP,
 * on a non-blocking stream_select event loop, to log scanners and harvest credentials.
 *
 * Deliberately tier-1: no desktop is ever rendered. RDP attacks are overwhelmingly
 * credential-spray, so the value is the connection metadata and the credential attempt, not the
 * graphics (a real desktop needs MCS bitmap codecs and modern clients gate it behind NLA anyway).
 *
 * Capture path:
 * - Read the X.224 Connection Request: the `mstshash` routing cookie (the username a brute-forcer
 *   is trying) and the RDP Negotiation Request flags (which of RDP/TLS/CredSSP the tool asked for).
 * - Answer with a Connection Confirm selecting standard RDP Security, so the client proceeds over
 *   plain TCP rather than a TLS/CredSSP tunnel — the path that surfaces a cleartext credential.
 * - Walk the MCS connection sequence (Connect Response, Attach User Confirm, Channel Join Confirms)
 *   far enough to receive the Client Info PDU, then parse its cleartext domain/username/password.
 * - If NTLM material appears instead, parse the NTLMSSP AUTHENTICATE (username/domain/workstation
 *   and the crackable NTLMv2 response). Never authenticate; close after capture.
 */
final class RdpServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms
    private const INBUF_CAP = 65536; // a legitimate RDP connection sequence is far smaller

    // TPKT / X.224 (RFC 1006, MS-RDPBCGR 2.2.1).
    private const TPKT_VERSION = 0x03;
    private const X224_CR = 0xE0; // Connection Request TPDU code (top nibble)
    private const X224_CC = 0xD0; // Connection Confirm TPDU code
    private const X224_DT = 0xF0; // Data TPDU code

    // RDP negotiation structure types (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1 / 2.2.1.2.2).
    private const RDP_NEG_REQ = 0x01;
    private const RDP_NEG_RSP = 0x02;

    // MCS domain-PDU discriminators: the T.125 CHOICE index shifted left by two.
    private const MCS_CONNECT_INITIAL = 0x7F; // BER [APPLICATION 101], second byte 0x65
    private const MCS_ERECT_DOMAIN_REQ = 0x04;
    private const MCS_ATTACH_USER_REQ = 0x28;
    private const MCS_CHANNEL_JOIN_REQ = 0x38;
    private const MCS_SEND_DATA_REQ = 0x64;

    // Server-assigned MCS channels. The user channel is handed to the client in the Attach User
    // Confirm; the I/O channel carries the Client Info PDU.
    private const MCS_IO_CHANNEL = 1003;   // 0x03EB
    private const MCS_USER_CHANNEL = 1007; // 0x03EF

    // Client Info PDU markers (MS-RDPBCGR 2.2.1.11).
    private const SEC_INFO_PKT = 0x0040; // basic security header flag identifying the Client Info PDU
    private const INFO_UNICODE = 0x0010; // TS_INFO_PACKET flag: strings are UTF-16LE

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private RdpConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:3389").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-rdp: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-rdp listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:RdpSession,ip:string}> $conns */
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

                // Guard against inbound buffer exhaustion — the connection sequence is tiny.
                if (strlen($session->inbuf) > self::INBUF_CAP) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                $this->processInbound($session);
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
        $session = new RdpSession($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "RDP connection from {$ip}:{$clientPort}",
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
    public function processInbound(RdpSession $s): void
    {
        while (true) {
            if ($s->state === RdpSession::STATE_DONE) {
                return;
            }
            if (strlen($s->inbuf) < 4) {
                return; // need a full TPKT header first
            }
            if (ord($s->inbuf[0]) !== self::TPKT_VERSION) {
                // Not TPKT: a TLS ClientHello (0x16) from an NLA-only client, or junk. Nothing to
                // model — record it and drop cleanly.
                $this->logUnknown($s, sprintf('non-TPKT byte 0x%02X', ord($s->inbuf[0])));
                $s->close = true;

                return;
            }

            $len = (ord($s->inbuf[2]) << 8) | ord($s->inbuf[3]);
            if ($len < 5 || $len > self::INBUF_CAP) {
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
            if ($s->close || $s->state === RdpSession::STATE_DONE) {
                return;
            }
        }
    }

    private function handlePdu(RdpSession $s, string $pdu): void
    {
        if ($s->state === RdpSession::STATE_WAIT_CONNECTION_REQUEST) {
            $this->handleConnectionRequest($s, $pdu);

            return;
        }

        // Post-negotiation: MCS PDUs ride inside an X.224 Data TPDU (header "02 f0 80"), so the MCS
        // body starts at offset 7 (TPKT 4 + X.224 DT 3).
        if (strlen($pdu) < 8 || ord($pdu[5]) !== self::X224_DT) {
            $this->logUnknown($s, 'malformed X.224 data PDU');
            $s->close = true;

            return;
        }
        $mcs = substr($pdu, 7);

        // Any NTLM AUTHENTICATE reaching us in the clear is a credential regardless of framing.
        if ($this->captureNtlm($s, $pdu)) {
            return;
        }

        switch (ord($mcs[0])) {
            case self::MCS_CONNECT_INITIAL:
                $s->outbuf .= $this->buildMcsConnectResponse();
                break;

            case self::MCS_ERECT_DOMAIN_REQ:
                // No confirm is defined for Erect Domain Request.
                break;

            case self::MCS_ATTACH_USER_REQ:
                $s->outbuf .= $this->buildAttachUserConfirm();
                break;

            case self::MCS_CHANNEL_JOIN_REQ:
                $this->handleChannelJoin($s, $mcs);
                break;

            case self::MCS_SEND_DATA_REQ:
                $this->handleSendData($s, $mcs);
                break;

            default:
                $this->logUnknown($s, sprintf('unmodelled MCS discriminator 0x%02X', ord($mcs[0])));
                $s->close = true;
        }
    }

    /**
     * Parses the X.224 Connection Request, logs the mstshash cookie and requested protocols, and
     * queues a Connection Confirm selecting standard RDP Security.
     */
    private function handleConnectionRequest(RdpSession $s, string $pdu): void
    {
        // TPKT (4) then the X.224 CR fixed part: LI, CR code, DST-REF(2), SRC-REF(2), class(1).
        if (strlen($pdu) < 11 || (ord($pdu[5]) & 0xF0) !== self::X224_CR) {
            $this->logUnknown($s, 'not an X.224 Connection Request');
            $s->close = true;

            return;
        }

        $srcRef = (ord($pdu[8]) << 8) | ord($pdu[9]);
        $variable = substr($pdu, 11); // cookie / routing token + optional RDP Negotiation Request

        $parsed = self::parseConnectionRequest($variable);
        $s->mstshash = $parsed['mstshash'];
        $s->requestedProtocols = $parsed['requestedProtocols'];
        $s->sawNegotiationRequest = $parsed['sawNegotiationRequest'];

        if ($s->mstshash !== null) {
            $this->logEvent([
                'event' => 'rdp_cookie',
                'ip' => $s->ip,
                'port' => $s->port,
                'path' => 'RDP cookie mstshash=' . $s->mstshash,
                'body' => $s->mstshash,
                'severity' => 'high',
            ]);
        }

        if ($s->sawNegotiationRequest) {
            $names = self::protocolNames($s->requestedProtocols);
            $this->logEvent([
                'event' => 'rdp_negotiate',
                'ip' => $s->ip,
                'port' => $s->port,
                'path' => 'RDP negotiate requested: ' . $names,
            ]);
        }

        // A client that sent no negotiation request expects a bare Connection Confirm (no negotiation
        // response) and standard RDP Security. One that negotiated gets our selected protocol.
        $s->outbuf .= self::buildConnectionConfirm(
            $s->sawNegotiationRequest ? $this->config->selectedProtocol : null,
            $srcRef
        );
        $s->state = RdpSession::STATE_MCS;
    }

    /**
     * Parses the variable part of an X.224 Connection Request.
     *
     * @return array{mstshash:?string,routingToken:?string,requestedProtocols:int,sawNegotiationRequest:bool}
     */
    public static function parseConnectionRequest(string $variable): array
    {
        $mstshash = null;
        $routingToken = null;
        $negOffset = 0;

        // The optional cookie / routing token is an ASCII line terminated by CR LF. mstshash carries
        // the username a brute-forcer is trying; a "Cookie: msts=" token routes to a session broker.
        $crlf = strpos($variable, "\r\n");
        if (str_starts_with($variable, 'Cookie: ') && $crlf !== false) {
            $line = substr($variable, 8, $crlf - 8);
            if (str_starts_with($line, 'mstshash=')) {
                $mstshash = substr($line, 9);
            } elseif (str_starts_with($line, 'msts=')) {
                $routingToken = substr($line, 5);
            }
            $negOffset = $crlf + 2;
        }

        $requestedProtocols = 0; // PROTOCOL_RDP
        $sawNegotiationRequest = false;

        // RDP Negotiation Request: type(1)=0x01, flags(1), length(2 LE)=0x0008, requestedProtocols(4 LE).
        if (strlen($variable) - $negOffset >= 8 && ord($variable[$negOffset]) === self::RDP_NEG_REQ) {
            $requestedProtocols = self::le32($variable, $negOffset + 4);
            $sawNegotiationRequest = true;
        }

        return [
            'mstshash' => $mstshash,
            'routingToken' => $routingToken,
            'requestedProtocols' => $requestedProtocols,
            'sawNegotiationRequest' => $sawNegotiationRequest,
        ];
    }

    /**
     * Builds a TPKT + X.224 Connection Confirm. When $selectedProtocol is non-null an RDP
     * Negotiation Response is appended selecting that protocol; otherwise a bare Confirm is sent.
     */
    public static function buildConnectionConfirm(?int $selectedProtocol, int $dstRef): string
    {
        $neg = '';
        if ($selectedProtocol !== null) {
            // RDP Negotiation Response: type(1)=0x02, flags(1)=0, length(2 LE)=8, selectedProtocol(4 LE).
            $neg = chr(self::RDP_NEG_RSP) . "\x00" . pack('v', 8) . pack('V', $selectedProtocol);
        }

        // X.224 Connection Confirm: LI counts the header after LI plus the negotiation response.
        // DST-REF echoes the client's SRC-REF from the Connection Request; SRC-REF is left zero.
        $li = 6 + strlen($neg);
        $x224 = chr($li) . chr(self::X224_CC) . pack('n', $dstRef) . "\x00\x00" . "\x00" . $neg;

        return self::tpkt($x224);
    }

    private function handleChannelJoin(RdpSession $s, string $mcs): void
    {
        // Channel Join Request: 0x38, initiator(2), channelId(2). Echo the channel in a Join Confirm.
        if (strlen($mcs) < 5) {
            $this->logUnknown($s, 'short MCS Channel Join Request');
            $s->close = true;

            return;
        }
        $initiator = substr($mcs, 1, 2);
        $channel = substr($mcs, 3, 2);
        $s->outbuf .= $this->buildChannelJoinConfirm($initiator, $channel);
    }

    /**
     * Unwraps an MCS Send Data Request and captures the credential it carries: a cleartext Client
     * Info PDU, or NTLM material. Anything else on this channel ends the session cleanly.
     */
    private function handleSendData(RdpSession $s, string $mcs): void
    {
        // 0x64, initiator(2), channelId(2), dataPriority(1), userData-length (PER), userData.
        if (strlen($mcs) < 8) {
            $this->logUnknown($s, 'short MCS Send Data Request');
            $s->close = true;

            return;
        }
        $off = 6; // past discriminator + initiator + channelId + priority
        $lenByte = ord($mcs[$off]);
        if ($lenByte & 0x80) {
            $length = (($lenByte & 0x7F) << 8) | ord($mcs[$off + 1]);
            $off += 2;
        } else {
            $length = $lenByte;
            $off += 1;
        }
        $userData = substr($mcs, $off, $length);

        $cred = self::parseClientInfo($userData);
        if ($cred !== null) {
            $this->logCredential($s, $cred, 'RDP Client Info PDU (standard security)');
            $s->state = RdpSession::STATE_DONE;
            $s->close = true;

            return;
        }

        // The credential PDU is what we came for; anything else on the I/O channel is unmodelled.
        $this->logUnknown($s, 'MCS Send Data without a recognised credential PDU');
        $s->close = true;
    }

    /**
     * Scans a PDU for an NTLMSSP AUTHENTICATE message and, if found, logs the captured credential.
     * Returns true when a credential was captured.
     */
    private function captureNtlm(RdpSession $s, string $pdu): bool
    {
        $ntlm = self::parseNtlmAuthenticate($pdu);
        if ($ntlm === null) {
            return false;
        }
        $this->logCredential($s, $ntlm, 'NTLMSSP AUTHENTICATE (NLA/CredSSP)');
        $s->state = RdpSession::STATE_DONE;
        $s->close = true;

        return true;
    }

    /**
     * @param array<string,string> $cred
     */
    private function logCredential(RdpSession $s, array $cred, string $via): void
    {
        $domain = $cred['domain'] ?? '';
        $user = $cred['username'] ?? '';
        $account = ($domain !== '' ? $domain . '\\' : '') . $user;

        $body = [];
        foreach ($cred as $k => $v) {
            $body[] = "{$k}={$v}";
        }

        $this->logEvent([
            'event' => 'rdp_cred',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => "RDP login attempt: {$account} via {$via}",
            'body' => implode(' ', $body),
            'severity' => 'critical',
        ]);
    }

    /**
     * Parses a TS_INFO_PACKET (Client Info PDU) sent under standard RDP Security with encryption
     * disabled, returning the cleartext credential. Returns null if $userData is not a Client Info
     * PDU or is malformed.
     *
     * @return array{domain:string,username:string,password:string}|null
     */
    public static function parseClientInfo(string $userData): ?array
    {
        // Basic Security Header: flags(2 LE), flagsHi(2 LE). SEC_INFO_PKT identifies the Client Info PDU.
        if (strlen($userData) < 4) {
            return null;
        }
        $secFlags = self::le16($userData, 0);
        if (!($secFlags & self::SEC_INFO_PKT)) {
            return null;
        }

        $info = substr($userData, 4);
        // TS_INFO_PACKET: codePage(4), flags(4), cbDomain(2), cbUserName(2), cbPassword(2),
        // cbAlternateShell(2), cbWorkingDir(2), then the strings with null terminators.
        if (strlen($info) < 18) {
            return null;
        }
        $flags = self::le32($info, 4);
        $cbDomain = self::le16($info, 8);
        $cbUser = self::le16($info, 10);
        $cbPassword = self::le16($info, 12);
        $unicode = (bool) ($flags & self::INFO_UNICODE);
        $term = $unicode ? 2 : 1; // null terminator width; the cb* lengths exclude it

        $p = 18;
        $domain = self::readInfoField($info, $p, $cbDomain, $term, $unicode);
        $username = self::readInfoField($info, $p, $cbUser, $term, $unicode);
        $password = self::readInfoField($info, $p, $cbPassword, $term, $unicode);
        if ($domain === null || $username === null || $password === null) {
            return null;
        }

        return ['domain' => $domain, 'username' => $username, 'password' => $password];
    }

    /**
     * Reads one length-prefixed TS_INFO_PACKET string, advancing $p past the field and its
     * terminator. Returns null if the buffer is too short.
     */
    private static function readInfoField(string $info, int &$p, int $length, int $term, bool $unicode): ?string
    {
        if ($p + $length + $term > strlen($info)) {
            return null;
        }
        $raw = substr($info, $p, $length);
        $p += $length + $term;

        return $unicode ? self::decodeUtf16le($raw) : $raw;
    }

    /**
     * Parses an NTLMSSP AUTHENTICATE message (MS-NLMP 2.2.1.3) from anywhere inside $buf, returning
     * the crackable credential material. Returns null if no AUTHENTICATE message is present.
     *
     * @return array{username:string,domain:string,workstation:string,nt_response:string}|null
     */
    public static function parseNtlmAuthenticate(string $buf): ?array
    {
        $sig = "NTLMSSP\x00";
        $base = strpos($buf, $sig);
        if ($base === false) {
            return null;
        }
        $msg = substr($buf, $base);
        // Signature(8), MessageType(4 LE); type 3 = AUTHENTICATE.
        if (strlen($msg) < 52 || self::le32($msg, 8) !== 3) {
            return null;
        }

        $flags = self::le32($msg, 60);
        $unicode = (bool) ($flags & 0x00000001); // NTLMSSP_NEGOTIATE_UNICODE

        $ntResponse = self::ntlmField($msg, 20);
        $domain = self::ntlmField($msg, 28);
        $username = self::ntlmField($msg, 36);
        $workstation = self::ntlmField($msg, 44);

        return [
            'username' => $unicode ? self::decodeUtf16le($username) : $username,
            'domain' => $unicode ? self::decodeUtf16le($domain) : $domain,
            'workstation' => $unicode ? self::decodeUtf16le($workstation) : $workstation,
            'nt_response' => bin2hex($ntResponse),
        ];
    }

    /**
     * Reads an NTLMSSP payload field descriptor { Len(2), MaxLen(2), BufferOffset(4) } at $descOff
     * and returns the referenced bytes. Empty string if the descriptor points outside the message.
     */
    private static function ntlmField(string $msg, int $descOff): string
    {
        if ($descOff + 8 > strlen($msg)) {
            return '';
        }
        $len = self::le16($msg, $descOff);
        $offset = self::le32($msg, $descOff + 4);
        if ($len === 0 || $offset + $len > strlen($msg)) {
            return '';
        }

        return substr($msg, $offset, $len);
    }

    /**
     * MCS Connect Response (MS-RDPBCGR 2.2.1.4) advertising standard RDP Security with encryption
     * disabled and no virtual channels, so the client sends its Client Info PDU in the clear with no
     * preceding Security Exchange. The server data blocks are fixed size, which keeps every BER and
     * GCC length in this response a single byte.
     */
    private function buildMcsConnectResponse(): string
    {
        // Server data blocks (little-endian type/length headers).
        $scCore = "\x01\x0c\x08\x00" . pack('V', 0x00080004);            // TS_UD_SC_CORE, version RDP 5+
        $scNet = "\x03\x0c\x08\x00" . pack('v', self::MCS_IO_CHANNEL) . pack('v', 0); // TS_UD_SC_NET, 0 channels
        $scSecurity = "\x02\x0c\x0c\x00" . pack('V', 0) . pack('V', 0);  // TS_UD_SC_SECURITY, method/level NONE
        $serverData = $scCore . $scNet . $scSecurity;
        $sd = strlen($serverData);

        // GCC ConferenceCreateResponse (T.124). The two PER length bytes below are the length of the
        // ConferenceCreateResponse and of the server user data; both stay single-byte for our sizes.
        $gcc = "\x00\x05\x00\x14\x7c\x00\x01"
            . chr(14 + $sd)                                // connectPDU length
            . "\x14\x76\x0a\x01\x01\x00\x01\xc0\x00\x4d\x63\x44\x6e"
            . chr($sd)                                     // server user data length
            . $serverData;

        // Server MCS domain parameters (BER INTEGERs).
        $domainParams = self::berSequence(
            self::berInteger(34)     // maxChannelIds
            . self::berInteger(3)    // maxUserIds
            . self::berInteger(0)    // maxTokenIds
            . self::berInteger(1)    // numPriorities
            . self::berInteger(0)    // minThroughput
            . self::berInteger(1)    // maxHeight
            . self::berInteger(65535) // maxMCSPDUSize
            . self::berInteger(2)    // protocolVersion
        );

        $body = "\x0a\x01\x00"        // result = rt-successful
            . "\x02\x01\x00"          // calledConnectId = 0
            . $domainParams
            . self::berOctetString($gcc); // userData

        // Connect-Response ::= [APPLICATION 102] -> tag 0x7f 0x66.
        $cr = "\x7f\x66" . self::berLength(strlen($body)) . $body;

        return self::tpktX224Data($cr);
    }

    /**
     * MCS Attach User Confirm handing the client its user channel id (MS-RDPBCGR 2.2.1.7).
     */
    private function buildAttachUserConfirm(): string
    {
        // 0x2e = AttachUserConfirm with the initiator present; result(1)=0; initiator = channel - 1001.
        $mcs = "\x2e\x00" . pack('n', self::MCS_USER_CHANNEL - 1001);

        return self::tpktX224Data($mcs);
    }

    /**
     * MCS Channel Join Confirm echoing the requested channel back to the client (MS-RDPBCGR 2.2.1.8).
     */
    private function buildChannelJoinConfirm(string $initiator, string $channel): string
    {
        // 0x3e = ChannelJoinConfirm with the channel id present; result(1)=0; initiator; requested; joined.
        $mcs = "\x3e\x00" . $initiator . $channel . $channel;

        return self::tpktX224Data($mcs);
    }

    /**
     * Human-readable list of the security protocols named in a requestedProtocols bit field, for
     * fingerprinting the client tool.
     */
    public static function protocolNames(int $flags): string
    {
        if ($flags === 0) {
            return 'RDP';
        }
        $names = [];
        if ($flags & RdpConfig::PROTOCOL_SSL) {
            $names[] = 'SSL';
        }
        if ($flags & RdpConfig::PROTOCOL_HYBRID) {
            $names[] = 'HYBRID';
        }
        if ($flags & RdpConfig::PROTOCOL_RDSTLS) {
            $names[] = 'RDSTLS';
        }
        if ($flags & RdpConfig::PROTOCOL_HYBRID_EX) {
            $names[] = 'HYBRID_EX';
        }
        if ($names === []) {
            return sprintf('unknown(0x%08X)', $flags);
        }

        return implode(', ', $names);
    }

    private function logUnknown(RdpSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'rdp_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'RDP unmodelled input: ' . $detail,
        ]);
    }

    private static function tpkt(string $payload): string
    {
        // TPKT header: version(0x03), reserved(0x00), length(2 BE) counting the 4-byte header.
        return "\x03\x00" . pack('n', strlen($payload) + 4) . $payload;
    }

    private static function tpktX224Data(string $mcs): string
    {
        // X.224 Data TPDU header "02 f0 80" precedes every MCS PDU.
        return self::tpkt("\x02\xf0\x80" . $mcs);
    }

    private static function berLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        if ($len < 0x100) {
            return "\x81" . chr($len);
        }

        return "\x82" . chr($len >> 8) . chr($len & 0xFF);
    }

    private static function berInteger(int $n): string
    {
        // MCS treats these as unsigned, matching real servers (e.g. 65535 -> 02 02 ff ff).
        if ($n === 0) {
            $bytes = "\x00";
        } else {
            $bytes = '';
            while ($n > 0) {
                $bytes = chr($n & 0xFF) . $bytes;
                $n >>= 8;
            }
        }

        return "\x02" . chr(strlen($bytes)) . $bytes;
    }

    private static function berSequence(string $content): string
    {
        return "\x30" . self::berLength(strlen($content)) . $content;
    }

    private static function berOctetString(string $content): string
    {
        return "\x04" . self::berLength(strlen($content)) . $content;
    }

    private static function le16(string $b, int $off): int
    {
        return ord($b[$off]) | (ord($b[$off + 1]) << 8);
    }

    private static function le32(string $b, int $off): int
    {
        return ord($b[$off])
            | (ord($b[$off + 1]) << 8)
            | (ord($b[$off + 2]) << 16)
            | (ord($b[$off + 3]) << 24);
    }

    /**
     * Decodes UTF-16LE to UTF-8, falling back to a BMP-only decoder when mbstring is unavailable so
     * the engine keeps no hard extension dependency.
     */
    private static function decodeUtf16le(string $b): string
    {
        if (function_exists('mb_convert_encoding')) {
            return (string) @mb_convert_encoding($b, 'UTF-8', 'UTF-16LE');
        }

        $out = '';
        $len = strlen($b) - (strlen($b) % 2);
        for ($i = 0; $i < $len; $i += 2) {
            $cp = ord($b[$i]) | (ord($b[$i + 1]) << 8);
            if ($cp < 0x80) {
                $out .= chr($cp);
            } elseif ($cp < 0x800) {
                $out .= chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
            } else {
                $out .= chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
            }
        }

        return $out;
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'RDP';
        $entry['proto'] = 'rdp';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        ($this->logger)($entry);
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 3389;
    }
}

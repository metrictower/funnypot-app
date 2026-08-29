<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Smb;

/**
 * Zero-dependency, single-process TCP server for the low-interaction SMB honeypot (port 445).
 * Speaks just enough SMB2 / NTLMSSP in pure PHP to fingerprint scanners and harvest the NTLM
 * credentials they offer, using a non-blocking stream_select event loop.
 *
 * Deliberately inert: it serves no share, opens no file, and never grants a session. The exchange
 * runs NEGOTIATE -> SESSION_SETUP(CHALLENGE) -> capture the AUTHENTICATE -> deny, and stops there.
 *
 * Captured:
 * - the offered SMB2 dialects + client GUID (recon fingerprint of the scanner)
 * - the NTLMv2 material (username / domain / workstation + the crackable response) an authenticator sends
 * - legacy SMB1 negotiate probes (EternalBlue-style mass scanners still open with these)
 *
 * Frame: NetBIOS Session Service (4-byte header: type 0x00 + 24-bit big-endian length) wrapping
 * a little-endian SMB2 message.
 */
final class SmbServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick

    // Guards against a client that stops draining or a runaway declared frame length.
    private const INBUF_CAP = 262144;   // 256 KiB — SMB2 negotiate/session-setup frames are small
    private const MAX_FRAME = 131072;   // 128 KiB — a single NetBIOS frame we will assemble

    // SMB2 command codes (MS-SMB2 2.2.1).
    private const SMB2_NEGOTIATE = 0x0000;
    private const SMB2_SESSION_SETUP = 0x0001;

    // SMB2 header flag: response is server -> client.
    private const SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;

    // NT status codes used on the wire.
    private const STATUS_SUCCESS = 0x00000000;
    private const STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
    private const STATUS_LOGON_FAILURE = 0xC000006D;

    // SMB2 negotiate signing modes (MS-SMB2 2.2.4).
    private const SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001;
    private const SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002;

    // SMB2 dialect revisions (MS-SMB2 2.2.3). 0x0311 is intentionally never chosen: it mandates
    // negotiate contexts (preauth-integrity / encryption) in the response that add no honeypot value.
    private const DIALECT_PREFERENCE = [0x0302, 0x0300, 0x0210, 0x0202];
    private const DIALECT_FALLBACK = 0x0210;

    // GSS/SPNEGO + NTLMSSP object identifiers.
    private const OID_SPNEGO = '1.3.6.1.5.5.2';
    private const OID_NTLMSSP = '1.3.6.1.4.1.311.2.2.10';

    // SPNEGO negState (RFC 4178).
    private const SPNEGO_ACCEPT_INCOMPLETE = 1;

    private const NTLMSSP_SIGNATURE = "NTLMSSP\x00";

    // NTLM message types (MS-NLMP 2.2.1).
    private const NTLM_NEGOTIATE = 1;
    private const NTLM_CHALLENGE = 2;
    private const NTLM_AUTHENTICATE = 3;

    // NTLM negotiate flags advertised in our CHALLENGE (MS-NLMP 2.2.2.5). A believable server set:
    // unicode, request-target, NTLM, always-sign, target-type-domain, extended session security,
    // target-info, version, 128/56-bit.
    private const NTLM_CHALLENGE_FLAGS = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000
        | 0x00010000 | 0x00080000 | 0x00800000 | 0x02000000 | 0x20000000 | 0x80000000;

    private const NTLMSSP_NEGOTIATE_UNICODE = 0x00000001;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private SmbConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:445").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-smb: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-smb ({$this->config->domain}\\{$this->config->computerName}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:SmbSession,ip:string}> $conns */
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
                    // Deliver any queued denial/response best-effort before dropping the socket.
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
        $session = new SmbSession($ip, $clientPort, $id);
        // The client speaks first in SMB2, so nothing is queued on connect.

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "SMB connection from {$ip}:{$clientPort}",
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
     * Consumes every complete NetBIOS-framed message currently buffered and dispatches each one.
     * Incomplete trailing bytes are left in inbuf until the rest arrives.
     */
    public function processInbound(SmbSession $s): void
    {
        while (strlen($s->inbuf) >= 4) {
            // NetBIOS Session Service header: byte0 = message type, bytes1..3 = 24-bit length.
            $type = ord($s->inbuf[0]);
            $len = (ord($s->inbuf[1]) << 16) | (ord($s->inbuf[2]) << 8) | ord($s->inbuf[3]);

            if ($len > self::MAX_FRAME) {
                $this->logUnknown($s, sprintf('NetBIOS frame too large (%d bytes)', $len));

                return;
            }
            if (strlen($s->inbuf) < 4 + $len) {
                return; // wait for the full frame
            }

            $frame = substr($s->inbuf, 4, $len);
            $s->inbuf = substr($s->inbuf, 4 + $len);

            // Type 0x00 is a session message; anything else (session request, keep-alive) is unmodelled.
            if ($type !== 0x00) {
                $this->logUnknown($s, sprintf('NetBIOS message type 0x%02X', $type));

                return;
            }

            $this->dispatchFrame($s, $frame);
            if ($s->close) {
                return;
            }
        }
    }

    private function dispatchFrame(SmbSession $s, string $frame): void
    {
        // SMB1 legacy probe: header begins 0xFF 'S' 'M' 'B'. Log the recon value and close —
        // the legacy dialect is not modelled, only observed.
        if (strncmp($frame, "\xFFSMB", 4) === 0) {
            $this->logEvent([
                'event' => 'smb1_probe',
                'ip' => $s->ip,
                'port' => $s->port,
                'path' => 'SMB1 legacy negotiate probe (mass-scanner / EternalBlue-style)',
            ]);
            $s->close = true;

            return;
        }

        // SMB2 header begins 0xFE 'S' 'M' 'B' and is 64 bytes.
        if (strncmp($frame, "\xFESMB", 4) !== 0 || strlen($frame) < 64) {
            $this->logUnknown($s, 'non-SMB2 frame');

            return;
        }

        $command = self::u16le($frame, 12);
        $messageId = substr($frame, 24, 8);
        $body = substr($frame, 64);

        switch ($command) {
            case self::SMB2_NEGOTIATE:
                $this->handleNegotiate($s, $body, $messageId);
                break;

            case self::SMB2_SESSION_SETUP:
                $this->handleSessionSetup($s, $frame, $messageId);
                break;

            default:
                $this->logUnknown($s, sprintf('unmodelled SMB2 command 0x%04X', $command));
        }
    }

    /**
     * SMB2 NEGOTIATE: log the offered dialects + client GUID, then answer with a believable
     * NEGOTIATE response carrying an SPNEGO/NTLMSSP security blob.
     */
    private function handleNegotiate(SmbSession $s, string $body, string $messageId): void
    {
        // Negotiate request fixed part (MS-SMB2 2.2.3): DialectCount@2, ClientGuid@12, Dialects@36.
        if (strlen($body) < 36) {
            $this->logUnknown($s, 'truncated SMB2 NEGOTIATE');

            return;
        }

        $dialectCount = self::u16le($body, 2);
        $clientGuid = substr($body, 12, 16);

        $dialects = [];
        for ($i = 0; $i < $dialectCount; $i++) {
            $off = 36 + ($i * 2);
            if ($off + 2 > strlen($body)) {
                break;
            }
            $dialects[] = self::u16le($body, $off);
        }

        $this->logEvent([
            'event' => 'smb_negotiate',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'SMB2 NEGOTIATE dialects [%s] client-guid %s',
                implode(', ', array_map(static fn ($d) => sprintf('0x%04X', $d), $dialects)),
                self::formatGuid($clientGuid)
            ),
        ]);

        $dialect = $this->chooseDialect($dialects);
        $s->outbuf .= $this->buildNegotiateResponse($messageId, $dialect);
        $s->state = SmbSession::STATE_SESSION_SETUP;
    }

    /**
     * SMB2 SESSION_SETUP: branch on the NTLM message the client wrapped in SPNEGO.
     * A Type 1 (NEGOTIATE) is answered with our CHALLENGE; a Type 3 (AUTHENTICATE) is the payload
     * — its credentials are captured and the logon is then denied. No SPNEGO ASN.1 parse is needed:
     * the NTLMSSP signature is unambiguous, so the message is located by it.
     */
    private function handleSessionSetup(SmbSession $s, string $frame, string $messageId): void
    {
        $pos = strpos($frame, self::NTLMSSP_SIGNATURE);
        if ($pos === false) {
            // A SESSION_SETUP without NTLMSSP (raw Kerberos, or a mechanism we do not model).
            $this->logUnknown($s, 'SESSION_SETUP without NTLMSSP');

            return;
        }

        $ntlm = substr($frame, $pos);
        if (strlen($ntlm) < 12) {
            $this->logUnknown($s, 'truncated NTLMSSP message');

            return;
        }

        $msgType = self::u32le($ntlm, 8);

        if ($msgType === self::NTLM_NEGOTIATE) {
            // Reply MORE_PROCESSING_REQUIRED with an NTLMSSP CHALLENGE. The 8-byte server challenge
            // is the one place randomness is required: it must vary per session for the captured
            // NTLMv2 response to be a fresh, crackable value.
            $s->serverChallenge = random_bytes(8);
            $s->sessionId = random_bytes(8);
            $s->outbuf .= $this->buildChallengeResponse($messageId, $s);

            return;
        }

        if ($msgType === self::NTLM_AUTHENTICATE) {
            $this->captureAuthenticate($s, $ntlm);
            // Deny the logon — a session is never granted. The response is queued; the socket is
            // left for the idle reaper so a persistent scanner can retry (and be denied again).
            $s->outbuf .= $this->buildSessionDenied($messageId, $s);
            $s->denied = true;
            $s->state = SmbSession::STATE_DONE;

            return;
        }

        $this->logUnknown($s, sprintf('unexpected NTLM message type %d', $msgType));
    }

    /**
     * Parses an NTLMSSP AUTHENTICATE (MS-NLMP 2.2.1.3) and logs the harvested credential. The
     * NTLMv2 response is reassembled with our per-session challenge into the standard net-NTLMv2
     * form so the captured hash is directly crackable.
     */
    private function captureAuthenticate(SmbSession $s, string $ntlm): void
    {
        if (strlen($ntlm) < 64) {
            $this->logUnknown($s, 'truncated NTLMSSP AUTHENTICATE');

            return;
        }

        $ntResp = self::readField($ntlm, 24, 20); // NtChallengeResponse (Len@20, Offset@24)
        $domainRaw = self::readField($ntlm, 32, 28); // DomainName (Len@28, Offset@32)
        $userRaw = self::readField($ntlm, 40, 36); // UserName (Len@36, Offset@40)
        $wsRaw = self::readField($ntlm, 48, 44); // Workstation (Len@44, Offset@48)

        $flags = self::u32le($ntlm, 60);
        $unicode = ($flags & self::NTLMSSP_NEGOTIATE_UNICODE) !== 0;

        $domain = self::decodeString($domainRaw, $unicode);
        $user = self::decodeString($userRaw, $unicode);
        $workstation = self::decodeString($wsRaw, $unicode);

        $crackable = $this->netNtlmv2($user, $domain, $s->serverChallenge, $ntResp);

        $this->logEvent([
            'event' => 'smb_cred',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'high',
            'path' => sprintf(
                'SMB NTLMv2 captured: user=%s domain=%s workstation=%s',
                self::printable($user),
                self::printable($domain),
                self::printable($workstation)
            ),
            'user' => self::printable($user),
            'domain' => self::printable($domain),
            'workstation' => self::printable($workstation),
            'ntlmv2' => bin2hex($ntResp),
            'server_challenge' => bin2hex($s->serverChallenge),
            'body' => $crackable,
        ]);
    }

    /**
     * Picks the dialect to answer with: the highest offered value in preference order. 3.1.1 is
     * never chosen (it would require negotiate contexts in the response). If a client offers only
     * dialects we avoid, fall back to a widely accepted one.
     *
     * @param list<int> $offered
     */
    public function chooseDialect(array $offered): int
    {
        foreach (self::DIALECT_PREFERENCE as $pref) {
            if (in_array($pref, $offered, true)) {
                return $pref;
            }
        }

        return self::DIALECT_FALLBACK;
    }

    // ---- Response builders -------------------------------------------------------------------

    /**
     * SMB2 NEGOTIATE response (MS-SMB2 2.2.4) wrapping an SPNEGO NegTokenInit that advertises NTLM.
     */
    public function buildNegotiateResponse(string $messageId, int $dialect): string
    {
        $secBlob = self::spnegoNegTokenInit([self::OID_NTLMSSP]);

        $signing = self::SMB2_NEGOTIATE_SIGNING_ENABLED
            | ($this->config->signingRequired ? self::SMB2_NEGOTIATE_SIGNING_REQUIRED : 0);

        // Fixed body is 64 bytes; the security buffer follows the 64-byte SMB2 header + this body.
        $secBufOffset = 64 + 64;

        $body = pack('v', 65)              // StructureSize (1 counts the variable buffer)
            . pack('v', $signing)          // SecurityMode
            . pack('v', $dialect)          // DialectRevision
            . pack('v', 0)                 // NegotiateContextCount / Reserved
            . $this->config->serverGuid()  // ServerGuid (16)
            . pack('V', 0)                 // Capabilities
            . pack('V', 0x00100000)        // MaxTransactSize
            . pack('V', 0x00100000)        // MaxReadSize
            . pack('V', 0x00100000)        // MaxWriteSize
            . pack('P', self::nowFiletime()) // SystemTime
            . pack('P', 0)                 // ServerStartTime
            . pack('v', $secBufOffset)     // SecurityBufferOffset
            . pack('v', strlen($secBlob))  // SecurityBufferLength
            . pack('V', 0)                 // NegotiateContextOffset / Reserved2
            . $secBlob;

        $header = self::buildSmb2Header(self::SMB2_NEGOTIATE, self::STATUS_SUCCESS, $messageId, "\x00\x00\x00\x00\x00\x00\x00\x00");

        return self::wrapNbss($header . $body);
    }

    /**
     * SMB2 SESSION_SETUP response (MS-SMB2 2.2.6) with STATUS_MORE_PROCESSING_REQUIRED, carrying an
     * SPNEGO NegTokenResp that wraps the NTLMSSP CHALLENGE with our random 8-byte server challenge.
     */
    public function buildChallengeResponse(string $messageId, SmbSession $s): string
    {
        $challenge = $this->buildNtlmChallenge($s->serverChallenge);
        $secBlob = self::spnegoNegTokenResp(self::SPNEGO_ACCEPT_INCOMPLETE, self::OID_NTLMSSP, $challenge);

        $secBufOffset = 64 + 8; // 64-byte header + 8-byte fixed session-setup body

        $body = pack('v', 9)              // StructureSize
            . pack('v', 0)                // SessionFlags
            . pack('v', $secBufOffset)    // SecurityBufferOffset
            . pack('v', strlen($secBlob)) // SecurityBufferLength
            . $secBlob;

        $header = self::buildSmb2Header(self::SMB2_SESSION_SETUP, self::STATUS_MORE_PROCESSING_REQUIRED, $messageId, $s->sessionId);

        return self::wrapNbss($header . $body);
    }

    /**
     * SMB2 SESSION_SETUP response denying the logon (STATUS_LOGON_FAILURE), empty security buffer.
     */
    public function buildSessionDenied(string $messageId, SmbSession $s): string
    {
        $body = pack('v', 9)   // StructureSize
            . pack('v', 0)     // SessionFlags
            . pack('v', 64 + 8) // SecurityBufferOffset (kept valid though the buffer is empty)
            . pack('v', 0);    // SecurityBufferLength

        $header = self::buildSmb2Header(self::SMB2_SESSION_SETUP, self::STATUS_LOGON_FAILURE, $messageId, $s->sessionId);

        return self::wrapNbss($header . $body);
    }

    /**
     * Builds the 64-byte SMB2 sync header (MS-SMB2 2.2.1.2) for a server response. MessageId and
     * SessionId are copied verbatim so they echo the client's request.
     */
    public static function buildSmb2Header(int $command, int $status, string $messageId, string $sessionId): string
    {
        return "\xFESMB"                                 // ProtocolId
            . pack('v', 64)                              // StructureSize
            . pack('v', 0)                               // CreditCharge
            . pack('V', $status)                         // Status
            . pack('v', $command)                        // Command
            . pack('v', 1)                               // CreditResponse
            . pack('V', self::SMB2_FLAGS_SERVER_TO_REDIR) // Flags
            . pack('V', 0)                               // NextCommand
            . substr($messageId . "\x00\x00\x00\x00\x00\x00\x00\x00", 0, 8) // MessageId (8)
            . pack('V', 0)                               // Reserved
            . pack('V', 0)                               // TreeId
            . substr($sessionId . "\x00\x00\x00\x00\x00\x00\x00\x00", 0, 8) // SessionId (8)
            . str_repeat("\x00", 16);                    // Signature
    }

    /**
     * Prepends the 4-byte NetBIOS Session Service header (type 0x00 + 24-bit big-endian length).
     */
    public static function wrapNbss(string $payload): string
    {
        $len = strlen($payload);

        return chr(0x00) . chr(($len >> 16) & 0xFF) . chr(($len >> 8) & 0xFF) . chr($len & 0xFF) . $payload;
    }

    /**
     * Builds an NTLMSSP CHALLENGE message (MS-NLMP 2.2.1.2) advertising the box's domain / computer
     * names in the target-info AV pairs, carrying the given 8-byte server challenge.
     */
    public function buildNtlmChallenge(string $serverChallenge): string
    {
        $targetName = self::utf16le($this->config->domain);
        $targetInfo = self::targetInfo(
            $this->config->domain,
            $this->config->computerName,
            $this->config->dnsDomain,
            $this->config->dnsComputer
        );

        // Fixed part of the CHALLENGE is 56 bytes (with the Version field present).
        $targetNameOffset = 56;
        $targetInfoOffset = 56 + strlen($targetName);

        $version = pack('C', $this->config->osMajor)
            . pack('C', $this->config->osMinor)
            . pack('v', $this->config->osBuild)
            . "\x00\x00\x00"
            . pack('C', 0x0F); // NTLMRevision = NTLMSSP_REVISION_W2K3

        return self::NTLMSSP_SIGNATURE
            . pack('V', self::NTLM_CHALLENGE)
            . pack('v', strlen($targetName)) . pack('v', strlen($targetName)) . pack('V', $targetNameOffset)
            . pack('V', self::NTLM_CHALLENGE_FLAGS)
            . $serverChallenge                       // ServerChallenge (8)
            . str_repeat("\x00", 8)                  // Reserved
            . pack('v', strlen($targetInfo)) . pack('v', strlen($targetInfo)) . pack('V', $targetInfoOffset)
            . $version
            . $targetName
            . $targetInfo;
    }

    /**
     * Encodes the NTLM target-info AV-pair list (MS-NLMP 2.2.1) terminated by MsvAvEOL.
     */
    private static function targetInfo(string $nbDomain, string $nbComputer, string $dnsDomain, string $dnsComputer): string
    {
        $pair = static fn (int $id, string $value): string => pack('v', $id) . pack('v', strlen($value)) . $value;

        return $pair(0x0002, self::utf16le($nbDomain))    // MsvAvNbDomainName
            . $pair(0x0001, self::utf16le($nbComputer))    // MsvAvNbComputerName
            . $pair(0x0004, self::utf16le($dnsDomain))     // MsvAvDnsDomainName
            . $pair(0x0003, self::utf16le($dnsComputer))   // MsvAvDnsComputerName
            . $pair(0x0000, '');                           // MsvAvEOL
    }

    // ---- SPNEGO / DER ------------------------------------------------------------------------

    /**
     * GSS-API InitialContextToken wrapping an SPNEGO NegTokenInit whose mechTypes advertise the
     * given mechanism OIDs. This is the first token, sent inside the NEGOTIATE response.
     *
     * @param list<string> $mechOids
     */
    public static function spnegoNegTokenInit(array $mechOids): string
    {
        $mechList = '';
        foreach ($mechOids as $oid) {
            $mechList .= self::derOid($oid);
        }
        $mechTypes = self::derTlv(0xA0, self::derTlv(0x30, $mechList)); // [0] MechTypeList
        $negTokenInit = self::derTlv(0x30, $mechTypes);                 // NegTokenInit SEQUENCE
        $inner = self::derTlv(0xA0, $negTokenInit);                     // [0] negTokenInit

        return self::derTlv(0x60, self::derOid(self::OID_SPNEGO) . $inner); // [APPLICATION 0]
    }

    /**
     * SPNEGO NegTokenResp carrying a negState, the accepted mechanism OID, and a response token
     * (the NTLMSSP CHALLENGE). This is a subsequent token — bare, with no GSS-API/SPNEGO OID wrapper.
     */
    public static function spnegoNegTokenResp(int $negState, string $mechOid, string $responseToken): string
    {
        $stateElem = self::derTlv(0xA0, self::derTlv(0x0A, chr($negState)));   // [0] ENUMERATED negState
        $supportedMech = self::derTlv(0xA1, self::derOid($mechOid));           // [1] supportedMech
        $respTok = self::derTlv(0xA2, self::derTlv(0x04, $responseToken));     // [2] OCTET STRING

        return self::derTlv(0xA1, self::derTlv(0x30, $stateElem . $supportedMech . $respTok)); // [1] negTokenResp
    }

    private static function derTlv(int $tag, string $value): string
    {
        return chr($tag) . self::derLen(strlen($value)) . $value;
    }

    private static function derLen(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $bytes = '';
        while ($n > 0) {
            $bytes = chr($n & 0xFF) . $bytes;
            $n >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derOid(string $dotted): string
    {
        $parts = array_map('intval', explode('.', $dotted));
        $body = self::base128($parts[0] * 40 + ($parts[1] ?? 0));
        for ($i = 2; $i < count($parts); $i++) {
            $body .= self::base128($parts[$i]);
        }

        return self::derTlv(0x06, $body);
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

    // ---- Field / string helpers --------------------------------------------------------------

    /**
     * Reads a length-prefixed NTLM payload field. The 2-byte Len sits at $lenOffset and the 4-byte
     * buffer Offset (from the NTLM message start) at $offOffset. Out-of-range fields yield ''.
     */
    private static function readField(string $ntlm, int $offOffset, int $lenOffset): string
    {
        $len = self::u16le($ntlm, $lenOffset);
        $off = self::u32le($ntlm, $offOffset);
        if ($len === 0 || $off + $len > strlen($ntlm)) {
            return '';
        }

        return substr($ntlm, $off, $len);
    }

    private static function decodeString(string $raw, bool $unicode): string
    {
        if ($raw === '' || !$unicode) {
            return $raw;
        }
        if (function_exists('mb_convert_encoding')) {
            return (string) mb_convert_encoding($raw, 'UTF-8', 'UTF-16LE');
        }

        // Fallback for hosts without mbstring: drop the UTF-16LE high bytes (lossy above ASCII).
        return preg_replace('/\x00/', '', $raw) ?? '';
    }

    /**
     * Interleaves an ASCII string to UTF-16LE. Persona names are ASCII, so a null-interleave is
     * sufficient and keeps the emulator free of an mbstring dependency for its own output.
     */
    private static function utf16le(string $s): string
    {
        $out = '';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $out .= $s[$i] . "\x00";
        }

        return $out;
    }

    /**
     * Assembles the captured NTLMv2 response into hashcat/John net-NTLMv2 form:
     * user::domain:serverChallenge:NTProofStr:blob. Returns '' if the NT response is too short.
     */
    private function netNtlmv2(string $user, string $domain, string $serverChallenge, string $ntResp): string
    {
        if (strlen($ntResp) < 16) {
            return '';
        }
        $ntProof = substr($ntResp, 0, 16);
        $blob = substr($ntResp, 16);

        return sprintf(
            '%s::%s:%s:%s:%s',
            self::printable($user),
            self::printable($domain),
            bin2hex($serverChallenge),
            bin2hex($ntProof),
            bin2hex($blob)
        );
    }

    /**
     * Canonical 8-4-4-4-12 hex rendering of a 16-byte GUID in wire order, for a stable fingerprint.
     */
    private static function formatGuid(string $raw): string
    {
        if (strlen($raw) !== 16) {
            return bin2hex($raw);
        }
        $h = bin2hex($raw);

        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4)
            . '-' . substr($h, 16, 4) . '-' . substr($h, 20, 12);
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(string $s): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $s) ?? '';
    }

    private static function u16le(string $buf, int $offset): int
    {
        return unpack('v', substr($buf, $offset, 2))[1];
    }

    private static function u32le(string $buf, int $offset): int
    {
        return unpack('V', substr($buf, $offset, 4))[1];
    }

    /** Current time as a Windows FILETIME (100ns intervals since 1601-01-01). */
    private static function nowFiletime(): int
    {
        return (time() + 11644473600) * 10000000;
    }

    private function logUnknown(SmbSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'smb_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'SMB unmodelled input: ' . $detail,
        ]);
        $s->close = true;
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'SMB';
        $entry['proto'] = 'smb';
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
                'port' => 445,
                'path' => 'SMB internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 445;
    }
}

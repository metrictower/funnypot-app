<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ipmi;

use Funnypot\Protocol\UdpResponseBucket;

/**
 * Zero-dependency, single-process UDP server for the low-interaction IPMI/BMC honeypot (port 623,
 * RMCP). Speaks just enough of the IPMI wire format (RMCP envelope + IPMI 1.5 session header + IPMI
 * 2.0 RMCP+/RAKP) in pure PHP to fingerprint BMC scanners and harvest the credential material they
 * spray, on a non-blocking stream_select loop over one UDP socket.
 *
 * Deliberately inert: it exposes no real management data, never authenticates, and never grants a
 * session. Get Channel Authentication Capabilities is answered with a believable BMC persona
 * advertising its auth types; the RMCP+ Open Session / RAKP handshake and the IPMI 1.5 Get Session
 * Challenge / Activate Session flow are captured for intel and refused — a RAKP Message 3 draws an
 * integrity-check failure, never a RAKP Message 4 success.
 *
 * Captured intel:
 * - Get Channel Auth Cap probes (a BMC-discovery / fingerprint scan).
 * - IPMI 2.0 RAKP Message 1 usernames. RAKP is the known hash-disclosure vector (CVE-2013-4786): the
 *   attacker's username is captured before any authentication, exactly the material a real BMC would
 *   later leak a crackable HMAC for. We never derive or emit a real HMAC — capture is the value.
 * - IPMI 1.5 Get Session Challenge usernames and Activate Session attempts.
 *
 * IPMI/RMCP over UDP is a reflection/amplification surface, so two hard anti-amplification guards
 * apply to every reply:
 * 1. No emitted datagram is ever larger than the request that triggered it (amplification factor
 *    <= 1). A believable reply that would exceed the request is dropped, so the honeypot can never be
 *    turned into an amplifier. (Auth-cap and RAKP replies are naturally larger than a minimal probe,
 *    so for a minimal probe the reply is dropped and only the intel is kept — the same trade the
 *    BACnet I-Am makes; the harvested username never depends on a reply going out.)
 * 2. Replies are metered per source IP with a token bucket — a spoofed request forges its source as a
 *    victim, so every reply we emit lands on that victim.
 */
final class IpmiServer
{
    use UdpResponseBucket;

    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const READ_CHUNK = 65535;        // a single UDP datagram
    private const INBUF_CAP = 65535;         // guard: an IPMI/RMCP message never legitimately exceeds this
    private const MAX_DGRAMS_PER_TICK = 64;  // bound the drain so a flood can't spin one tick forever

    private const DEFAULT_PORT = 623;

    // RMCP header (RFC / IPMI 2.0).
    private const RMCP_VERSION = 0x06;
    private const RMCP_SEQ_IPMI = 0xFF;   // IPMI messages are not RMCP-ACKed, so the sequence is 0xFF
    private const RMCP_CLASS_ASF = 0x06;  // ASF (presence ping) — RMCP but not IPMI
    private const RMCP_CLASS_IPMI = 0x07;

    // IPMI session auth-type / payload-format byte.
    private const AUTH_NONE = 0x00;
    private const AUTH_RMCPPLUS = 0x06; // IPMI 2.0 (RMCP+) session format

    // IPMI LAN message addresses.
    private const BMC_ADDR = 0x20;            // responder: the BMC
    private const REMOTE_CONSOLE_ADDR = 0x81; // requester: the remote console

    // IPMI network functions (App).
    private const NETFN_APP_REQUEST = 0x06;
    private const NETFN_APP_RESPONSE = 0x07;

    // IPMI App commands.
    private const CMD_GET_CHANNEL_AUTH_CAP = 0x38;
    private const CMD_GET_SESSION_CHALLENGE = 0x39;
    private const CMD_ACTIVATE_SESSION = 0x3A;
    private const CMD_SET_SESSION_PRIV = 0x3B;

    // RMCP+ payload types (low 6 bits of the payload-type byte).
    private const PT_IPMI = 0x00;
    private const PT_OEM_EXPLICIT = 0x02;
    private const PT_OPEN_SESSION_REQ = 0x10;
    private const PT_OPEN_SESSION_RESP = 0x11;
    private const PT_RAKP1 = 0x12;
    private const PT_RAKP2 = 0x13;
    private const PT_RAKP3 = 0x14;
    private const PT_RAKP4 = 0x15;

    // RMCP+ / RAKP status codes.
    private const RMCPP_STATUS_OK = 0x00;
    private const RMCPP_STATUS_INVALID_INTEGRITY = 0x0F;

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
        private IpmiConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:623").
     */
    public function run(string $bind): void
    {
        $sock = @stream_socket_server("udp://{$bind}", $errno, $errstr, STREAM_SERVER_BIND);
        if ($sock === false) {
            fwrite(STDERR, "funnypot-ipmi: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($sock, false);
        fwrite(STDERR, "funnypot-ipmi (BMC) listening on {$bind} (UDP)\n");

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
                $session = new IpmiSession($ip, $clientPort, ++$id);
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
    public function processInbound(IpmiSession $s): void
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

        if (strlen($data) < 4 || ord($data[0]) !== self::RMCP_VERSION) {
            $this->logUnknown($s, 'not an RMCP message (bad version)');

            return;
        }

        $class = ord($data[3]) & 0x1F;
        if ($class !== self::RMCP_CLASS_IPMI) {
            // ASF presence pings and other RMCP classes are recon but not IPMI: capture, never reply
            // (a bare reply would be another reflection primitive).
            $detail = $class === self::RMCP_CLASS_ASF
                ? 'ASF RMCP message (presence ping), not IPMI'
                : sprintf('RMCP class 0x%02X (not IPMI)', $class);
            $this->logUnknown($s, $detail);

            return;
        }

        if (strlen($data) < 5) {
            $this->logUnknown($s, 'truncated IPMI session header');

            return;
        }

        $s->authType = ord($data[4]);
        if ($s->authType === self::AUTH_RMCPPLUS) {
            $this->handleRmcpPlus($s, $data);

            return;
        }

        $this->handleIpmi15($s, $data);
    }

    // ---- IPMI 1.5 (legacy session format) -----------------------------------------------------

    private function handleIpmi15(IpmiSession $s, string $data): void
    {
        $req = self::parseIpmi15($data);
        if ($req === null) {
            $this->logUnknown($s, 'unparseable IPMI 1.5 message');

            return;
        }
        $s->netFn = $req['netFn'];
        $s->cmd = $req['cmd'];

        if ($req['netFn'] !== self::NETFN_APP_REQUEST) {
            $this->logUnknown($s, sprintf('IPMI 1.5 netFn 0x%02X cmd 0x%02X', $req['netFn'], $req['cmd']));

            return;
        }

        switch ($req['cmd']) {
            case self::CMD_GET_CHANNEL_AUTH_CAP:
                $this->handleGetChannelAuthCap($s, $req);

                return;

            case self::CMD_GET_SESSION_CHALLENGE:
                $gsc = self::parseGetSessionChallenge($req['data']);
                $s->username = $gsc['username'];
                $this->logAuthAttempt(
                    $s,
                    sprintf('IPMI 1.5 Get Session Challenge username=%s', self::printable($gsc['username'])),
                    'high',
                    $gsc['username']
                );
                // A believable challenge reply, capped (dropped when it would amplify). Random, inert.
                $resp = self::buildGetSessionChallengeResponse($req['rqSeqLun'], random_bytes(4), random_bytes(16));
                $s->outbuf = $this->capReply($s, $resp, '');

                return;

            case self::CMD_ACTIVATE_SESSION:
                // INERT: a session is never activated. Capture the attempt; send no reply.
                $this->logAuthAttempt($s, 'IPMI 1.5 Activate Session attempt', 'medium');

                return;

            case self::CMD_SET_SESSION_PRIV:
                $this->logAuthAttempt($s, 'IPMI 1.5 Set Session Privilege attempt', 'medium');

                return;

            default:
                $this->logUnknown($s, sprintf('IPMI 1.5 App command 0x%02X', $req['cmd']));
        }
    }

    /**
     * Get Channel Authentication Capabilities: the BMC-discovery probe. Capture it, then answer with
     * the believable persona advertising which auth types the BMC supports.
     *
     * @param array{netFn:int,cmd:int,rqSeqLun:int,data:string,authType:int} $req
     */
    private function handleGetChannelAuthCap(IpmiSession $s, array $req): void
    {
        $channel = strlen($req['data']) >= 1 ? ord($req['data'][0]) & 0x0F : 0;
        $priv = strlen($req['data']) >= 2 ? ord($req['data'][1]) & 0x0F : 0;

        $this->logEvent([
            'event' => 'ipmi_auth_caps',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'low',
            'path' => sprintf(
                'IPMI Get Channel Authentication Capabilities (channel=%d priv=%s)',
                $channel,
                self::privName($priv)
            ),
        ]);

        $resp = self::buildGetChannelAuthCapResponse($this->config, $req['rqSeqLun']);
        $s->outbuf = $this->capReply($s, $resp, '');
    }

    // ---- IPMI 2.0 (RMCP+ / RAKP) --------------------------------------------------------------

    private function handleRmcpPlus(IpmiSession $s, string $data): void
    {
        $req = self::parseRmcpPlus($data);
        if ($req === null) {
            $this->logUnknown($s, 'unparseable RMCP+ payload (or OEM-explicit, not modelled)');

            return;
        }
        $s->payloadType = $req['payloadType'];

        switch ($req['payloadType']) {
            case self::PT_OPEN_SESSION_REQ:
                $this->handleOpenSession($s, $req['payload']);

                return;

            case self::PT_RAKP1:
                $this->handleRakp1($s, $req['payload']);

                return;

            case self::PT_RAKP3:
                $this->handleRakp3($s, $req['payload']);

                return;

            case self::PT_IPMI:
                // An in-session IPMI message with no session ever established: never execute it.
                $this->logUnknown($s, 'RMCP+ in-session IPMI message without a session');

                return;

            default:
                $this->logUnknown($s, sprintf('RMCP+ payload type 0x%02X', $req['payloadType']));
        }
    }

    /**
     * RMCP+ Open Session Request: the first step of the IPMI 2.0 handshake. Capture the requested
     * privilege + console session id, then answer with an Open Session Response so a scanner proceeds
     * to RAKP Message 1 (which carries the username we are after). Never a real session.
     */
    private function handleOpenSession(IpmiSession $s, string $payload): void
    {
        $os = self::parseOpenSessionRequest($payload);
        if ($os === null) {
            $this->logUnknown($s, 'malformed RMCP+ Open Session Request');

            return;
        }

        $this->logAuthAttempt(
            $s,
            sprintf(
                'IPMI 2.0 Open Session Request (priv=%s console_sid=%s)',
                self::privName($os['maxPriv']),
                bin2hex($os['consoleSessionId'])
            ),
            'medium'
        );

        // A managed-system session id the scanner would echo back in RAKP; random and inert — no
        // session state is kept, so it is never honoured.
        $resp = self::buildOpenSessionResponse(
            $os['tag'],
            self::RMCPP_STATUS_OK,
            $this->config->maxPrivilege,
            $os['consoleSessionId'],
            random_bytes(4)
        );
        $s->outbuf = $this->capReply($s, $resp, '');
    }

    /**
     * RAKP Message 1: the hash-disclosure step. It carries the username the attacker is probing — the
     * whole point of the emulator. Capture it (before any authentication, exactly as the real vector
     * exposes it), then answer with a plausible RAKP Message 2 whose HMAC is random noise derived from
     * no credential, so an offline crack can never succeed.
     */
    private function handleRakp1(IpmiSession $s, string $payload): void
    {
        $r = self::parseRakp1($payload);
        if ($r === null) {
            $this->logUnknown($s, 'malformed RAKP Message 1');

            return;
        }
        $s->username = $r['username'];

        $this->logAuthAttempt(
            $s,
            sprintf(
                'IPMI 2.0 RAKP Message 1 username=%s priv=%s',
                self::printable($r['username']),
                self::privName($r['priv'])
            ),
            'high',
            $r['username']
        );

        // The console session id belongs to the earlier Open Session Request; this stateless capture
        // does not correlate datagrams, so it is left zero. The reply is best-effort — usually dropped
        // by the anti-amplification cap — and never leaks anything credential-derived.
        $resp = self::buildRakp2(
            $r['tag'],
            self::RMCPP_STATUS_OK,
            "\x00\x00\x00\x00",
            random_bytes(16),
            $this->config->guid,
            random_bytes(20)
        );
        $s->outbuf = $this->capReply($s, $resp, '');
    }

    /**
     * RAKP Message 3: the attacker completing authentication. INERT — a session is never granted, so
     * this always draws a RAKP Message 4 reporting an integrity-check failure (which is also the
     * honest outcome, since RAKP Message 2's key material was random noise).
     */
    private function handleRakp3(IpmiSession $s, string $payload): void
    {
        $r = self::parseRakp3($payload);
        if ($r === null) {
            $this->logUnknown($s, 'malformed RAKP Message 3');

            return;
        }

        $this->logAuthAttempt($s, 'IPMI 2.0 RAKP Message 3 attempt', 'medium');

        $resp = self::buildRakp4($r['tag'], self::RMCPP_STATUS_INVALID_INTEGRITY, "\x00\x00\x00\x00");
        $s->outbuf = $this->capReply($s, $resp, '');
    }

    // ---- Parsing (pure, test-callable) --------------------------------------------------------

    /**
     * Parses an IPMI 1.5 RMCP datagram down to its IPMI LAN message fields. Returns null on any
     * malformed structure so the caller can log it as an unknown probe rather than faulting.
     *
     * @return array{authType:int,netFn:int,cmd:int,rqSeqLun:int,data:string}|null
     */
    public static function parseIpmi15(string $data): ?array
    {
        // RMCP(4) + session header: authType(1) + seq(4) + sessionId(4) + [authCode(16)] + payloadLen(1).
        if (strlen($data) < 14) {
            return null;
        }
        $authType = ord($data[4]);
        $off = 13; // 4 (RMCP) + 1 (authType) + 4 (seq) + 4 (sessionId)
        if ($authType !== self::AUTH_NONE) {
            $off += 16; // an auth code is present for any non-none auth type
        }
        if ($off >= strlen($data)) {
            return null;
        }
        $msgLen = ord($data[$off]);
        $off += 1;
        $msg = substr($data, $off, $msgLen);
        // IPMI LAN message: rsAddr(1) netFn/LUN(1) chk1(1) rqAddr(1) rqSeq/LUN(1) cmd(1) [data] chk2(1).
        if (strlen($msg) < 7) {
            return null;
        }

        $netFn = (ord($msg[1]) >> 2) & 0x3F;
        $rqSeqLun = ord($msg[4]);
        $cmd = ord($msg[5]);
        $mdata = substr($msg, 6, strlen($msg) - 7); // strip the trailing checksum

        return ['authType' => $authType, 'netFn' => $netFn, 'cmd' => $cmd, 'rqSeqLun' => $rqSeqLun, 'data' => $mdata];
    }

    /**
     * The auth-type byte + username from a Get Session Challenge request's data field. Lenient: a
     * short field simply yields an empty username.
     *
     * @return array{authType:int,username:string}
     */
    public static function parseGetSessionChallenge(string $mdata): array
    {
        $authType = strlen($mdata) >= 1 ? ord($mdata[0]) : 0;
        $username = strlen($mdata) > 1 ? substr($mdata, 1, 16) : '';

        return ['authType' => $authType, 'username' => rtrim($username, "\x00")];
    }

    /**
     * Parses the RMCP+ (IPMI 2.0) session header. Returns the payload type, session id, sequence and
     * the payload bytes, or null when the envelope is malformed or an OEM-explicit payload (not
     * modelled).
     *
     * @return array{payloadType:int,sessionId:string,seq:string,payload:string}|null
     */
    public static function parseRmcpPlus(string $data): ?array
    {
        // RMCP(4) + authType(1) + payloadType(1) + sessionId(4) + seq(4) + payloadLen(2 LE) + payload.
        if (strlen($data) < 16) {
            return null;
        }
        $payloadType = ord($data[5]) & 0x3F;
        if ($payloadType === self::PT_OEM_EXPLICIT) {
            return null; // OEM payloads carry an extra IANA/id block we do not model
        }
        $sessionId = substr($data, 6, 4);
        $seq = substr($data, 10, 4);
        $plen = ord($data[14]) | (ord($data[15]) << 8);
        $payload = substr($data, 16, $plen);

        return ['payloadType' => $payloadType, 'sessionId' => $sessionId, 'seq' => $seq, 'payload' => $payload];
    }

    /**
     * Parses an RMCP+ Open Session Request payload.
     *
     * @return array{tag:int,maxPriv:int,consoleSessionId:string}|null
     */
    public static function parseOpenSessionRequest(string $p): ?array
    {
        // tag(1) + maxPriv(1) + reserved(2) + remoteConsoleSessionId(4) + auth/integ/conf payloads.
        if (strlen($p) < 8) {
            return null;
        }

        return ['tag' => ord($p[0]), 'maxPriv' => ord($p[1]) & 0x0F, 'consoleSessionId' => substr($p, 4, 4)];
    }

    /**
     * Parses a RAKP Message 1 payload, extracting the username — the credential intel.
     *
     * @return array{tag:int,bmcSessionId:string,consoleRandom:string,priv:int,nameOnlyLookup:bool,username:string}|null
     */
    public static function parseRakp1(string $p): ?array
    {
        // tag(1) reserved(3) managedSystemSessionId(4) consoleRandom(16) privLevel(1) reserved(2)
        // usernameLength(1) username(N).
        if (strlen($p) < 28) {
            return null;
        }
        $privByte = ord($p[24]);
        $nameLen = ord($p[27]);
        if (28 + $nameLen > strlen($p)) {
            $nameLen = max(0, strlen($p) - 28); // lenient: take whatever username bytes are present
        }

        return [
            'tag' => ord($p[0]),
            'bmcSessionId' => substr($p, 4, 4),
            'consoleRandom' => substr($p, 8, 16),
            'priv' => $privByte & 0x0F,
            'nameOnlyLookup' => ($privByte & 0x10) !== 0,
            'username' => substr($p, 28, $nameLen),
        ];
    }

    /**
     * Parses a RAKP Message 3 payload.
     *
     * @return array{tag:int,status:int,mgmtSessionId:string,authCode:string}|null
     */
    public static function parseRakp3(string $p): ?array
    {
        // tag(1) status(1) reserved(2) managedSystemSessionId(4) keyExchangeAuthCode(N).
        if (strlen($p) < 8) {
            return null;
        }

        return ['tag' => ord($p[0]), 'status' => ord($p[1]), 'mgmtSessionId' => substr($p, 4, 4), 'authCode' => substr($p, 8)];
    }

    // ---- Response building (pure, test-callable) ----------------------------------------------

    /**
     * The believable Get Channel Authentication Capabilities response: completion code plus the fixed
     * persona (channel, supported auth types, status, extended-capabilities, OEM). This is the
     * uncapped, believable response; the anti-amplification cap is applied by the caller.
     */
    public static function buildGetChannelAuthCapResponse(IpmiConfig $c, int $rqSeqLun): string
    {
        $data = chr(0x00)                       // completion code: success
            . chr($c->channel & 0x0F)           // channel number
            . chr($c->authTypeSupport & 0xFF)   // auth type support bit field
            . chr($c->statusByte & 0xFF)        // per-message / user-level / login status
            . chr($c->extCapabilities & 0xFF)   // IPMI v1.5 / v2.0 support
            . chr($c->oemId & 0xFF)             // OEM IANA id, LS byte first
            . chr(($c->oemId >> 8) & 0xFF)
            . chr(($c->oemId >> 16) & 0xFF)
            . chr($c->oemAux & 0xFF);           // OEM auxiliary data

        return self::wrapIpmi15(self::ipmiLanMessage(self::NETFN_APP_RESPONSE, $rqSeqLun, self::CMD_GET_CHANNEL_AUTH_CAP, $data));
    }

    /** A believable Get Session Challenge response: completion + temporary session id + challenge. */
    public static function buildGetSessionChallengeResponse(int $rqSeqLun, string $tempSessionId4, string $challenge16): string
    {
        $data = chr(0x00) . substr($tempSessionId4 . "\x00\x00\x00\x00", 0, 4) . substr($challenge16 . str_repeat("\x00", 16), 0, 16);

        return self::wrapIpmi15(self::ipmiLanMessage(self::NETFN_APP_RESPONSE, $rqSeqLun, self::CMD_GET_SESSION_CHALLENGE, $data));
    }

    /** An RMCP+ Open Session Response advertising fixed RAKP-HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128. */
    public static function buildOpenSessionResponse(int $tag, int $status, int $maxPriv, string $consoleSessionId4, string $mgmtSessionId4): string
    {
        // Payload records: type(1) reserved(2) length(1)=8 algorithm(1) reserved(3).
        $auth = "\x00\x00\x00\x08\x01\x00\x00\x00";  // authentication: RAKP-HMAC-SHA1
        $integ = "\x01\x00\x00\x08\x01\x00\x00\x00"; // integrity: HMAC-SHA1-96
        $conf = "\x02\x00\x00\x08\x01\x00\x00\x00";  // confidentiality: AES-CBC-128

        $payload = chr($tag) . chr($status) . chr($maxPriv & 0x0F) . "\x00"
            . substr($consoleSessionId4 . "\x00\x00\x00\x00", 0, 4)
            . substr($mgmtSessionId4 . "\x00\x00\x00\x00", 0, 4)
            . $auth . $integ . $conf;

        return self::wrapRmcpPlus(self::PT_OPEN_SESSION_RESP, $payload);
    }

    /**
     * A RAKP Message 2. On success it carries the managed-system random + GUID + key-exchange auth
     * code; on any error status only the echoed console session id (per the spec's short form).
     */
    public static function buildRakp2(int $tag, int $status, string $consoleSessionId4, string $bmcRandom16, string $bmcGuid16, string $authCode): string
    {
        $head = chr($tag) . chr($status) . "\x00\x00" . substr($consoleSessionId4 . "\x00\x00\x00\x00", 0, 4);
        $payload = $status === self::RMCPP_STATUS_OK
            ? $head . substr($bmcRandom16 . str_repeat("\x00", 16), 0, 16) . substr($bmcGuid16 . str_repeat("\x00", 16), 0, 16) . $authCode
            : $head;

        return self::wrapRmcpPlus(self::PT_RAKP2, $payload);
    }

    /** A RAKP Message 4 — used only to report a failure, since a session is never granted. */
    public static function buildRakp4(int $tag, int $status, string $consoleSessionId4, string $integrityCheck = ''): string
    {
        $payload = chr($tag) . chr($status) . "\x00\x00" . substr($consoleSessionId4 . "\x00\x00\x00\x00", 0, 4) . $integrityCheck;

        return self::wrapRmcpPlus(self::PT_RAKP4, $payload);
    }

    /**
     * Builds an IPMI LAN response message: requester/responder addressing, both 2's-complement
     * checksums, and the response network function. $completionAndData is the completion code followed
     * by any response data.
     */
    public static function ipmiLanMessage(int $responderNetFn, int $rqSeqLun, int $cmd, string $completionAndData): string
    {
        $head = chr(self::REMOTE_CONSOLE_ADDR) . chr(($responderNetFn << 2) & 0xFF); // rqAddr, netFn/LUN
        $chk1 = self::csum($head);
        $tail = chr(self::BMC_ADDR) . chr($rqSeqLun & 0xFF) . chr($cmd & 0xFF) . $completionAndData;
        $chk2 = self::csum($tail);

        return $head . $chk1 . $tail . $chk2;
    }

    /** Wraps an IPMI LAN message in an IPMI 1.5 session header (auth none) and an RMCP/IPMI header. */
    public static function wrapIpmi15(string $msg): string
    {
        return chr(self::RMCP_VERSION) . "\x00" . chr(self::RMCP_SEQ_IPMI) . chr(self::RMCP_CLASS_IPMI)
            . chr(self::AUTH_NONE) . "\x00\x00\x00\x00" . "\x00\x00\x00\x00" . chr(strlen($msg) & 0xFF) . $msg;
    }

    /** Wraps a payload in an RMCP+ (IPMI 2.0) session header and an RMCP/IPMI header. */
    public static function wrapRmcpPlus(int $payloadType, string $payload): string
    {
        return chr(self::RMCP_VERSION) . "\x00" . chr(self::RMCP_SEQ_IPMI) . chr(self::RMCP_CLASS_IPMI)
            . chr(self::AUTH_RMCPPLUS) . chr($payloadType & 0x3F) . "\x00\x00\x00\x00" . "\x00\x00\x00\x00"
            . pack('v', strlen($payload)) . $payload;
    }

    /** IPMI 2's-complement checksum: the sum of the bytes plus the checksum is zero mod 256. */
    private static function csum(string $bytes): string
    {
        $sum = 0;
        $len = strlen($bytes);
        for ($i = 0; $i < $len; $i++) {
            $sum += ord($bytes[$i]);
        }

        return chr((0x100 - ($sum & 0xFF)) & 0xFF);
    }

    /**
     * ANTI-AMPLIFICATION cap for a reply. Returns $primary when it is no larger than the request, else
     * $fallback when that fits, else '' — so the reflection factor is always <= 1.
     */
    private function capReply(IpmiSession $s, string $primary, string $fallback): string
    {
        if ($primary !== '' && strlen($primary) <= $s->requestLength) {
            return $primary;
        }
        if ($fallback !== '' && strlen($fallback) <= $s->requestLength) {
            return $fallback;
        }

        return '';
    }

    // ---- Anti-reflection throttle -------------------------------------------------------------
    // udpResponseAllowed() lives in the shared UdpResponseBucket trait (`use` above).

    // ---- Logging ------------------------------------------------------------------------------

    /**
     * Records a captured authentication / credential-harvest attempt (RAKP or the IPMI 1.5 session
     * flow) under the ipmi_rakp event. A username, when present, is included as searchable intel.
     */
    private function logAuthAttempt(IpmiSession $s, string $detail, string $severity, ?string $username = null): void
    {
        $entry = [
            'event' => 'ipmi_rakp',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => $severity,
            'path' => $detail,
        ];
        if ($username !== null) {
            $entry['username'] = self::printable($username);
        }

        $this->logEvent($entry);
    }

    private function logUnknown(IpmiSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'ipmi_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'IPMI unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'IPMI';
        $entry['proto'] = 'ipmi';
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
                'path' => 'IPMI internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    // ---- Naming / sanitising helpers ----------------------------------------------------------

    private static function privName(int $priv): string
    {
        return match ($priv) {
            1 => 'CALLBACK',
            2 => 'USER',
            3 => 'OPERATOR',
            4 => 'ADMINISTRATOR',
            5 => 'OEM',
            default => sprintf('priv-%d', $priv),
        };
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

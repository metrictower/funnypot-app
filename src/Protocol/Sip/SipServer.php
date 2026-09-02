<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

use Funnypot\App\ThreatIntel\OperatorBlocklist;

/**
 * Pure-PHP SIP and RTP VoIP honeypot service (RFC 3261 & RFC 3550).
 * Emulates an Asterisk PBX 20 server with anti-reflection (B1) and anti-spoofing (B2) guards.
 */
final class SipServer
{
    /** @var resource|null UDP socket */
    private $udpSocket = null;

    /** @var resource|null TCP listen socket */
    private $tcpSocket = null;

    /** @var array<int, resource> TCP client socket resource id => resource */
    private array $tcpClients = [];

    /** @var array<int, string> TCP client socket resource id => inbuf */
    private array $tcpBuffers = [];

    /** @var array<int, float> TCP client socket resource id => last activity time (idle-close). */
    private array $tcpLastActivity = [];

    /**
     * TCP client socket resource id => accept-time peer address ("ip:port"). Captured at accept
     * because a later stream_socket_get_name() on a non-blocking accepted socket is unreliable and
     * can resolve to nothing — the source IP must come from accept, never a fabricated fallback.
     * @var array<int, string>
     */
    private array $tcpPeers = [];

    /** Ceilings that stop a TCP flood / slowloris from exhausting fds or memory. */
    private const MAX_TCP_CLIENTS = 128;
    private const MAX_TCP_BUFFER = 16384;
    private const TCP_IDLE_TIMEOUT = 30.0;
    // RFC 3261 Timer B/H: give up on an INVITE that is never ACKed. Without this a scan INVITE
    // (no ACK, so never "streaming") sits in the table until the max-duration cap and quickly fills
    // maxActiveCalls — turning every later caller away with 486 Busy.
    private const INVITE_SETUP_TIMEOUT = 32.0;
    // Randomized ring before answering. A constant answer time is a dead giveaway, so each call rings
    // a different length; the window spans several ring-cadence cycles, so the caller's phone (which
    // renders local ringback from our 180 Ringing) is heard as ring / silence / ring a random number
    // of times before we pick up. Kept well under INVITE_SETUP_TIMEOUT so a real caller is not reaped.
    private const RING_MIN_MS = 4000;
    private const RING_MAX_MS = 12000;

    /** @var array<string, SipSession> Active sessions keyed by callId + peerAddr */
    private array $sessions = [];

    /**
     * Nonce store: nonce => ['ip' => issuing peer IP, 'ts' => issued unix time]. The issuing IP binds
     * each UDP nonce to the address it was challenged to (FP-0247 anti-spoof): a nonce harvested from a
     * real 401 must not validate a spoofed REGISTER replayed from a different (victim) source. Nonces
     * are one-shot (consumed on first response) and expire after 300s.
     *
     * @var array<string, array{ip: string, ts: int}>
     */
    private array $activeNonces = [];

    /**
     * Per-source-IP token bucket throttling UDP responses (F4). A spoofed request forges its source
     * as a victim, so every UDP reply we emit lands on that victim — capping replies per apparent
     * source bounds how hard the honeypot can be turned into a reflector. TCP is return-routable, so
     * only UDP is metered.
     * @var array<string, array{tokens: float, last: float}>
     */
    private array $udpResponseBuckets = [];
    private const UDP_RESP_BURST = 20.0;   // bucket capacity
    private const UDP_RESP_RATE = 10.0;    // tokens refilled per second
    private const UDP_BUCKET_MAX_IPS = 4096; // cap tracked IPs so the map can't grow unbounded

    /**
     * Per-apparent-source call-admission throttle. F4 (above) meters the RESPONSE bytes we emit; this
     * meters the REQUESTS we even process. A sustained INVITE/REGISTER/OPTIONS flood from one source
     * drains its bucket, after which the request is dropped before a session is built, a byte is sent,
     * or a per-call row is written — the flood then costs one parse and a bucket check. Capacity +
     * refill come from SipConfig (callBurst / callRatePerSec); disabled when callBurst <= 0.
     * @var array<string, array{tokens: float, last: float}>
     */
    private array $callBuckets = [];

    /**
     * Rollup state for suppressed (dropped) flood requests, per apparent source: the running count, the
     * time of the first drop in the current burst, and when we last emitted a rollup event — so a flood
     * of thousands becomes ~one 'call_flood' row per minute instead of one row per call.
     * @var array<string, array{count: int, since: string, lastLog: float, method: string, lastLoggedCount: int}>
     */
    private array $floodState = [];
    private const FLOOD_ROLLUP_SECS = 60.0; // emit at most one flood rollup per source per this window
    private const CALL_BUCKET_MAX_IPS = 4096; // cap tracked sources (all maps) so they can't grow unbounded

    /**
     * Cumulative per-source call ceiling (distinct from the per-second rate bucket): counts a source's
     * throttled requests (calls, extension-enum REGISTERs, OPTIONS sweeps) across an active run. Once it
     * exceeds callCeiling the source is a confirmed flooder we've already characterized, so it flips to
     * 'strict' — every subsequent request is dropped (logging collapsed to the flood rollup) until it
     * stays quiet for callCeilingIdleReset and is forgotten. The rate bucket catches only FAST floods;
     * this catches a slow, relentless source that never drains the per-second bucket yet still buries the
     * log in per-request rows.
     * @var array<string, array{count: int, last: float, strict: bool}>
     */
    private array $ceilingState = [];

    /** SIP methods that initiate work / draw an unsolicited response and so are worth flood-throttling.
     *  In-dialog follow-ups (ACK/BYE/CANCEL/INFO) are left alone so an admitted call still tears down. */
    private const THROTTLED_METHODS = ['INVITE', 'REGISTER', 'OPTIONS', 'MESSAGE'];
    private const DTMF_MAX_DIGITS = 64; // cap captured DTMF per dialog; a real sequence is far shorter

    /** The request currently being dispatched, so logEvent can attach attacker attribution. */
    private ?SipMessage $currentReq = null;
    private string $currentTransport = 'udp';
    private int $currentPeerPort = 0;

    /** DTMF event code (0-15) => key label, per RFC 4733 §3.2. */
    private const DTMF_EVENTS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'A', 'B', 'C', 'D'];

    private RtpStreamer $rtpStreamer;
    private ToneGenerator $toneGen;
    private PersonaSoundboard $soundboard;
    private CredentialStore $credStore;

    /** @var callable|null */
    private $logger;

    public function __construct(
        private readonly SipConfig $config,
        ?callable $logger = null,
        ?RtpStreamer $rtpStreamer = null,
        ?PersonaSoundboard $soundboard = null,
        ?CredentialStore $credStore = null,
        private ?OperatorBlocklist $block = null
    ) {
        $this->logger = $logger;
        $this->rtpStreamer = $rtpStreamer ?? new RtpStreamer($this->config->rtpPort);
        $this->toneGen = new ToneGenerator(
            $this->config->ringFrequency1,
            $this->config->ringFrequency2,
            $this->config->ringCadenceOn,
            $this->config->ringCadenceOff
        );
        $this->soundboard = $soundboard ?? new PersonaSoundboard($this->config->audioDir, $this->toneGen);
        $this->credStore = $credStore ?? new CredentialStore($this->config->latchedCredentialsFile);
    }

    public function __destruct()
    {
        $this->closeSockets();
    }

    public function closeSockets(): void
    {
        if ($this->udpSocket && is_resource($this->udpSocket)) {
            @fclose($this->udpSocket);
            $this->udpSocket = null;
        }
        if ($this->tcpSocket && is_resource($this->tcpSocket)) {
            @fclose($this->tcpSocket);
            $this->tcpSocket = null;
        }
        foreach ($this->tcpClients as $sock) {
            if (is_resource($sock)) {
                @fclose($sock);
            }
        }
        foreach ($this->sessions as $key => $s) {
            $this->endSession($s, $key);
        }
        $this->tcpClients = [];
        $this->tcpBuffers = [];
        $this->tcpPeers = [];
    }

    /**
     * Binds the server sockets to the configured address.
     */
    public function bind(): void
    {
        $bind = $this->config->bind;

        // 1. Connectionless UDP 5060 socket
        $udp = @stream_socket_server('udp://' . $bind, $errno, $errstr, STREAM_SERVER_BIND);
        if (!$udp) {
            throw new \RuntimeException("Failed to bind UDP socket on {$bind}: {$errstr} ({$errno})");
        }
        stream_set_blocking($udp, false);
        $this->udpSocket = $udp;

        // 2. Stream TCP 5060 listen socket
        $tcp = @stream_socket_server('tcp://' . $bind, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if (!$tcp) {
            @fclose($udp);
            throw new \RuntimeException("Failed to bind TCP socket on {$bind}: {$errstr} ({$errno})");
        }
        stream_set_blocking($tcp, false);
        $this->tcpSocket = $tcp;
    }

    /**
     * Main server loop.
     */
    public function listen(string $bind = ''): void
    {
        if ($bind !== '') {
            $this->config->bind = $bind;
        }

        $this->bind();
        echo "funnypot-sip ({$this->config->style}, audio={$this->config->audioMode}) listening on {$this->config->bind} (UDP & TCP)\n";

        while (true) {
            $this->runOnce();
        }
    }

    /**
     * Non-blocking single iteration (for select loop / testing).
     */
    public function runOnce(): void
    {
        // Fault isolation: this listener runs unsupervised, so a fault while handling one message,
        // RTP tick or cleanup must degrade (log + skip) — never escape the loop and kill the process.
        // Each phase is guarded independently so a bad message can't stop RTP for live calls, etc.
        try {
            $read = [];
            if ($this->udpSocket && is_resource($this->udpSocket)) {
                $read[] = $this->udpSocket;
            }
            if ($this->tcpSocket && is_resource($this->tcpSocket)) {
                $read[] = $this->tcpSocket;
            }
            $rtpSock = $this->rtpStreamer->getSocket();
            if ($rtpSock && is_resource($rtpSock)) {
                $read[] = $rtpSock;
            }
            foreach ($this->tcpClients as $client) {
                if (is_resource($client)) {
                    $read[] = $client;
                }
            }

            $write = null;
            $except = null;

            // 5ms timeout to maintain accurate 20ms RTP packet timing without CPU spin
            $numChanged = @stream_select($read, $write, $except, 0, 5000);
            if ($numChanged && $numChanged > 0) {
                foreach ($read as $sock) {
                    try {
                        if ($sock === $this->udpSocket) {
                            $this->handleInboundUdp();
                        } elseif ($sock === $rtpSock) {
                            $this->handleInboundRtp();
                        } elseif ($sock === $this->tcpSocket) {
                            $this->handleTcpAccept();
                        } else {
                            $this->handleInboundTcp($sock);
                        }
                    } catch (\Throwable $e) {
                        $this->logFault('inbound', $e);
                    }
                }
            }
        } catch (\Throwable $e) {
            $this->logFault('select', $e);
        }

        // Answer any ringing call whose randomized ring interval has elapsed
        try {
            $this->deliverPendingAnswers();
        } catch (\Throwable $e) {
            $this->logFault('answer', $e);
        }

        // Drive RTP media streaming timers
        try {
            $this->tickRtpStreams();
        } catch (\Throwable $e) {
            $this->logFault('rtp-tick', $e);
        }

        // Evict expired calls and nonces
        try {
            $this->cleanupExpiredSessions();
        } catch (\Throwable $e) {
            $this->logFault('cleanup', $e);
        }
    }

    /**
     * Records an internal fault to the event stream (so it surfaces on the dashboard) without ever
     * letting it escape the run loop — the honeypot must degrade, never crash. If logging itself
     * throws, swallow it: keeping the listener alive matters more than that one log line.
     */
    private function logFault(string $where, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'error',
                'ip' => '',
                'port' => 0,
                'path' => "SIP internal fault [{$where}]: " . $e->getMessage(),
                'matched' => 0,
                'served' => 0,
                'reportable' => false,
            ]);
        } catch (\Throwable $ignored) {
            // logging is broken; the loop surviving is what matters
        }
    }

    /**
     * Handles incoming UDP datagrams.
     */
    private function handleInboundUdp(): void
    {
        $data = @stream_socket_recvfrom($this->udpSocket, 65535, 0, $peerAddr);
        if ($data === false || $data === '' || !$peerAddr) {
            return;
        }

        [$peerIp, $peerPort] = $this->splitAddr($peerAddr);
        // Operator manual block: drop before parse — a blocked UDP source gets zero bytes, not even the
        // malformed-input 400 below (which would be a reflected packet at a possibly-spoofed victim).
        if ($this->block !== null && $this->block->isBlocked($peerIp)) {
            return;
        }
        $req = SipMessage::parse($data);
        if (!$req) {
            // Parseable-but-invalid: 400 like a real Asterisk (best-effort, rate-limited by the F4
            // bucket); ungrammatical garbage without routing headers is dropped.
            $bad = SipMessage::build400($data, $this->config->userAgent);
            if ($bad !== null) {
                $this->sendResponse($bad, $peerIp, $peerPort, 'udp');
            }

            return;
        }

        $this->dispatchMessage($req, $peerIp, $peerPort, 'udp');
    }

    /**
     * Accepts new TCP connections on port 5060.
     */
    private function handleTcpAccept(): void
    {
        $client = @stream_socket_accept($this->tcpSocket, 0, $peerAddr);
        if ($client) {
            // Operator manual block: refuse a blocked source at accept — no buffer, no response.
            $acceptIp = is_string($peerAddr) ? $this->splitAddr($peerAddr)[0] : '';
            if ($this->block !== null && $acceptIp !== '' && $this->block->isBlocked($acceptIp)) {
                @fclose($client);

                return;
            }
            if (count($this->tcpClients) >= self::MAX_TCP_CLIENTS) {
                @fclose($client); // at capacity — refuse (fd-exhaustion guard)

                return;
            }
            stream_set_blocking($client, false);
            $id = (int) $client;
            $this->tcpClients[$id] = $client;
            $this->tcpBuffers[$id] = '';
            $this->tcpLastActivity[$id] = microtime(true);
            // Attribution source: the accepted socket's real peer, captured now while it is reliable.
            $this->tcpPeers[$id] = is_string($peerAddr) ? $peerAddr : '';
        }
    }

    /**
     * Reads from connected TCP client streams.
     */
    private function handleInboundTcp($sock): void
    {
        $id = (int) $sock;
        $chunk = @fread($sock, 8192);
        if ($chunk === false || $chunk === '') {
            @fclose($sock);
            unset($this->tcpClients[$id], $this->tcpBuffers[$id], $this->tcpLastActivity[$id], $this->tcpPeers[$id]);

            return;
        }

        $this->tcpLastActivity[$id] = microtime(true);
        $this->tcpBuffers[$id] .= $chunk;

        // Slowloris guard: a client dribbling data with no complete SIP message is dropped rather
        // than buffered without bound.
        if (strlen($this->tcpBuffers[$id]) > self::MAX_TCP_BUFFER) {
            @fclose($sock);
            unset($this->tcpClients[$id], $this->tcpBuffers[$id], $this->tcpLastActivity[$id], $this->tcpPeers[$id]);

            return;
        }

        // Source IP from the accept-time capture, never a fabricated loopback. An unresolvable peer
        // stays empty (never 127.0.0.1:5060) so it is logged as unknown and suppressed from reports
        // by logEvent's reportable guard — reporting a placeholder would blame an innocent/local IP.
        $peer = $this->tcpPeers[$id] ?? '';
        [$peerIp, $peerPort] = $peer !== '' ? $this->splitAddr($peer) : ['', 0];

        // Operator manual block: drop the whole connection for a blocked source (catches an IP blocked
        // mid-session, and never sends the malformed-input 400 below). Zero further bytes.
        if ($this->block !== null && $this->block->isBlocked($peerIp)) {
            @fclose($sock);
            unset($this->tcpClients[$id], $this->tcpBuffers[$id], $this->tcpLastActivity[$id], $this->tcpPeers[$id]);

            return;
        }

        // Drain every complete SIP message in the buffer. One read can carry a partial message (wait
        // for the rest) or several pipelined ones; consume exactly each framed message and keep the
        // remainder buffered, so a body split across reads is never parsed truncated.
        while (($frameLen = SipMessage::frameLength($this->tcpBuffers[$id])) !== null) {
            $frame = substr($this->tcpBuffers[$id], 0, $frameLen);
            $this->tcpBuffers[$id] = substr($this->tcpBuffers[$id], $frameLen);

            $req = SipMessage::parse($frame);
            if ($req) {
                $this->dispatchMessage($req, $peerIp, $peerPort, 'tcp', $sock);
            } else {
                // Parseable-but-invalid: answer 400 like a real Asterisk (best-effort), else drop.
                $bad = SipMessage::build400($frame, $this->config->userAgent);
                if ($bad !== null) {
                    $this->sendResponse($bad, $peerIp, $peerPort, 'tcp', $sock);
                }
            }
        }
    }

    /**
     * Central dispatch for SIP methods.
     */
    public function dispatchMessage(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock = null): void
    {
        if (!$req->isRequest) {
            return; // Ignore inbound responses for now
        }

        // Make the request (and its transport) available to logEvent so every event carries
        // attacker attribution and transport tells without threading them through every handler.
        $this->currentReq = $req;
        $this->currentTransport = $transport;
        $this->currentPeerPort = $peerPort;

        // Operator manual block: a blocked source gets ZERO bytes for ANY method — no session, no
        // response, no bucket churn, no log. Silent drop = reflection-safe on UDP. Checked before the
        // flood throttle (which only covers some methods and mutates bucket state we must not touch here).
        if ($this->block !== null && $this->block->isBlocked($peerIp)) {
            return;
        }

        // Per-source flood throttle: a sustained INVITE/REGISTER/OPTIONS/MESSAGE flood from one apparent
        // source is dropped here, before any session is built or byte emitted (silent drop = reflection-
        // safe on UDP), with its per-call logging collapsed to a periodic rollup. Auto-recovers when the
        // source slows. ACK/BYE/CANCEL/INFO are exempt so an already-admitted call still tears down; a
        // re-INVITE from a drained source is throttled like any INVITE (a flood has no legitimate ones).
        if (in_array($req->method, self::THROTTLED_METHODS, true)) {
            // Cumulative ceiling first (a slow, relentless dialer the rate bucket never catches), then the
            // per-second rate bucket (a fast flood). Either dropping routes to the same rollup so a buried
            // log collapses to ~one 'call_flood' row per source per minute.
            if ($this->overCallCeiling($peerIp, $req->method) || !$this->admitRequest($peerIp)) {
                $this->recordFloodDrop($peerIp, $req->method);

                return;
            }
        }

        switch ($req->method) {
            case 'OPTIONS':
                $this->handleOptions($req, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'REGISTER':
                $this->handleRegister($req, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'INVITE':
                $this->handleInvite($req, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'ACK':
                $this->handleAck($req, $peerIp, $peerPort);
                break;

            case 'BYE':
                $this->handleBye($req, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'CANCEL':
                $this->handleCancel($req, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'INFO':
                // Capture any out-of-band DTMF (application/dtmf-relay or application/dtmf), then ack.
                $this->captureInfoDtmf($req, $peerIp, $peerPort, $transport);
                $res = $req->buildOk(SipMessage::asteriskTag(), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
                $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'MESSAGE':
                // SIP MESSAGE = SMS-over-SIP: smishing content, A2P spam, or open-relay probing. Capture
                // the target, sender and body as intel and 202-accept it (an Asterisk with messaging
                // would) to draw more samples. INERT: the message is only logged, never relayed.
                $this->handleMessage($req, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'SUBSCRIBE':
            case 'PUBLISH':
            case 'REFER':
                // Auth-requiring methods: a real Asterisk challenges these with 401 (same as REGISTER),
                // not a bare 200 — an unauthenticated 200 to SUBSCRIBE/PUBLISH is a stack tell. The
                // challenge nonce is fresh but not stored (we do not validate a re-auth for these), so a
                // SUBSCRIBE/PUBLISH flood cannot grow the nonce table; the scanner just re-challenges (tarpit).
                $res = $req->buildUnauthorized(SipMessage::asteriskTag(), $this->config->realm, bin2hex(random_bytes(16)), $this->config->userAgent);
                $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            case 'NOTIFY':
            case 'UPDATE':
            case 'PRACK':
                // In-dialog methods with no matching dialog: a real stack answers 481, not 200 (a bare 200
                // to an out-of-dialog NOTIFY/UPDATE/PRACK is a tell).
                $res = $req->buildResponse(481, 'Call/Transaction Does Not Exist', SipMessage::asteriskTag(), [], '', $this->config->userAgent);
                $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            default:
                // Unknown/garbage verb -> 501, like a real Asterisk. A bare 200 to any method is a
                // one-packet honeypot detector. Still logged as a probe (intel).
                $this->sendResponse($req->buildNotImplemented($this->config->userAgent), $peerIp, $peerPort, $transport, $tcpSock);
                $this->logEvent([
                    'proto' => 'sip',
                    'method' => 'SIP',
                    'event' => 'probe',
                    'ip' => $peerIp,
                    'port' => $peerPort,
                    'path' => 'SIP ' . substr($req->method, 0, 16) . ' unsupported method (501)',
                    'matched' => 1,
                    'served' => 1,
                    'reportable' => ($transport === 'tcp'),
                ]);
                break;
        }
    }

    /**
     * RFC 3261 OPTIONS scanner probe handler.
     */
    private function handleOptions(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        // Same enumeration shaping as REGISTER/INVITE: an OPTIONS aimed at a specific AOR this PBX
        // doesn't host answers 404 (svmap maps only real extensions). A server-directed OPTIONS
        // keep-alive (no user part in the Request-URI) keeps the normal 200 OK. Probe still logged.
        $ext = $this->addressedExtension($req);
        if ($this->config->shapesExtensionEnumeration() && $ext !== null && !$this->config->isValidExtension($ext)) {
            $res = $req->buildNotFound(SipMessage::asteriskTag(), $this->config->userAgent);
            $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'probe',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP OPTIONS ext:{$ext} unknown extension (404) enumeration probe ({$transport})",
                'matched' => 1,
                'served' => 1,
                'reportable' => ($transport === 'tcp'),
            ]);

            return;
        }

        // OPTIONS is the scanner's first-contact fingerprint surface — answer as a fuller Asterisk so
        // svmap/sipvicious mark the box live and escalate to REGISTER/INVITE. Accept + Allow-Events
        // advertise a complete pjsip stack (SDP negotiation + event subscriptions); Allow/Supported
        // stay Asterisk-20-faithful (no REGISTER-only 'path' extension, which would be a tell here).
        $res = $req->buildOk(SipMessage::asteriskTag(), "<sip:{$this->getServerIp()}:5060>", '', [
            'Accept' => 'application/sdp',
            'Allow-Events' => 'message-summary, presence, dialog, refer, cc',
        ], $this->config->userAgent);
        $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

        // Anti-Spoofing (B2): Bare UDP OPTIONS are spoofable; only reportable over TCP
        $this->logEvent([
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'probe',
            'ip' => $peerIp,
            'port' => $peerPort,
            'path' => "SIP OPTIONS probe ({$transport})",
            'matched' => 1,
            'served' => 1,
            'reportable' => ($transport === 'tcp'),
        ]);
    }

    /**
     * Handles inbound RTP audio datagrams from the caller.
     * Detects voice energy to hold conversational pauses so Lenny listens while the caller speaks!
     */
    private function handleInboundRtp(): void
    {
        $pkt = $this->rtpStreamer->receivePacket();
        if ($pkt && strlen($pkt['payload']) > 0) {
            $payload = $pkt['payload'];
            $isVoice = false;

            // Check peak amplitude for caller speech detection (VAD)
            $len = strlen($payload);
            for ($i = 0; $i < $len; $i += 8) {
                $byte = ord($payload[$i]);
                $val = ~$byte & 0xff;
                $exp = ($val >> 4) & 0x07;
                $mant = $val & 0x0f;
                $sample = (($mant << 3) + 0x84) << $exp;
                if ($sample > 700) {
                    $isVoice = true;
                    break;
                }
            }

            foreach ($this->sessions as $s) {
                if ($s->peerIp === $pkt['peerIp'] && $s->isStreaming()) {
                    // Caller is still on the line — mark activity so the call doesn't idle out.
                    $s->lastInboundTime = microtime(true);

                    // Out-of-band DTMF (RFC 4733 telephone-event): a keypad press, not audio.
                    // Decode and log it; do not fold it into the recorded audio channel.
                    if ($s->dtmfPt !== null && ($pkt['pt'] ?? -1) === $s->dtmfPt) {
                        $this->captureRtpDtmf($s, $payload, (int) ($pkt['timestamp'] ?? 0));
                        break;
                    }

                    // Record the caller's audio (the intel) as the recording's left channel.
                    if ($this->config->recordCalls) {
                        $s->recordedInbound .= $payload;
                    }
                    // If caller is speaking during Lenny's pause, hold the pause so Lenny doesn't interrupt!
                    if ($isVoice && $s->personaPauseRemaining > 0) {
                        // Keep at least 1.5s (75 ticks) of silence buffer after caller finishes talking
                        $s->personaPauseRemaining = max($s->personaPauseRemaining, 75);
                    }
                    break;
                }
            }
        }
    }

    /**
     * RFC 3261 REGISTER extension & credential brute-force handler.
     * Supports weak default password acceptance and open unauthenticated access.
     */
    private function handleRegister(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        $auth = $req->getDigestAuth();
        $toTag = SipMessage::asteriskTag();
        $contact = $req->getHeader('contact') ?? "<sip:{$peerIp}:{$peerPort}>";

        // Extension-enumeration shaping: a REGISTER for an AOR this PBX does not host answers 404,
        // not the 401 challenge — so svwar sees a bounded, realistic extension map (valid ones
        // challenge → juicy target) instead of an impossible infinite-extension PBX. The probe is
        // still logged as intel. Only shaped when a specific extension is identifiable; a
        // server-directed REGISTER with no AOR falls through to the normal challenge flow.
        $ext = $this->registerExtension($req, $auth);
        if ($this->config->shapesExtensionEnumeration() && $ext !== null && !$this->config->isValidExtension($ext)) {
            $this->sendResponse($req->buildNotFound($toTag, $this->config->userAgent), $peerIp, $peerPort, $transport, $tcpSock);
            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'probe',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP REGISTER ext:{$ext} unknown extension (404) enumeration probe",
                'matched' => 1,
                'served' => 1,
                'reportable' => ($transport === 'tcp'),
            ]);

            return;
        }

        // 1. Unauthenticated open access mode:
        if ($this->config->authMode === 'open') {
            $user = $req->getDialedNumber();
            $res = $req->buildRegisteredOk($toTag, $contact, 3600, $this->config->userAgent);
            $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'login',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP REGISTER user:{$user} (unauthenticated open access)",
                'matched' => 1,
                'served' => 1,
                'reportable' => ($transport === 'tcp'),
            ]);

            return;
        }

        if (empty($auth)) {
            // Step 1: Challenge with 401 Unauthorized
            $nonce = bin2hex(random_bytes(16));
            // Bind the nonce to the address it is issued to: over spoofable UDP it is valid only when
            // replayed from this same source (FP-0247 anti-spoof). Keep the 300s expiry on 'ts'.
            $this->activeNonces[$nonce] = ['ip' => $peerIp, 'ts' => time()];

            $res = $req->buildUnauthorized($toTag, $this->config->realm, $nonce, $this->config->userAgent);
            $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

            // First-leg UDP is not yet proven round-trip
            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'probe',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP REGISTER challenge sent ({$transport})",
                'matched' => 1,
                'served' => 1,
                'reportable' => false,
            ]);

            return;
        }

        // Step 2: Credential response received!
        $user = $auth['username'] ?? 'unknown';
        $responseHash = $auth['response'] ?? '';
        $nonce = $auth['nonce'] ?? '';

        // Verify the nonce was issued by us AND — over spoofable UDP — that this response comes from
        // the SAME address the nonce was challenged to. A single spoofed UDP REGISTER carrying a nonce
        // harvested from a real 401 (issued to the attacker's own IP) would otherwise report the
        // spoofed victim as reportable=true. TCP is source-verified by the handshake, so it stays an
        // accepted path regardless of the stored IP. The nonce is consumed on first response (one-shot)
        // so a captured nonce cannot be replayed — from any source — for the 300s expiry window.
        $nonceEntry = $this->activeNonces[$nonce] ?? null;
        $nonceMatchesSource = is_array($nonceEntry) && ($nonceEntry['ip'] ?? '') === $peerIp;
        $validRoundTrip = $nonceMatchesSource || $transport === 'tcp';
        if ($nonceEntry !== null) {
            unset($this->activeNonces[$nonce]);   // one-shot: a challenge nonce is spent on first use
        }

        // Credential capture for an already-known AOR.
        // Once any credential has been latched for (IP, extension) we ACCEPT every subsequent
        // REGISTER — a honeypot lures by being trivially easy to authenticate. Rejecting a second
        // password would turn bots away after one crack AND bounce a real softphone: an uncrackable
        // password can only be stored as a nonce-bound hash, so on the next refresh (fresh nonce)
        // the SAME password no longer matches. We answer 200 either way, still capturing the intel.
        if ($this->config->latchPasswords && $this->credStore->hasLatched($peerIp, $user)) {
            // Same credential if the latched plaintext re-verifies against THIS request's nonce/nc
            // (a real softphone re-REGISTERs with the same password but a fresh nonce/nc, so a raw
            // response-hash compare would spuriously reject it), or — for an uncrackable permissive
            // password we could only store as its hash — if the exact response repeats.
            $latched = $this->credStore->getLatched($peerIp, $user);
            $sameCredential = $latched !== null
                && (SipMessage::verifyDigest($auth, $latched, $req->method) || hash_equals($latched, $responseHash));

            // Accept every REGISTER on a known AOR — same credential or a fresh guess.
            $res = $req->buildRegisteredOk($toTag, $contact, 3600, $this->config->userAgent);
            $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

            if ($sameCredential) {
                $path = "SIP REGISTER ext:{$user} (latched credentials verified)";
            } else {
                // A different guess on an already-cracked AOR: capture it as intel. Re-latch the
                // recovered plaintext when we can name it, so a caller's steady-state password
                // re-verifies cleanly on later refreshes instead of re-logging every time.
                $recovered = $this->recoverPlaintext($auth, $req->method);
                if ($recovered !== null) {
                    $this->credStore->latch($peerIp, $user, $recovered);
                }
                $path = "SIP REGISTER ext:{$user} additional credential captured (hash: {$responseHash})";
            }

            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'login',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => $path,
                'matched' => 1,
                'served' => 1,
                'reportable' => $validRoundTrip,
            ]);

            return;
        }

        // Not yet latched for this IP and extension:
        // Check password according to authMode:
        $accepted = false;
        $matchedPass = '';

        if ($this->config->authMode === 'permissive' || $this->config->authMode === 'accept_all') {
            // A CORRECT weak password (username-as-password or a seeded default) is accepted immediately,
            // exactly as a real weak PBX would. An ARBITRARY password (which only permissive accepts) is
            // gated behind crack resistance: reject the first N guesses per (IP, ext) so a random-password
            // spray does not "crack" on guess #1 — the honeypot tell svcrack/rcrack look for — then accept
            // + latch, keeping the toll-fraud lure while burning the brute-forcer's time.
            if (SipMessage::verifyDigest($auth, $user, $req->method)) {
                $accepted = true;
                $matchedPass = $user;
            } else {
                foreach ($this->config->defaultPasswords as $cand) {
                    if (SipMessage::verifyDigest($auth, $cand, $req->method)) {
                        $accepted = true;
                        $matchedPass = $cand;
                        break;
                    }
                }
            }
            if (!$accepted && $this->crackResistancePassed($peerIp, $user)) {
                $accepted = true;
                $matchedPass = 'cracked_hash:' . substr($responseHash, 0, 8);
            }
        } elseif ($this->config->authMode === 'weak') {
            // Check if password matches extension/username (e.g. 101:101)
            if (SipMessage::verifyDigest($auth, $user, $req->method)) {
                $accepted = true;
                $matchedPass = $user;
            } else {
                // Check against list of common default passwords
                foreach ($this->config->defaultPasswords as $cand) {
                    if (SipMessage::verifyDigest($auth, $cand, $req->method)) {
                        $accepted = true;
                        $matchedPass = $cand;
                        break;
                    }
                }
            }
        }

        if ($accepted) {
            // SUCCESS: Latch this credential for this IP and extension so future conflicting guesses fail!
            // Latch the recovered plaintext when we know it, so re-auth survives the caller's nonce/nc
            // changing on every refresh; only when the password is uncrackable (permissive accepting an
            // arbitrary password) do we fall back to latching the raw response hash.
            if ($this->config->latchPasswords) {
                $latchValue = ($matchedPass !== '' && strpos($matchedPass, 'cracked_hash:') !== 0)
                    ? $matchedPass
                    : $responseHash;
                $this->credStore->latch($peerIp, $user, $latchValue);
            }

            $res = $req->buildRegisteredOk($toTag, $contact, 3600, $this->config->userAgent);
            $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'login',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP REGISTER ext:{$user} ACCEPTED & LATCHED password '{$matchedPass}'",
                'matched' => 1,
                'served' => 1,
                'reportable' => $validRoundTrip,
            ]);

            return;
        }

        // Log failed registration attempt
        $this->logEvent([
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'login',
            'ip' => $peerIp,
            'port' => $peerPort,
            'path' => "SIP REGISTER user:{$user} hash:{$responseHash}",
            'matched' => 1,
            'served' => 1,
            'reportable' => $validRoundTrip,
        ]);

        // Return 403 Forbidden
        $res = $req->buildForbidden($toTag, $this->config->userAgent);
        $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);
    }

    /**
     * Permissive-mode crack resistance: whether an arbitrary password should now be accepted for
     * (IP, ext). Rejects the first (seeded) threshold guesses so the crack "succeeds" after a believable
     * few tries, not on guess #1. crackMin <= 0 disables it (accept the first guess).
     */
    private function crackResistancePassed(string $peerIp, string $user): bool
    {
        if ($this->config->crackMin <= 0) {
            return true;
        }
        $n = $this->credStore->incrementCrackAttempt($peerIp, $user);

        return $n > $this->crackThreshold($peerIp, $user);
    }

    /** A stable per-(IP, ext) guess threshold in [crackMin, crackMax], so different accounts "crack"
     *  after a different, realistic number of tries rather than a uniform constant. */
    private function crackThreshold(string $peerIp, string $user): int
    {
        $min = max(1, $this->config->crackMin);
        $max = max($min, $this->config->crackMax);
        $span = ($max - $min) + 1;
        $h = (int) hexdec(substr(hash('sha256', $peerIp . '|' . $user . '|crack'), 0, 8));

        return $min + ($h % $span);
    }

    /**
     * Recover the cleartext password behind a digest response when it is one we can name
     * (username-as-password or a seeded default). Returns null for an unknowable password —
     * a digest hash is one-way, so an arbitrary password cannot be reconstructed.
     */
    private function recoverPlaintext(array $auth, string $method): ?string
    {
        $user = $auth['username'] ?? '';
        if ($user !== '' && SipMessage::verifyDigest($auth, $user, $method)) {
            return $user;
        }
        foreach ($this->config->defaultPasswords as $cand) {
            if (SipMessage::verifyDigest($auth, $cand, $method)) {
                return $cand;
            }
        }

        return null;
    }

    /**
     * RFC 3261 INVITE toll-fraud call & tarpit setup.
     */
    private function handleInvite(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        // An INVITE always ANSWERS — never 404 on the dialed target. A caller dials external numbers
        // (toll-fraud targets, premium/international) that are not PBX extensions; the whole point of
        // this honeypot is to answer, connect, stream a persona and capture the dialed number. Gating
        // INVITE on extension validity (like REGISTER/OPTIONS enumeration) would silently reject the
        // exact toll-fraud calls we want to record. The dialed number is captured on the call event.
        $callId = $req->getCallId() ?? ('call-' . bin2hex(random_bytes(4)));
        $sessionKey = $this->sessionKey($callId, $peerIp, $peerPort);

        // Anti-Reflection & Bandwidth Limiting (B1): Enforce concurrency ceilings
        $activeCount = count($this->sessions);
        $perIpCount = $this->countSessionsForIp($peerIp);

        if ($activeCount >= $this->config->maxActiveCalls || $perIpCount >= $this->config->perIpCalls) {
            // Reject call with 486 Busy Here
            $res = $req->buildBusy(SipMessage::asteriskTag(), $this->config->userAgent);
            $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'call_rejected',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP call rejected (ceiling reached: active={$activeCount}, perIp={$perIpCount})",
                'matched' => 1,
                'served' => 1,
                'reportable' => false,
            ]);

            return;
        }

        // 1. Send provisional 100 Trying
        $trying = $req->buildTrying($this->config->userAgent);
        $this->sendResponse($trying, $peerIp, $peerPort, $transport, $tcpSock);

        // 2. Setup call session. Each call from this IP advances the persona cycle so a wardialer
        //    placing repeat calls hears a different voice every time.
        $dialedNumber = $req->getDialedNumber();
        $callCount = $this->credStore->incrementCallCountForIp($peerIp);
        $persona = $this->soundboard->resolvePersona($this->config->audioMode, $dialedNumber, $callCount);

        $s = new SipSession($callId, $peerIp, $peerPort, $transport);
        $s->tcpSocket = $tcpSock;
        $s->fromTag = $req->getFrom() ?? '';
        $s->dialedNumber = $dialedNumber;
        $s->persona = $persona;
        $s->userAgent = $this->requestUserAgent($req);
        $s->tool = $this->classifyTool($req);
        // Remember which payload type the caller mapped to DTMF so RTP telephone-event packets decode.
        $s->dtmfPt = $req->sdpTelephoneEventPt;

        // Anti-Reflection Invariant (B1): remoteRtpIp is strictly locked to $peerIp
        $s->remoteRtpIp = $peerIp;
        // Take RTP port from client's SDP descriptor (default to 16402 if unspecified)
        $s->remoteRtpPort = $req->sdpAudioPort ?? 16402;
        $s->state = SipSession::STATE_RINGING;

        $this->sessions[$sessionKey] = $s;

        // 3. Ring, then answer after a randomized interval. We send 180 Ringing (no media) so the
        //    caller's phone renders the standard repeating ring cadence, and hold the 200 OK for a
        //    random number of ring cycles — a constant answer time is a honeypot tell. The 200 OK is
        //    delivered from the run loop (deliverPendingAnswers) so the select loop never sleeps.
        //    Deliberately no server-side early-media ringback: streaming RTP to an un-ACKed source
        //    would be an RTP-reflection vector (return-routability is only proven by the ACK).
        $serverIp = $this->getServerIp();
        $localRtpPort = $this->rtpStreamer->getLocalPort();
        // Per-call SDP session id/version — a constant "o=- 1 1" is a cross-call fingerprint.
        $sessionId = (string) random_int(1000000000, 2147483647);
        $sdp = SipMessage::buildSdp($serverIp, $localRtpPort, $sessionId, $this->config->userAgent);
        $contact = "<sip:{$dialedNumber}@{$serverIp}:5060>";

        $this->sendResponse($req->buildRinging($s->toTag, $this->config->userAgent), $peerIp, $peerPort, $transport, $tcpSock);
        $s->pendingOk = $req->buildOk($s->toTag, $contact, $sdp, [], $this->config->userAgent);
        $s->answerAt = microtime(true) + random_int(self::RING_MIN_MS, self::RING_MAX_MS) / 1000.0;

        $this->logEvent([
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'call',
            'ip' => $peerIp,
            'port' => $peerPort,
            'path' => "SIP call connected: {$dialedNumber} (persona: {$persona}, rtp: {$peerIp}:{$s->remoteRtpPort})",
            'matched' => 1,
            'served' => 1,
            'reportable' => false, // Will become reportable once ACK arrives
        ]);
    }

    /**
     * RFC 3261 ACK completes the 3-way handshake and begins RTP audio streaming.
     */
    private function handleAck(SipMessage $req, string $peerIp, int $peerPort): void
    {
        $callId = $req->getCallId() ?? '';
        $match = $this->findSessionByCallId($callId, $peerIp);

        if ($match) {
            [, $s] = $match;

            // Return-routability: only start streaming if the ACK echoes the To-tag we issued in
            // the 200 OK. A spoofed-INVITE reflector never sees that tag (the 200 OK went to the
            // spoofed victim), so this blocks RTP being blasted at a spoofed address.
            if (!preg_match('/;tag=([^\s;>]+)/i', $req->getTo() ?? '', $m) || !hash_equals($s->toTag, $m[1])) {
                return;
            }

            $s->state = SipSession::STATE_STREAMING;
            $s->wasStreaming = true;   // FP-0247: latch — this call passed the ACK To-tag check
            $s->lastRtpSendTime = microtime(true);
            $s->lastInboundTime = microtime(true); // baseline for hangup/idle detection

            // B2: Bidirectional ACK confirms legitimate two-way connectivity!
            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'ack',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP call ACK received, streaming started ({$s->persona})",
                'matched' => 1,
                'served' => 1,
                'reportable' => true,
            ]);
        }
    }

    /**
     * RFC 3261 BYE call termination handler.
     */
    private function handleBye(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        $callId = $req->getCallId() ?? '';
        $match = $this->findSessionByCallId($callId, $peerIp);

        $res = $req->buildOk(SipMessage::asteriskTag(), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
        $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

        if ($match) {
            [$sessionKey, $s] = $match;
            $this->endSession($s, $sessionKey);
        }
    }

    /**
     * RFC 3261 CANCEL cancels a pending INVITE.
     */
    private function handleCancel(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        $callId = $req->getCallId() ?? '';
        $match = $this->findSessionByCallId($callId, $peerIp);

        // 1. 200 OK for CANCEL
        $ok = $req->buildOk(SipMessage::asteriskTag(), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
        $this->sendResponse($ok, $peerIp, $peerPort, $transport, $tcpSock);

        // 2. 487 Request Terminated for the INVITE
        $term = $req->buildResponse(487, 'Request Terminated', SipMessage::asteriskTag(), [], '', $this->config->userAgent);
        $this->sendResponse($term, $peerIp, $peerPort, $transport, $tcpSock);

        if ($match) {
            [$sessionKey] = $match;
            unset($this->sessions[$sessionKey]);
        }
    }

    /**
     * SIP MESSAGE (RFC 3428): SMS-over-SIP. Attackers use it for smishing, A2P spam and to probe
     * whether the PBX is an open message relay. Capture the target, sender and body as intel and
     * 200-accept it so more samples arrive. INERT invariant: the message is only logged, never relayed.
     */
    private function handleMessage(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        $target = $req->getDialedNumber();                 // Request-URI user = destination MSISDN/ext
        $ctype = strtolower($req->getHeader('content-type') ?? '');
        $body = trim($req->body);
        // Collapse + cap the body: it is intel, and a flood must not bloat the log.
        $snippet = substr((string) preg_replace('/\s+/', ' ', $body), 0, 400);

        $res = $req->buildResponse(200, 'OK', SipMessage::asteriskTag(), [], '', $this->config->userAgent);
        $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

        $this->logEvent([
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'message',
            'ip' => $peerIp,
            'port' => $peerPort,
            'path' => "SIP MESSAGE to:{$target} ({$ctype}): {$snippet}",
            'matched' => 1,
            'served' => 1,
            'reportable' => ($transport === 'tcp'),
        ]);
    }

    /**
     * The extension/AOR a REGISTER targets, or null if none can be identified. On the credential leg
     * the digest username is the AOR; otherwise it is the user part of the To / From / Request-URI.
     * Returns null (no shaping — keep the normal challenge) for a server-directed REGISTER that names
     * no specific AOR.
     * @param array<string, string> $auth
     */
    private function registerExtension(SipMessage $req, array $auth): ?string
    {
        $user = trim($auth['username'] ?? '');
        if ($user !== '') {
            return $user;
        }
        foreach ([$req->getTo(), $req->getFrom(), $req->uri] as $src) {
            if ($src !== null && preg_match('/sip:([^@;>\s]+)@/i', $src, $m)) {
                return trim($m[1]);
            }
        }

        return null;
    }

    /**
     * The extension/AOR an OPTIONS or INVITE addresses, or null if none. A specific AOR is addressed
     * only when the Request-URI carries a user part (sip:user@host); a bare sip:host targets the
     * server itself (a keep-alive), not an extension, so it is not enumeration-shaped.
     */
    private function addressedExtension(SipMessage $req): ?string
    {
        if (preg_match('/sip:([^@;>\s]+)@/i', $req->uri, $m)) {
            return trim($m[1]);
        }

        return null;
    }

    /**
     * Finds an active session matching Call-ID and source IP.
     * @return array{0: string, 1: SipSession}|null
     */
    private function findSessionByCallId(string $callId, string $peerIp): ?array
    {
        foreach ($this->sessions as $key => $s) {
            if ($s->callId === $callId && $s->peerIp === $peerIp) {
                return [$key, $s];
            }
        }

        return null;
    }

    /**
     * Transmits RTP audio packets to active streaming sessions every 20ms.
     */
    public function tickRtpStreams(): void
    {
        $now = microtime(true);

        foreach ($this->sessions as $key => $s) {
            try {
                if (!$s->isStreaming()) {
                    continue;
                }

                // Enforce max call duration safety cutoff. End the session through the normal path so
                // the recording is written AND logged with its dashboard URL — an inline write here
                // would leave the WAV orphaned on disk, invisible in the feed.
                if ($s->getDuration() > $this->config->maxCallDuration) {
                    $this->endSession($s, $key);
                    continue;
                }

                if ($s->lastRtpSendTime <= 0.0) {
                    $s->lastRtpSendTime = $now;
                }

                // Virtual clock pacing: transmit 160-byte (20ms) slices at exactly 50 pps with zero timing drift
                $burst = 0;
                while (($now - $s->lastRtpSendTime) >= 0.020 && $burst < 3) {
                    $slice = $this->soundboard->getNextSlice($s);
                    $this->rtpStreamer->sendPacket($s, $slice);

                    // Record conversation audio
                    if ($this->config->recordCalls) {
                        $s->recordedUlaw .= $slice;
                    }

                    $s->lastRtpSendTime += 0.020;
                    $burst++;
                }

                // Prevent clock drift / lag behind after system pause
                if (($now - $s->lastRtpSendTime) > 0.060) {
                    $s->lastRtpSendTime = $now;
                }
            } catch (\Throwable $e) {
                // A poisoned session must be evicted, not retried every tick (a tight error loop).
                $this->logFault('rtp-session', $e);
                unset($this->sessions[$key]);
            }
        }
    }

    /**
     * Sends a SIP response over UDP or TCP.
     */
    private function sendResponse(string $raw, string $peerIp, int $peerPort, string $transport, $tcpSock = null): void
    {
        // RFC 3581: if the client's top Via asked for ;rport, echo the observed source as
        // received=/rport= — real edge PBXs do this for NAT traversal, and omitting it is a tell.
        $raw = $this->addViaReceived($raw, $peerIp, $peerPort);

        if ($transport === 'tcp' && $tcpSock && is_resource($tcpSock)) {
            @fwrite($tcpSock, $raw);
        } elseif ($this->udpSocket && is_resource($this->udpSocket)) {
            // F4: a spoofed request aims our UDP reply at a forged victim. Meter replies per apparent
            // source so no single source can pull an unbounded stream of reflected packets.
            if (!$this->udpResponseAllowed($peerIp)) {
                return;
            }
            $dest = "{$peerIp}:{$peerPort}";
            @stream_socket_sendto($this->udpSocket, $raw, 0, $dest);
        }
    }

    /**
     * Token-bucket admission for a UDP reply to $ip (F4 anti-reflection throttle). Returns false when
     * the apparent source has drained its bucket, so the reply is dropped rather than reflected.
     */
    /**
     * Echo the observed source into the first Via as received=/rport= when the client requested rport
     * (RFC 3581). Only the top Via, only when a bare ;rport is present; other responses pass through.
     */
    private function addViaReceived(string $raw, string $peerIp, int $peerPort): string
    {
        $out = preg_replace(
            '/(^Via:[^\r\n]*?);rport(?![=\w])/mi',
            '$1;received=' . $peerIp . ';rport=' . $peerPort,
            $raw,
            1
        );

        return $out ?? $raw;
    }

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

    /**
     * Call-admission token bucket for an apparent source $ip. Returns false when the source has drained
     * its bucket (a sustained flood), so the request is dropped before any session/response/log. Capacity
     * and refill come from SipConfig; callBurst <= 0 disables the throttle (always admit). Mirrors the F4
     * response bucket, keyed the same way (apparent source), and bounds the tracked-IP map.
     */
    private function admitRequest(string $ip): bool
    {
        $burst = $this->config->callBurst;
        if ($burst <= 0.0) {
            return true; // throttle disabled
        }
        $rate = $this->config->callRatePerSec;
        $now = microtime(true);

        if (!isset($this->callBuckets[$ip])) {
            if (count($this->callBuckets) >= self::CALL_BUCKET_MAX_IPS) {
                $oldestKey = null;
                $oldestAt = INF;
                foreach ($this->callBuckets as $k => $b) {
                    if ($b['last'] < $oldestAt) {
                        $oldestAt = $b['last'];
                        $oldestKey = $k;
                    }
                }
                if ($oldestKey !== null) {
                    unset($this->callBuckets[$oldestKey]);
                }
            }
            $this->callBuckets[$ip] = ['tokens' => $burst, 'last' => $now];
        }

        $bucket = &$this->callBuckets[$ip];
        $elapsed = max(0.0, $now - $bucket['last']);
        $bucket['tokens'] = min($burst, $bucket['tokens'] + $elapsed * $rate);
        $bucket['last'] = $now;

        // Fully refilled -> the source has been quiet long enough to have recovered; flush the residual
        // drop count (so the total is exact, not undercounted by the last window) then drop the rollup
        // state so a later flood is reported as a fresh incident rather than continuing the count.
        if ($bucket['tokens'] >= $burst) {
            $this->flushFloodRollup($ip);
            unset($this->floodState[$ip]);
        }

        if ($bucket['tokens'] < 1.0) {
            return false;
        }
        $bucket['tokens'] -= 1.0;

        return true;
    }

    /**
     * Cumulative per-source ceiling gate. Returns true when the request should be dropped because the
     * source is a confirmed flooder. A source accumulates one count per throttled request (INVITE calls,
     * REGISTER enumeration/brute-force, OPTIONS sweeps) across an active run; once the count exceeds
     * callCeiling it flips to 'strict' and every throttled request from it is dropped — we have already
     * learned all we can, so there is nothing left to gain by answering. The source is forgotten (and thus
     * forgiven) after callCeilingIdleReset seconds of silence.
     */
    private function overCallCeiling(string $ip, string $method): bool
    {
        $ceiling = $this->config->callCeiling;
        if ($ceiling <= 0) {
            return false; // disabled
        }
        $now = microtime(true);

        if (!isset($this->ceilingState[$ip])) {
            if (count($this->ceilingState) >= self::CALL_BUCKET_MAX_IPS) {
                $oldestKey = null;
                $oldestAt = INF;
                foreach ($this->ceilingState as $k => $s) {
                    if ($s['last'] < $oldestAt) {
                        $oldestAt = $s['last'];
                        $oldestKey = $k;
                    }
                }
                if ($oldestKey !== null) {
                    unset($this->ceilingState[$oldestKey]);
                }
            }
            $this->ceilingState[$ip] = ['count' => 0, 'last' => $now, 'strict' => false];
        }

        $st = &$this->ceilingState[$ip];
        // A source that has been silent longer than the reset window is forgiven: start a fresh run so a
        // bot that gives up and returns hours later is re-characterized rather than dropped on sight. A
        // strict source is dropped before the rate bucket runs, so its flood state is cleared here (with a
        // final flush) rather than in admitRequest.
        if (($now - $st['last']) > $this->config->callCeilingIdleReset) {
            $st['count'] = 0;
            $st['strict'] = false;
            $this->flushFloodRollup($ip);
            unset($this->floodState[$ip]);
        }
        $st['last'] = $now;

        if ($st['strict']) {
            return true;
        }

        // Count every throttled request toward the ceiling, not just calls. A tool floods us with
        // whatever method it uses: INVITE (toll-fraud dial), REGISTER (extension enumeration / credential
        // brute-force), OPTIONS (liveness sweep). A call-only counter would let the REGISTER/OPTIONS
        // scanners run forever. This method is only ever invoked for THROTTLED_METHODS, so any call here
        // is a floodable request.
        $st['count']++;
        if ($st['count'] > $ceiling) {
            $st['strict'] = true;

            return true;
        }

        return false;
    }

    /**
     * Record one dropped (throttled) request for $ip and, at most once per FLOOD_ROLLUP_SECS, emit a
     * single 'call_flood' rollup event carrying the running suppressed count — so a flood of thousands
     * costs a handful of rows, not one per call, while the operator still sees the source and volume.
     */
    private function recordFloodDrop(string $ip, string $method): void
    {
        $now = microtime(true);

        if (!isset($this->floodState[$ip])) {
            if (count($this->floodState) >= self::CALL_BUCKET_MAX_IPS) {
                $oldestKey = null;
                $oldestAt = INF;
                foreach ($this->floodState as $k => $s) {
                    if ($s['lastLog'] < $oldestAt) {
                        $oldestAt = $s['lastLog'];
                        $oldestKey = $k;
                    }
                }
                if ($oldestKey !== null) {
                    unset($this->floodState[$oldestKey]);
                }
            }
            // First drop of a fresh flood: log it immediately so the incident's start is visible.
            $this->floodState[$ip] = ['count' => 1, 'since' => gmdate('c'), 'lastLog' => $now, 'method' => $method, 'lastLoggedCount' => 0];
            $this->emitFloodRollup($ip);

            return;
        }

        $st = &$this->floodState[$ip];
        $st['count']++;
        $st['method'] = $method;
        if (($now - $st['lastLog']) >= self::FLOOD_ROLLUP_SECS) {
            $st['lastLog'] = $now;
            $this->emitFloodRollup($ip);
        }
    }

    /**
     * Emit the residual (not-yet-rolled-up) drops for $ip before its flood state is cleared. Without this
     * the last <FLOOD_ROLLUP_SECS window of a flood is never logged, so the recorded suppressed-count
     * permanently undercounts by up to one rollup window. Call right before dropping the flood state.
     */
    private function flushFloodRollup(string $ip): void
    {
        if (isset($this->floodState[$ip]) && $this->floodState[$ip]['count'] > $this->floodState[$ip]['lastLoggedCount']) {
            $this->emitFloodRollup($ip);
        }
    }

    /** Emit one throttle rollup event. Never reportable: a throttled flood is pre-ACK and, over UDP,
     *  the source is unverifiable (possibly a spoofed victim) — reporting it would blame an innocent IP. */
    private function emitFloodRollup(string $ip): void
    {
        $st = &$this->floodState[$ip];
        $st['lastLoggedCount'] = $st['count'];
        $this->logEvent([
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'call_flood',
            'ip' => $ip,
            'port' => $this->currentPeerPort,
            'path' => "SIP flood throttled: {$st['count']} {$st['method']} request(s) dropped from {$ip} since {$st['since']}",
            'matched' => 1,
            'served' => 0,
            'reportable' => false,
        ]);
    }

    private function sessionKey(string $callId, string $peerIp, int $peerPort): string
    {
        return $callId . '@' . $peerIp . ':' . $peerPort;
    }

    private function countSessionsForIp(string $ip): int
    {
        $count = 0;
        foreach ($this->sessions as $s) {
            if ($s->peerIp === $ip) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Ends an active call session, writes the linear PCM .wav file, and logs the call_end event.
     */
    private function endSession(SipSession $s, string $sessionKey): void
    {
        $duration = round($s->getDuration(), 2);
        $pkts = $s->rtpPacketsSent;

        // Save the call audio as gzip'd 8kHz mu-law: mu-law is already half a PCM WAV, gzip then
        // collapses the long silence gaps (a scanner call shrinks to a few KB). The dashboard route
        // decompresses + expands to a playable WAV on request. Prune the dir so it can't fill disk.
        // Require CALLER-side audio before writing anything: scanners answer the handshake but send no
        // RTP, so a recording of only our persona + silence is zero intel and pure storage waste. Keep the
        // file only when the caller sent enough inbound audio (recordMinInboundBytes; 0 disables the gate).
        $inboundBytes = strlen($s->recordedInbound);
        $callerAudio = $this->config->recordMinInboundBytes <= 0
            ? ($inboundBytes > 0)
            : ($inboundBytes >= $this->config->recordMinInboundBytes);

        $recUrl = '';
        if ($this->config->recordCalls && $callerAudio && strlen($s->recordedUlaw) > 0) {
            // Cap the sanitized id length so an over-long attacker Call-ID can't exceed NAME_MAX.
            $recId = substr((string) preg_replace('/[^a-zA-Z0-9_-]/', '_', $s->callId), 0, 64);
            $filePath = $this->config->recordingsDir . '/' . $recId . '.ulaw.gz';
            @mkdir(dirname($filePath), 0777, true);
            if (@file_put_contents($filePath, (string) gzencode($s->recordedUlaw, 6)) !== false) {
                $recUrl = '/funnypot/recording?id=' . urlencode($recId);
                // Caller's channel — makes the served recording stereo (guaranteed non-empty here).
                @file_put_contents(
                    $this->config->recordingsDir . '/' . $recId . '.rx.ulaw.gz',
                    (string) gzencode($s->recordedInbound, 6)
                );
                $this->pruneRecordings();
            }
        }

        unset($this->sessions[$sessionKey]);

        $endEvent = [
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'call_end',
            'ip' => $s->peerIp,
            'port' => $s->peerPort,
            'path' => "SIP call ended: {$s->dialedNumber} ({$duration}s, {$pkts} pkts, persona: {$s->persona})"
                . ($this->config->recordCalls && !$callerAudio ? ', no caller audio (recording dropped)' : '')
                . ($s->dtmfDigits !== '' ? ", dtmf: {$s->dtmfDigits}" : ''),
            'matched' => 1,
            'served' => 1,
            'recording' => $recUrl,
            // FP-0247 anti-spoof: a session created by a spoofed INVITE (then reaped by setup-stall
            // eviction) or torn down by a spoofed BYE never passed the ACK To-tag check, so its source
            // is unverified over UDP — report only a return-routable TCP call or one that actually
            // streamed (wasStreaming latched at the validated ACK).
            'reportable' => ($s->transport === 'tcp') || $s->wasStreaming,
            // Attribution captured at INVITE — the ending event may fire from the idle loop with no
            // current request, so carry it from the session rather than from logEvent enrichment.
            'ua' => $s->userAgent,
            'tool' => $s->tool,
            'tells' => $s->transport === 'tcp' ? 'tcp(return-routable)' : 'udp(spoofable)',
        ];
        if ($s->dtmfDigits !== '') {
            $endEvent['dtmf'] = $s->dtmfDigits;
        }
        $this->logEvent($endEvent);
    }

    /**
     * Keeps the recordings dir under the configured cap by deleting the oldest files first, so a
     * flood of calls (rotating Call-IDs) can never exhaust the disk.
     */
    private function pruneRecordings(): void
    {
        $cap = $this->config->recordingsMaxBytes;
        if ($cap <= 0) {
            return;
        }
        // Glob each extension separately and merge: GLOB_BRACE is not defined on musl/Alpine (the
        // prod image), where using it is a fatal "undefined constant" that would kill the listener.
        // '*.ulaw' does not match '*.ulaw.gz' (different final extension), so there is no overlap.
        $files = array_merge(
            glob($this->config->recordingsDir . '/*.ulaw.gz') ?: [],
            glob($this->config->recordingsDir . '/*.ulaw') ?: [],
            glob($this->config->recordingsDir . '/*.wav') ?: []
        );
        if ($files === []) {
            return;
        }

        $sizes = [];
        $total = 0;
        foreach ($files as $f) {
            $sz = (int) @filesize($f);
            $sizes[$f] = $sz;
            $total += $sz;
        }
        if ($total <= $cap) {
            return;
        }

        usort($files, static fn (string $a, string $b): int => (int) @filemtime($a) <=> (int) @filemtime($b));
        foreach ($files as $f) {
            if ($total <= $cap) {
                break;
            }
            if (@unlink($f)) {
                $total -= $sizes[$f];
            }
        }
    }

    /**
     * The server-issued To-tag for an active dialog. A legitimate caller's ACK must echo it (that
     * check is what stops spoofed-INVITE RTP reflection); exposed so tests can build a valid ACK.
     */
    public function dialogToTag(string $callId, string $peerIp): ?string
    {
        $match = $this->findSessionByCallId($callId, $peerIp);

        return $match ? $match[1]->toTag : null;
    }

    /**
     * Deliver the held 200 OK for any ringing call whose randomized ring interval has elapsed. Held
     * here rather than sent inline at INVITE so the answer time varies call-to-call without the
     * select loop ever blocking on a sleep.
     */
    private function deliverPendingAnswers(): void
    {
        $now = microtime(true);
        foreach ($this->sessions as $s) {
            if ($s->answerAt <= 0.0 || $now < $s->answerAt) {
                continue;
            }
            try {
                $this->sendResponse($s->pendingOk, $s->peerIp, $s->peerPort, $s->transport, $s->tcpSocket);
                $s->state = SipSession::STATE_CONNECTED;
            } catch (\Throwable $e) {
                $this->logFault('answer', $e);
            }
            $s->answerAt = 0.0;
            $s->pendingOk = '';
        }
    }

    private function cleanupExpiredSessions(): void
    {
        $now = microtime(true);
        foreach ($this->sessions as $key => $s) {
            // Idle = time since the CALLER last sent us anything. A caller who hangs up without a
            // clean BYE stops sending RTP, so this fires and we stop recording — instead of running
            // to the max-duration cap and recording minutes of silence.
            $baseline = $s->lastInboundTime > 0.0 ? $s->lastInboundTime : $s->startTime;
            $idle = $now - $baseline;
            // A streaming call that has received ZERO caller RTP is a scanner that completed the
            // handshake but never spoke: we would otherwise stream a persona to no one until the full
            // idle cap. Drop it on a shorter clock so we free the slot + stop wasting CPU fast. A call
            // that DID send some audio then went quiet still uses the normal idle cap. 0 disables.
            $noAudio = $s->isStreaming() && $s->recordedInbound === '';
            $idleCap = ($noAudio && $this->config->callNoAudioTimeout > 0)
                ? $this->config->callNoAudioTimeout
                : $this->config->callIdleTimeout;
            // A never-ACKed INVITE never becomes "streaming", so the idle clause below can't reap it.
            // Evict it at the setup timeout so scan INVITEs can't exhaust the call table.
            $setupStalled = !$s->isStreaming() && ($now - $s->startTime) > self::INVITE_SETUP_TIMEOUT;
            if ($s->getDuration() > $this->config->maxCallDuration
                || ($s->isStreaming() && $idle > $idleCap)
                || $setupStalled) {
                try {
                    $this->endSession($s, $key);
                } catch (\Throwable $e) {
                    // Evict even if ending failed, so a poisoned session can't be retried forever.
                    $this->logFault('endSession', $e);
                    unset($this->sessions[$key]);
                }
            }
        }

        // Idle-close half-open / slowloris TCP clients that never completed a message.
        foreach ($this->tcpLastActivity as $id => $ts) {
            if ($now - $ts > self::TCP_IDLE_TIMEOUT) {
                if (isset($this->tcpClients[$id])) {
                    @fclose($this->tcpClients[$id]);
                }
                unset($this->tcpClients[$id], $this->tcpBuffers[$id], $this->tcpLastActivity[$id], $this->tcpPeers[$id]);
            }
        }

        // Clean nonces older than 300s. Entries are ['ip'=>..,'ts'=>..]; tolerate a legacy scalar too.
        $expireTime = time() - 300;
        foreach ($this->activeNonces as $nonce => $entry) {
            $ts = is_array($entry) ? (int) ($entry['ts'] ?? 0) : (int) $entry;
            if ($ts < $expireTime) {
                unset($this->activeNonces[$nonce]);
            }
        }
    }

    private function splitAddr(string $addr): array
    {
        $lastColon = strrpos($addr, ':');
        if ($lastColon !== false) {
            $ip = substr($addr, 0, $lastColon);
            $port = (int) substr($addr, $lastColon + 1);

            return [$ip, $port];
        }

        return [$addr, 5060];
    }

    private function getServerIp(): string
    {
        $ip = getenv('FUNNYPOT_PUBLIC_IP') ?: (getenv('FUNNYPOT_BIND_IP') ?: '127.0.0.1');

        return $ip === '0.0.0.0' ? '127.0.0.1' : $ip;
    }

    /**
     * The caller's User-Agent, trimmed and length-capped. This is inbound attacker data recorded as
     * threat intel; it is never echoed back to a client.
     */
    private function requestUserAgent(SipMessage $req): string
    {
        $ua = trim($req->getHeader('user-agent') ?? $req->getHeader('server') ?? '');

        return $ua === '' ? '' : substr($ua, 0, 128);
    }

    /**
     * Best-effort attribution of the SIP tool behind a request from its User-Agent. Purely for the
     * intel log — these needles match the ATTACKER's advertised client, never anything we emit.
     */
    private function classifyTool(SipMessage $req): string
    {
        $ua = strtolower($this->requestUserAgent($req));

        $map = [
            'friendly-scanner' => 'sipvicious',
            'friendly scanner' => 'sipvicious',
            'sipvicious'       => 'sipvicious',
            'sundayddr'        => 'sundayddr-wardialer',
            'sipcli'           => 'sipcli',
            'sip-scan'         => 'sip-scan',
            'sipscan'          => 'sip-scan',
            'pplsip'           => 'pplsip-scanner',
            'vaxsipuseragent'  => 'vaxsip-masscaller',
            'sipsak'           => 'sipsak',
            'iwar'             => 'iwar-wardialer',
            'warvox'           => 'warvox',
            'sipp'             => 'sipp',
            'nmap nse'         => 'nmap-sip',
            'nmap'             => 'nmap-sip',
            'zoiper'           => 'zoiper-softphone',
            'x-lite'           => 'softphone',
            'eyebeam'          => 'softphone',
            'microsip'         => 'softphone',
            'linphone'         => 'softphone',
            'pjsua'            => 'pjsip',
            'pjsip'            => 'pjsip',
            'asterisk'         => 'asterisk-relay',
            'freeswitch'       => 'freeswitch-relay',
            'kamailio'         => 'kamailio-relay',
            'opensips'         => 'opensips-relay',
        ];
        foreach ($map as $needle => $tool) {
            if ($ua !== '' && strpos($ua, $needle) !== false) {
                return $tool;
            }
        }

        // No usable User-Agent match — fall back to a wire signature. Major SIP scanners either omit the
        // UA (SIPVicious PRO) or let the operator change it, but their shared request builders stamp fixed
        // structural tells that survive a UA swap. Catch those so the probes still classify + stand out.
        $wire = $this->classifyByWireSignature($req);
        if ($wire !== null) {
            return $wire;
        }

        return $ua === '' ? 'unknown' : 'other';
    }

    /**
     * UA-independent SIP-scanner classification from fixed structural signatures. Each check is a
     * high-confidence literal a real client never emits, so false positives are negligible:
     *  - Metasploit SIP mixin: a hardcoded From-tag `70c00e8c` on every probe.
     *  - SIPVicious family (OSS + PRO): From/To domain 1.1.1.1 (To echoes From), a `"sipvicious"` display
     *    name, or a Via branch `z9hG4bK-` followed by pure decimals (random.getrandbits(32)).
     *  - sippts (Pepelux): a long lowercase-alnum Via branch with NO z9hG4bK cookie + a bare 32-hex Call-ID;
     *    OR the fixed 13-method Allow list; OR the SDP session name s=SIPPTS (the latter two survive both a
     *    -ua override and a fuzzed branch).
     */
    private function classifyByWireSignature(SipMessage $req): ?string
    {
        $via = (string) ($req->getHeader('via') ?? '');
        $from = strtolower((string) ($req->getHeader('from') ?? ''));
        $to = strtolower((string) ($req->getHeader('to') ?? ''));

        // Metasploit: fixed From-tag literal (1-in-4-billion by chance) present on every SIP module probe.
        if (strpos($from, 'tag=70c00e8c') !== false) {
            return 'metasploit-sip';
        }

        // SIPVicious OSS/PRO: distinctive From identity or the pure-decimal branch suffix.
        if (strpos($from, '"sipvicious"') !== false
            || (strpos($from, '@1.1.1.1') !== false && strpos($to, '@1.1.1.1') !== false)
            || preg_match('/branch=z9hG4bK-\d{6,}(?:[;>\s]|$)/i', $via) === 1) {
            return 'sipvicious';
        }

        // sippts: a hard RFC-3261 violation — no z9hG4bK cookie, a long lowercase-alnum branch, and a bare
        // 32-hex Call-ID (no @host).
        if ($via !== '' && stripos($via, 'z9hG4bK') === false
            && preg_match('/branch=[a-z0-9]{40,}/', $via) === 1
            && preg_match('/^[a-f0-9]{32}$/', trim((string) ($req->getHeader('call-id') ?? ''))) === 1) {
            return 'pplsip-scanner';
        }

        // sippts, UA- and branch-independent: its shared builder stamps two fixed constants a real client
        // never emits — the exact 13-method Allow list (this order) and the SDP session name s=SIPPTS.
        // These survive both a -ua override and a fuzzed branch, so they catch runs the checks above miss.
        $allowNorm = strtolower((string) preg_replace('/\s+/', '', (string) ($req->getHeader('allow') ?? '')));
        if ($allowNorm === 'invite,register,ack,cancel,bye,notify,refer,options,info,subscribe,update,prack,message') {
            return 'pplsip-scanner';
        }
        if (stripos($req->body, 's=SIPPTS') !== false) {
            return 'pplsip-scanner';
        }

        return null;
    }

    /**
     * Transport-layer tells that separate an automated flooder from a real softphone: spoofability
     * of the transport, whether the Via carries the RFC 3261 branch cookie / rport, a missing
     * Contact, and a source port pinned to 5060 (tools bind it; softphones use an ephemeral port).
     * @return list<string>
     */
    private function transportTells(SipMessage $req, string $transport, int $peerPort): array
    {
        $tells = [];
        $tells[] = $transport === 'tcp' ? 'tcp(return-routable)' : 'udp(spoofable)';

        $via = $req->getVia() ?? '';
        if ($via === '') {
            $tells[] = 'no-via';
        } elseif (stripos($via, 'z9hG4bK') === false) {
            $tells[] = 'pre-rfc3261-branch';
        }
        if (stripos($via, ';rport') === false) {
            $tells[] = 'no-rport';
        }
        if (trim($req->getHeader('contact') ?? '') === '') {
            $tells[] = 'no-contact';
        }
        if ($peerPort === 5060) {
            $tells[] = 'src-port-5060';
        }

        return $tells;
    }

    /**
     * Decode one inbound RTP telephone-event packet (RFC 4733) and record the key-press. A single
     * key spans many packets sharing one RTP timestamp, so timestamp-dedup logs each digit once.
     */
    private function captureRtpDtmf(SipSession $s, string $payload, int $timestamp): void
    {
        if (strlen($payload) < 1 || $timestamp === $s->lastDtmfTs) {
            return;
        }
        $eventCode = ord($payload[0]);
        if (!isset(self::DTMF_EVENTS[$eventCode])) {
            return;
        }
        $s->lastDtmfTs = $timestamp;
        $digit = self::DTMF_EVENTS[$eventCode];
        $s->dtmfDigits .= $digit;

        $this->logEvent([
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'dtmf',
            'ip' => $s->peerIp,
            'port' => $s->peerPort,
            'path' => "SIP DTMF '{$digit}' on call {$s->dialedNumber} (rfc4733 rtp-event)",
            'matched' => 1,
            'served' => 1,
            'reportable' => true,
            'ua' => $s->userAgent,
            'tool' => $s->tool,
            'tells' => $s->transport === 'tcp' ? 'tcp(return-routable)' : 'udp(spoofable)',
        ]);
    }

    /**
     * Capture DTMF signalled out of band via SIP INFO — both application/dtmf-relay ("Signal=5")
     * and application/dtmf (a bare digit). The digit is appended to the matching session, if any.
     */
    private function captureInfoDtmf(SipMessage $req, string $peerIp, int $peerPort, string $transport): void
    {
        $ctype = strtolower($req->getHeader('content-type') ?? '');
        if (strpos($ctype, 'dtmf') === false) {
            return;
        }

        $body = $req->body;
        $digit = '';
        if (preg_match('/Signal\s*=\s*([0-9A-Da-d*#])/', $body, $m)) {
            $digit = strtoupper($m[1]);
        } elseif (preg_match('/^\s*([0-9A-Da-d*#])\s*$/', $body, $m)) {
            $digit = strtoupper($m[1]);
        }
        if ($digit === '') {
            return;
        }

        // Attribute the digit to a matching dialog if there is one, and bound a post-call INFO burst:
        // once a full DTMF sequence is captured on an admitted dialog, stop logging + buffering the tail
        // (FP-0218 — a real sequence is far shorter than the cap; the tail is a flood we gain nothing from).
        // A bare/off-dialog INFO (no session) is still logged as intel, but the reportable gate below keeps
        // a lone spoofable datagram from blaming a forged source.
        $match = $this->findSessionByCallId($req->getCallId() ?? '', $peerIp);
        $streaming = false;
        if ($match) {
            [, $s] = $match;
            if (strlen($s->dtmfDigits) >= self::DTMF_MAX_DIGITS) {
                return; // full sequence already captured; ignore the in-dialog flood tail silently
            }
            $s->dtmfDigits .= $digit;
            $streaming = $s->isStreaming();
        }

        $this->logEvent([
            'proto' => 'sip',
            'method' => 'SIP',
            'event' => 'dtmf',
            'ip' => $peerIp,
            'port' => $peerPort,
            'path' => "SIP DTMF '{$digit}' via INFO ({$ctype})",
            'matched' => 1,
            'served' => 1,
            // FP-0247 anti-spoof: a lone forged INFO carrying a DTMF body is one spoofable UDP
            // datagram — reporting it would blame the forged source. Report only over return-routable
            // TCP, or when the INFO belongs to a call that passed the ACK To-tag check and is streaming.
            'reportable' => ($transport === 'tcp') || $streaming,
        ]);
    }

    private function logEvent(array $event): void
    {
        // UTC ISO-8601 timestamp on every event, matching the other emulators' envelope so the
        // dashboard can render a time for SIP hits.
        $event['ts'] = gmdate('c');

        // Enrich every per-message event with attacker attribution + transport tells, unless the
        // caller already set them (session-derived events like call_end / dtmf carry their own).
        if ($this->currentReq !== null) {
            if (!array_key_exists('ua', $event)) {
                $event['ua'] = $this->requestUserAgent($this->currentReq);
            }
            if (!array_key_exists('tool', $event)) {
                $event['tool'] = $this->classifyTool($this->currentReq);
            }
            if (!array_key_exists('tells', $event)) {
                $event['tells'] = implode(',', $this->transportTells($this->currentReq, $this->currentTransport, $this->currentPeerPort));
            }
        }

        // Never report a placeholder source. An empty/loopback IP means peer resolution failed;
        // reporting it would attribute the attack to an innocent or local address.
        if (($event['reportable'] ?? false) && !$this->isReportableIp((string) ($event['ip'] ?? ''))) {
            $event['reportable'] = false;
        }

        if ($this->logger) {
            ($this->logger)($event);
        }
    }

    /**
     * Whether a source IP is safe to report. An empty/placeholder/loopback address means peer
     * resolution failed, so it must never reach the reporter.
     */
    private function isReportableIp(string $ip): bool
    {
        if ($ip === '' || strtolower($ip) === 'unknown') {
            return false;
        }

        return $ip !== '::1' && strncmp($ip, '127.', 4) !== 0;
    }

    public function getActiveSessionCount(): int
    {
        return count($this->sessions);
    }
}

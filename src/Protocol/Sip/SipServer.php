<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

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

    /** Ceilings that stop a TCP flood / slowloris from exhausting fds or memory. */
    private const MAX_TCP_CLIENTS = 128;
    private const MAX_TCP_BUFFER = 16384;
    private const TCP_IDLE_TIMEOUT = 30.0;

    /** @var array<string, SipSession> Active sessions keyed by callId + peerAddr */
    private array $sessions = [];

    /** @var array<string, string> Nonce store: nonce => issued timestamp */
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
        ?CredentialStore $credStore = null
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
                if ($sock === $this->udpSocket) {
                    $this->handleInboundUdp();
                } elseif ($sock === $rtpSock) {
                    $this->handleInboundRtp();
                } elseif ($sock === $this->tcpSocket) {
                    $this->handleTcpAccept();
                } else {
                    $this->handleInboundTcp($sock);
                }
            }
        }

        // Drive RTP media streaming timers
        $this->tickRtpStreams();

        // Evict expired calls and nonces
        $this->cleanupExpiredSessions();
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
        $req = SipMessage::parse($data);
        if (!$req) {
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
            if (count($this->tcpClients) >= self::MAX_TCP_CLIENTS) {
                @fclose($client); // at capacity — refuse (fd-exhaustion guard)

                return;
            }
            stream_set_blocking($client, false);
            $id = (int) $client;
            $this->tcpClients[$id] = $client;
            $this->tcpBuffers[$id] = '';
            $this->tcpLastActivity[$id] = microtime(true);
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
            unset($this->tcpClients[$id], $this->tcpBuffers[$id], $this->tcpLastActivity[$id]);

            return;
        }

        $this->tcpLastActivity[$id] = microtime(true);
        $this->tcpBuffers[$id] .= $chunk;

        // Slowloris guard: a client dribbling data with no complete SIP message is dropped rather
        // than buffered without bound.
        if (strlen($this->tcpBuffers[$id]) > self::MAX_TCP_BUFFER) {
            @fclose($sock);
            unset($this->tcpClients[$id], $this->tcpBuffers[$id], $this->tcpLastActivity[$id]);

            return;
        }

        $buf = $this->tcpBuffers[$id];

        // Attempt to parse complete SIP message
        $req = SipMessage::parse($buf);
        if ($req) {
            $name = stream_socket_get_name($sock, true);
            [$peerIp, $peerPort] = $name ? $this->splitAddr($name) : ['127.0.0.1', 5060];
            $this->dispatchMessage($req, $peerIp, $peerPort, 'tcp', $sock);

            // Clear buffer up to parsed length if Content-Length accounted for
            $this->tcpBuffers[$id] = '';
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
                $this->captureInfoDtmf($req, $peerIp, $peerPort);
                $res = $req->buildOk('tag-' . bin2hex(random_bytes(3)), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
                $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);
                break;

            default:
                // Return 200 OK for other discovery methods (NOTIFY, etc.)
                $res = $req->buildOk('tag-' . bin2hex(random_bytes(3)), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
                $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);
                break;
        }
    }

    /**
     * RFC 3261 OPTIONS scanner probe handler.
     */
    private function handleOptions(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        $res = $req->buildOk('tag-' . bin2hex(random_bytes(3)), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
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
        $toTag = 'tag-' . bin2hex(random_bytes(3));
        $contact = $req->getHeader('contact') ?? "<sip:{$peerIp}:{$peerPort}>";

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
            $this->activeNonces[$nonce] = (string) time();

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

        // Verify nonce was issued by us (proves two-way round-trip!)
        $validRoundTrip = isset($this->activeNonces[$nonce]) || $transport === 'tcp';

        // Check if password matches a weak/default password
        // Smart Credential Latching:
        // If an IP has already latched a working password for this extension, enforce that password strictly!
        // Conflicting password attempts are rejected with 403 Forbidden so svcrack sees only 1 valid password.
        if ($this->config->latchPasswords && $this->credStore->hasLatched($peerIp, $user)) {
            // Same credential if the latched plaintext re-verifies against THIS request's nonce/nc
            // (a real softphone re-REGISTERs with the same password but a fresh nonce/nc, so a raw
            // response-hash compare would spuriously reject it), or — for an uncrackable permissive
            // password we could only store as its hash — if the exact response repeats.
            $latched = $this->credStore->getLatched($peerIp, $user);
            $sameCredential = $latched !== null
                && (SipMessage::verifyDigest($auth, $latched, $req->method) || hash_equals($latched, $responseHash));

            if ($sameCredential) {
                // Re-authentication using the latched password succeeds!
                $res = $req->buildRegisteredOk($toTag, $contact, 3600, $this->config->userAgent);
                $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

                $this->logEvent([
                    'proto' => 'sip',
                    'method' => 'SIP',
                    'event' => 'login',
                    'ip' => $peerIp,
                    'port' => $peerPort,
                    'path' => "SIP REGISTER ext:{$user} (latched credentials verified)",
                    'matched' => 1,
                    'served' => 1,
                    'reportable' => $validRoundTrip,
                ]);

                return;
            }

            // Conflicting password attempted on an already cracked extension!
            // Reject with 403 Forbidden
            $res = $req->buildForbidden($toTag, $this->config->userAgent);
            $this->sendResponse($res, $peerIp, $peerPort, $transport, $tcpSock);

            $this->logEvent([
                'proto' => 'sip',
                'method' => 'SIP',
                'event' => 'login',
                'ip' => $peerIp,
                'port' => $peerPort,
                'path' => "SIP REGISTER ext:{$user} REJECTED conflicting password attempt (hash: {$responseHash})",
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
            $accepted = true;
            // Check if it matched a known default for richer logging
            if (SipMessage::verifyDigest($auth, $user, $req->method)) {
                $matchedPass = $user;
            } else {
                foreach ($this->config->defaultPasswords as $cand) {
                    if (SipMessage::verifyDigest($auth, $cand, $req->method)) {
                        $matchedPass = $cand;
                        break;
                    }
                }
            }
            if ($matchedPass === '') {
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
     * RFC 3261 INVITE toll-fraud call & tarpit setup.
     */
    private function handleInvite(SipMessage $req, string $peerIp, int $peerPort, string $transport, $tcpSock): void
    {
        $callId = $req->getCallId() ?? ('call-' . bin2hex(random_bytes(4)));
        $sessionKey = $this->sessionKey($callId, $peerIp, $peerPort);

        // Anti-Reflection & Bandwidth Limiting (B1): Enforce concurrency ceilings
        $activeCount = count($this->sessions);
        $perIpCount = $this->countSessionsForIp($peerIp);

        if ($activeCount >= $this->config->maxActiveCalls || $perIpCount >= $this->config->perIpCalls) {
            // Reject call with 486 Busy Here
            $res = $req->buildBusy('busy-' . bin2hex(random_bytes(3)), $this->config->userAgent);
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
        $s->state = SipSession::STATE_CONNECTED;

        $this->sessions[$sessionKey] = $s;

        // 3. Build and send 200 OK with our SDP descriptor
        $serverIp = $this->getServerIp();
        $localRtpPort = $this->rtpStreamer->getLocalPort();
        $sdp = SipMessage::buildSdp($serverIp, $localRtpPort, '1', $this->config->userAgent);

        $contact = "<sip:{$dialedNumber}@{$serverIp}:5060>";
        $ok = $req->buildOk($s->toTag, $contact, $sdp, [], $this->config->userAgent);
        $this->sendResponse($ok, $peerIp, $peerPort, $transport, $tcpSock);

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

        $res = $req->buildOk('bye-' . bin2hex(random_bytes(3)), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
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
        $ok = $req->buildOk('cancel-' . bin2hex(random_bytes(3)), "<sip:{$this->getServerIp()}:5060>", '', [], $this->config->userAgent);
        $this->sendResponse($ok, $peerIp, $peerPort, $transport, $tcpSock);

        // 2. 487 Request Terminated for the INVITE
        $term = $req->buildResponse(487, 'Request Terminated', 'term-' . bin2hex(random_bytes(3)), [], '', $this->config->userAgent);
        $this->sendResponse($term, $peerIp, $peerPort, $transport, $tcpSock);

        if ($match) {
            [$sessionKey] = $match;
            unset($this->sessions[$sessionKey]);
        }
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
        }
    }

    /**
     * Sends a SIP response over UDP or TCP.
     */
    private function sendResponse(string $raw, string $peerIp, int $peerPort, string $transport, $tcpSock = null): void
    {
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
        $recUrl = '';
        if ($this->config->recordCalls && strlen($s->recordedUlaw) > 0) {
            // Cap the sanitized id length so an over-long attacker Call-ID can't exceed NAME_MAX.
            $recId = substr((string) preg_replace('/[^a-zA-Z0-9_-]/', '_', $s->callId), 0, 64);
            $filePath = $this->config->recordingsDir . '/' . $recId . '.ulaw.gz';
            @mkdir(dirname($filePath), 0777, true);
            if (@file_put_contents($filePath, (string) gzencode($s->recordedUlaw, 6)) !== false) {
                $recUrl = '/funnypot/recording?id=' . urlencode($recId);
                // Caller's channel (if they sent any audio) — makes the served recording stereo.
                if ($s->recordedInbound !== '') {
                    @file_put_contents(
                        $this->config->recordingsDir . '/' . $recId . '.rx.ulaw.gz',
                        (string) gzencode($s->recordedInbound, 6)
                    );
                }
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
                . ($s->dtmfDigits !== '' ? ", dtmf: {$s->dtmfDigits}" : ''),
            'matched' => 1,
            'served' => 1,
            'recording' => $recUrl,
            'reportable' => true,
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

    private function cleanupExpiredSessions(): void
    {
        $now = microtime(true);
        foreach ($this->sessions as $key => $s) {
            // Idle = time since the CALLER last sent us anything. A caller who hangs up without a
            // clean BYE stops sending RTP, so this fires and we stop recording — instead of running
            // to the max-duration cap and recording minutes of silence.
            $baseline = $s->lastInboundTime > 0.0 ? $s->lastInboundTime : $s->startTime;
            $idle = $now - $baseline;
            if ($s->getDuration() > $this->config->maxCallDuration || ($s->isStreaming() && $idle > $this->config->callIdleTimeout)) {
                $this->endSession($s, $key);
            }
        }

        // Idle-close half-open / slowloris TCP clients that never completed a message.
        foreach ($this->tcpLastActivity as $id => $ts) {
            if ($now - $ts > self::TCP_IDLE_TIMEOUT) {
                if (isset($this->tcpClients[$id])) {
                    @fclose($this->tcpClients[$id]);
                }
                unset($this->tcpClients[$id], $this->tcpBuffers[$id], $this->tcpLastActivity[$id]);
            }
        }

        // Clean nonces older than 300s
        $expireTime = time() - 300;
        foreach ($this->activeNonces as $nonce => $ts) {
            if ((int) $ts < $expireTime) {
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
        if ($ua === '') {
            return 'unknown'; // Many scanners send no User-Agent at all.
        }

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
            if (strpos($ua, $needle) !== false) {
                return $tool;
            }
        }

        return 'other';
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
    private function captureInfoDtmf(SipMessage $req, string $peerIp, int $peerPort): void
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

        $match = $this->findSessionByCallId($req->getCallId() ?? '', $peerIp);
        if ($match) {
            [, $s] = $match;
            $s->dtmfDigits .= $digit;
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
            'reportable' => true,
        ]);
    }

    private function logEvent(array $event): void
    {
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

        if ($this->logger) {
            ($this->logger)($event);
        }
    }

    public function getActiveSessionCount(): int
    {
        return count($this->sessions);
    }
}

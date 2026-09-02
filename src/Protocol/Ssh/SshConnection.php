<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

use Funnypot\Protocol\MalformedStream;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\HostKey\HostKeySet;
use Funnypot\Protocol\Ssh\Kex\KexAlgorithm;
use Funnypot\Protocol\Ssh\Kex\KexSuite;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Shell\FakeShell;
use Funnypot\Protocol\TrollStream;

/**
 * One attacker's SSH-2.0 session, driven purely by inbound bytes. It walks the transport handshake
 * (version exchange → KEXINIT → the negotiated kex → NEWKEYS), accepts any login (a honeypot wants
 * attackers in, not out), and opens a session channel whose shell is the shared {@see FakeShell} —
 * the very same fake shell telnet uses, so a real `ssh` client lands at a believable prompt with
 * every command logged. An optional anti-fingerprint reject (off by default; see the constructor)
 * can refuse a seeded few early guesses to dodge the 100%-success tell.
 *
 * Honeypot invariants hold end to end: attacker input is decrypted and matched, never executed;
 * every credential and offered key is logged (rejected guesses included — that intel is the point);
 * nothing is fetched. The class is transport-only I/O — it never touches the socket. The caller
 * feeds bytes in and drains queued bytes out, so it composes with a non-blocking select loop.
 *
 * Handshake shape mirrors a real sshd: our KEXINIT follows the client's identification line (not
 * before it); when the client offers ext-info-c we send SSH_MSG_EXT_INFO as the first encrypted
 * packet after NEWKEYS; and, when strict kex is mutually agreed, each direction's sequence number
 * resets at its NEWKEYS with the strict "unexpected packet" discipline enforced during the initial
 * kex. The served KEXINIT name-lists are byte-identical to before, so the strict-kex reset ships
 * dormant (we do not advertise kex-strict-s until FP-0291) — EXT_INFO and the ordering go live now.
 */
final class SshConnection
{
    // Transport messages (RFC 4253 / 4252 / 4254).
    private const MSG_DISCONNECT = 1;
    private const MSG_IGNORE = 2;
    private const MSG_UNIMPLEMENTED = 3;
    private const MSG_DEBUG = 4;
    private const MSG_SERVICE_REQUEST = 5;
    private const MSG_SERVICE_ACCEPT = 6;
    private const MSG_EXT_INFO = 7;
    private const MSG_KEXINIT = 20;
    private const MSG_NEWKEYS = 21;
    // 30 is shared by KEX_ECDH_INIT / KEXDH_INIT / (unsupported) GEX_REQUEST_OLD — routed by the
    // negotiated kex object, never decoded here. 32/34 are the two GEX inbound messages we route.
    private const MSG_KEX_ECDH_INIT = 30;
    private const MSG_KEX_ECDH_REPLY = 31;
    private const MSG_KEX_DH_GEX_INIT = 32;
    private const MSG_KEX_DH_GEX_REQUEST = 34;
    private const MSG_USERAUTH_REQUEST = 50;
    private const MSG_USERAUTH_FAILURE = 51;
    private const MSG_USERAUTH_SUCCESS = 52;
    private const MSG_GLOBAL_REQUEST = 80;
    private const MSG_REQUEST_FAILURE = 82;
    private const MSG_CHANNEL_OPEN = 90;
    private const MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    private const MSG_CHANNEL_OPEN_FAILURE = 92;
    private const MSG_CHANNEL_WINDOW_ADJUST = 93;
    private const MSG_CHANNEL_DATA = 94;
    private const MSG_CHANNEL_EOF = 96;
    private const MSG_CHANNEL_CLOSE = 97;
    private const MSG_CHANNEL_REQUEST = 98;
    private const MSG_CHANNEL_SUCCESS = 99;
    private const MSG_CHANNEL_FAILURE = 100;

    private const MAX_IN = 262144;      // hard cap on unconsumed inbound bytes
    private const MAX_AUTH_TRIES = 24;  // bound credential spraying per connection
    private const INITIAL_WINDOW = 1 << 21;
    private const MAX_PACKET = 32768;

    private const KEX_ALGOS = ['curve25519-sha256', 'curve25519-sha256@libssh.org'];
    private const HOSTKEY_ALGOS = ['ssh-ed25519'];
    private const CIPHERS = ['aes256-ctr'];
    private const MACS = ['hmac-sha2-256'];

    // The server-sig-algs value a real OpenSSH 8.9p1 advertises in SSH_MSG_EXT_INFO —
    // sshkey_alg_list(0, 1, 1) with ENABLE_SK and without WITH_XMSS (the Ubuntu build). A literal
    // constant, identical for every connection, never derived from attacker bytes and not in HASSH.
    // FP-0291: per-profile (8.7 has no publickey-hostbound and only nr=1).
    private const SERVER_SIG_ALGS = 'ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com';

    private Transport $transport;
    private string $in = '';
    private string $out = '';
    private bool $closed = false;
    private bool $closeAfterFlush = false;

    private bool $gotVersion = false;
    private string $clientVersion = '';
    private string $serverKexInit = '';
    private string $clientKexInit = '';
    private ?KexAlgorithm $kex = null;
    /** @var array{ivC2S:string,ivS2C:string,keyC2S:string,keyS2C:string,macC2S:string,macS2C:string}|null */
    private ?array $keys = null;

    // Handshake-shape state, all set during the initial kex (M1: never recomputed from a rekey
    // KEXINIT). $advertisesStrictKex reflects whether our served kex list carries kex-strict-s — the
    // two-sided gate (PROTOCOL §1.9): a client's counters reset only if WE advertised, so with the
    // list unchanged this stays false and the reset never fires (dormant until FP-0291).
    private bool $advertisesStrictKex;
    private bool $strictKex = false;      // strict kex mutually agreed (this connection)
    private bool $wantExtInfo = false;    // client offered ext-info-c → send EXT_INFO after NEWKEYS
    private bool $initialKexDone = false; // cleared-KEX_INITIAL equivalent: set once client NEWKEYS is consumed

    private bool $authed = false;
    private int $authTries = 0;
    private int $passwordTries = 0;
    private int $authRejectK;          // password guesses to reject before accepting; seeded per attacker

    private ?int $channel = null;      // client's channel id, once a session is open
    private int $clientWindow = 0;
    private int $clientMaxPacket = self::MAX_PACKET;
    private int $localWindow = self::INITIAL_WINDOW;
    private bool $shellOpen = false;
    private string $lineBuf = '';
    private bool $swallowLf = false;
    private bool $trolling = false;    // taunt mode: streaming the troll animation, shell frozen
    private int $trollFrame = 0;
    private ?FakeShell $shell = null;

    /**
     * @param callable(string,string):void $logger           ($event, $detail)
     * @param int                          $authRejectBudget  Opt-in anti-fingerprint reject. Default
     *        0 = pure accept-all: every login succeeds first try, which is what a honeypot wants —
     *        let attackers in and watch them. Set > 0 to trade some welcome for evading the
     *        ssh-default-logins "100% success" tell: K in {0..budget}, seeded per attacker, is the
     *        number of early password guesses refused (real "Permission denied, please try again")
     *        before auth is accepted. Every attempt, rejected ones included, is still logged.
     */
    public function __construct(
        private HostKeySet $hostKeys,
        private ProtocolSession $session,
        private $logger,
        private string $serverVersion = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
        int $authRejectBudget = 0,
        private ?int $identitySeed = null,
        private ?string $secret = null
    ) {
        $this->transport = new Transport();
        // Two-sided strict-kex gate reads the SAME array buildKexInit() serializes, so the gate can
        // never disagree with the served bytes. False today (no marker in KEX_ALGOS) → dormant.
        // FP-0291: compute from the profile's kex list at the point it is serialized, never a second source.
        $this->advertisesStrictKex = in_array(KexSuite::KEX_STRICT_S, self::KEX_ALGOS, true);
        // Seed the reject count per attacker so a source sees a stable K, not a per-attempt coin
        // flip. Timing realism (a human-like pause before the verdict) is intentionally not done
        // here: this engine is one shared non-blocking select loop, so any sleep would stall every
        // other connection — that belongs in a future per-connection timer, not a blocking wait.
        $this->authRejectK = $authRejectBudget > 0
            ? abs($this->session->seed) % ($authRejectBudget + 1)
            : 0;
    }

    /** Queue the identification line only; our KEXINIT follows once the client's line is read, as sshd does. */
    public function onConnect(): void
    {
        $this->out .= $this->serverVersion . "\r\n";
    }

    /** Feed raw inbound bytes; advances the state machine and queues any response bytes. */
    public function feed(string $bytes): void
    {
        if ($this->closed) {
            return;
        }
        $this->in .= $bytes;
        if (strlen($this->in) > self::MAX_IN) {
            $this->disconnect('buffer cap');

            return;
        }
        try {
            if (!$this->gotVersion && !$this->readVersion()) {
                return;
            }
            while (!$this->closed && ($payload = $this->transport->next($this->in)) !== null) {
                if ($payload !== '') {
                    $this->handle($payload);
                }
            }
        } catch (\Throwable $e) {
            $this->disconnect('protocol error');
        }
    }

    /** Drain queued outbound bytes (the caller writes them to the socket). */
    public function takeOut(): string
    {
        $out = $this->out;
        $this->out = '';

        return $out;
    }

    public function isClosed(): bool
    {
        return $this->closed;
    }

    /** True once every queued byte is written and the socket should be closed. */
    public function shouldClose(): bool
    {
        return $this->closeAfterFlush && $this->out === '';
    }

    private function readVersion(): bool
    {
        $pos = strpos($this->in, "\n");
        if ($pos === false) {
            if (strlen($this->in) > 512) {
                $this->disconnect('no identification');
            }

            return false;
        }
        $line = substr($this->in, 0, $pos);
        $this->in = substr($this->in, $pos + 1);
        $this->clientVersion = rtrim($line, "\r\n");
        if (strncmp($this->clientVersion, 'SSH-2.0-', 8) !== 0 && strncmp($this->clientVersion, 'SSH-1.99-', 9) !== 0) {
            $this->disconnect('unsupported protocol');

            return false;
        }
        $this->gotVersion = true;
        $this->log('connect', $this->clientVersion);
        // Queue our KEXINIT now, after the client's identification line — real-sshd ordering. Set
        // before any packet can be handled (feed() returns until gotVersion), so negotiate() sees it.
        $this->serverKexInit = $this->buildKexInit();
        $this->out .= $this->transport->frame($this->serverKexInit);

        return true;
    }

    private function handle(string $payload): void
    {
        $msg = ord($payload[0]);
        // Strict-kex packet discipline (PROTOCOL §1.9(a); OpenSSH packet.c:1741-1749 / kex_protocol_error):
        // during the initial kex under strict mode only the kex messages (and DISCONNECT) may appear —
        // IGNORE/DEBUG/UNIMPLEMENTED, silently tolerated otherwise, are a violation. Gated on the initial
        // kex only (M1: a later rekey KEXINIT ignores the markers). Dormant until FP-0291.
        if ($this->strictKex && !$this->initialKexDone && !$this->allowedDuringStrictKex($msg)) {
            $this->disconnect('strict kex violation');

            return;
        }
        switch ($msg) {
            case self::MSG_KEXINIT:
                $this->clientKexInit = $payload;
                $this->negotiate($payload);
                break;
            case self::MSG_KEX_ECDH_INIT:        // 30 — also KEXDH_INIT / (unsupported) GEX_REQUEST_OLD
            case self::MSG_KEX_DH_GEX_INIT:      // 32
            case self::MSG_KEX_DH_GEX_REQUEST:   // 34
                $this->kexMessage($msg, $payload);
                break;
            case self::MSG_NEWKEYS:
                // The client's NEWKEYS is the last plaintext inbound packet; only now does the
                // receive side switch to ciphertext, using the client->server keys from the kex.
                // Under strict kex the inbound sequence number resets to 0 with the switch (the
                // packet just consumed was the client's NEWKEYS), so its next packet opens at 0.
                if ($this->keys !== null) {
                    $this->transport->enableRecv(CipherSuite::build(
                        'aes256-ctr',
                        'hmac-sha2-256',
                        $this->keys['keyC2S'],
                        $this->keys['ivC2S'],
                        $this->keys['macC2S']
                    ), $this->strictKex);
                    // The initial kex is complete (sshd clears KEX_INITIAL in kex_input_newkeys);
                    // strict discipline and marker parsing no longer apply to later packets.
                    $this->initialKexDone = true;
                }
                break;
            case self::MSG_SERVICE_REQUEST:
                $this->serviceRequest($payload);
                break;
            case self::MSG_USERAUTH_REQUEST:
                $this->userAuth($payload);
                break;
            case self::MSG_CHANNEL_OPEN:
                $this->channelOpen($payload);
                break;
            case self::MSG_CHANNEL_REQUEST:
                $this->channelRequest($payload);
                break;
            case self::MSG_CHANNEL_DATA:
                $this->channelData($payload);
                break;
            case self::MSG_CHANNEL_EOF:
            case self::MSG_CHANNEL_WINDOW_ADJUST:
            case self::MSG_IGNORE:
            case self::MSG_DEBUG:
            case self::MSG_UNIMPLEMENTED:
            case self::MSG_EXT_INFO:
                // A client only sends EXT_INFO if we advertised ext-info-s (we do not); parse-and-
                // ignore it as sshd does rather than answering UNIMPLEMENTED via default:.
                break;
            case self::MSG_CHANNEL_CLOSE:
                if ($this->channel !== null) {
                    $this->send((new Buf())->byte(self::MSG_CHANNEL_CLOSE)->uint32($this->channel)->get());
                }
                $this->disconnect('channel closed');
                break;
            case self::MSG_GLOBAL_REQUEST:
                $this->globalRequest($payload);
                break;
            case self::MSG_DISCONNECT:
                $this->disconnect('client disconnect');
                break;
            default:
                // Unknown/unsupported message — acknowledge per spec, stay up.
                $this->sendUnimplemented();
        }
    }

    /**
     * SSH_MSG_UNIMPLEMENTED (RFC 4253 §11.4). The uint32 is the offending packet's sequence number —
     * the sequence number of the packet most recently pulled by the transport, as a real sshd sends.
     */
    private function sendUnimplemented(): void
    {
        $this->send((new Buf())->byte(self::MSG_UNIMPLEMENTED)->uint32($this->transport->lastInSeq())->get());
    }

    private function buildKexInit(): string
    {
        return (new Buf())
            ->byte(self::MSG_KEXINIT)
            ->raw(random_bytes(16))            // cookie
            ->nameList(self::KEX_ALGOS)
            ->nameList(self::HOSTKEY_ALGOS)
            ->nameList(self::CIPHERS)           // encryption client->server
            ->nameList(self::CIPHERS)           // encryption server->client
            ->nameList(self::MACS)              // mac client->server
            ->nameList(self::MACS)              // mac server->client
            ->nameList(['none'])                // compression client->server
            ->nameList(['none'])                // compression server->client
            ->nameList([])                      // languages client->server
            ->nameList([])                      // languages server->client
            ->bool(false)                       // first_kex_packet_follows
            ->uint32(0)                         // reserved
            ->get();
    }

    private function negotiate(string $payload): void
    {
        // Skip the message byte and the 16-byte cookie; the algorithm name-lists follow.
        if (strlen($payload) < 17) {
            $this->disconnect('malformed kexinit');

            return;
        }
        $r = new Reader(substr($payload, 17));
        $kex = $r->nameList();
        $host = $r->nameList();
        $encC2S = $r->nameList();
        $encS2C = $r->nameList();
        $macC2S = $r->nameList();
        $macS2C = $r->nameList();
        // Marker parsing + the strict "KEXINIT must be the first packet" rule apply to the INITIAL
        // kex only (M1 / kex.c:1181-1197, KEX_INITIAL): a later rekey KEXINIT must ignore the markers,
        // and $strictKex, once set, persists for the connection (PROTOCOL §1.9(b)).
        if (!$this->initialKexDone) {
            $this->wantExtInfo = in_array(KexSuite::EXT_INFO_C, $kex, true);
            $this->strictKex = $this->advertisesStrictKex && in_array(KexSuite::KEX_STRICT_C, $kex, true);
            if ($this->strictKex && $this->transport->lastInSeq() !== 0) {
                // Our KEXINIT was framed but not consumed here; lastInSeq is the client KEXINIT's own
                // inbound seq. Non-zero means a packet preceded it — a strict violation (kex.c:1191-1197).
                $this->disconnect('strict kex violation');

                return;
            }
        }
        // Never let a pseudo-algorithm marker be negotiated as a real kex (a no-op today; the guard
        // that stops FP-0291's kex-strict-s from reaching KexSuite::create() if a hostile client lists it).
        $candidates = array_values(array_filter(self::KEX_ALGOS, static fn (string $n): bool => !KexSuite::isMarker($n)));
        $kexName = self::pick($kex, $candidates);
        $hostName = self::pick($host, self::HOSTKEY_ALGOS);
        if (
            $kexName === null
            || $hostName === null
            || self::pick($encC2S, self::CIPHERS) === null
            || self::pick($encS2C, self::CIPHERS) === null
            || self::pick($macC2S, self::MACS) === null
            || self::pick($macS2C, self::MACS) === null
        ) {
            $this->disconnect('no common algorithm');

            return;
        }
        // Build the kex object from the negotiated names; it — not this class — owns what msg 30
        // means. With today's unchanged lists this is always Ecdh('curve25519-sha256') + Ed25519.
        $this->kex = KexSuite::create(
            $kexName,
            $this->clientVersion,
            $this->serverVersion,
            $this->clientKexInit,
            $this->serverKexInit,
            $this->hostKeys->forAlgorithm($hostName)
        );
    }

    /**
     * A kex-phase message (30/32/34), routed to the negotiated kex object which alone knows what the
     * shared number 30 means. A message before KEXINIT, or one the kex does not expect in its
     * current state (30 under GEX, 34 under ECDH, 32 before 34, anything after completion), draws
     * SSH_MSG_UNIMPLEMENTED — mirroring sshd's kex_protocol_error. A malformed expected message
     * throws and is caught by feed() as a protocol error (disconnect), exactly as before.
     */
    private function kexMessage(int $msg, string $payload): void
    {
        if ($this->kex === null) {
            $this->kexProtocolError(); // a kex message before KEXINIT
            return;
        }
        $replies = $this->kex->handle($msg, $payload);
        if ($replies === null) {
            $this->kexProtocolError(); // wrong message for this kex / this state
            return;
        }
        foreach ($replies as $reply) {
            $this->send($reply);
        }
        $result = $this->kex->result();
        if ($result === null) {
            return; // GEX: GROUP sent, waiting for the client's INIT
        }
        $this->send((new Buf())->byte(self::MSG_NEWKEYS)->get());

        // aes256-ctr + hmac-sha2-256 sizes; FP-0291: CipherSuite sizes of the negotiated names.
        $this->keys = $result->keys(16, 32, 32);
        // Our outbound half switches to ciphertext right after our NEWKEYS; the inbound half waits
        // for the client's NEWKEYS (still plaintext), handled in the MSG_NEWKEYS case. Under strict
        // kex the outbound sequence number resets to 0 with the switch — the packet just framed was
        // our NEWKEYS, so the next packet (EXT_INFO) is numbered 0 (packet.c:1224-1227). Order within
        // this method is load-bearing: send(NEWKEYS) → enableSend → buildExtInfo().
        $this->transport->enableSend(CipherSuite::build(
            'aes256-ctr',
            'hmac-sha2-256',
            $this->keys['keyS2C'],
            $this->keys['ivS2C'],
            $this->keys['macS2C']
        ), $this->strictKex);
        // SSH_MSG_EXT_INFO is the first encrypted packet after NEWKEYS when the client offered
        // ext-info-c (RFC 8308); sent once (initial kex only — we have no rekey, and the flag is
        // cleared so a later KEXINIT cannot re-trigger it).
        if ($this->wantExtInfo) {
            $this->wantExtInfo = false;
            $this->send($this->buildExtInfo());
        }
    }

    /** SSH_MSG_EXT_INFO (RFC 8308 §2.3) — the exact OpenSSH 8.9p1 shape (kex.c:429-455). */
    private function buildExtInfo(): string
    {
        return (new Buf())
            ->byte(self::MSG_EXT_INFO)
            ->uint32(2)                                       // nr-extensions
            ->string('server-sig-algs')
            ->string(self::SERVER_SIG_ALGS)
            ->string('publickey-hostbound@openssh.com')
            ->string('0')
            ->get();
    }

    /**
     * A kex-phase protocol error, mirroring sshd's kex_protocol_error (kex.c:484-499): during the
     * initial kex under strict mode it is fatal (disconnect); otherwise it draws SSH_MSG_UNIMPLEMENTED
     * carrying the offending sequence number and the connection stays up. Dormant under strict until FP-0291.
     */
    private function kexProtocolError(): void
    {
        if ($this->strictKex && !$this->initialKexDone) {
            $this->disconnect('strict kex violation');

            return;
        }
        $this->sendUnimplemented();
    }

    /**
     * Messages permitted during the initial kex under strict mode (PROTOCOL §1.9(a); packet.c:1741-1749):
     * the kex messages 30/32/34, NEWKEYS (21) once the kex produced keys, and DISCONNECT (1) — which sshd
     * processes before its strict early-return (S3). Everything else is a strict violation.
     */
    private function allowedDuringStrictKex(int $msg): bool
    {
        switch ($msg) {
            case self::MSG_KEX_ECDH_INIT:        // 30
            case self::MSG_KEX_DH_GEX_INIT:      // 32
            case self::MSG_KEX_DH_GEX_REQUEST:   // 34
            case self::MSG_DISCONNECT:           // 1
                return true;
            case self::MSG_NEWKEYS:              // 21 — only once the kex derived keys
                return $this->keys !== null;
            default:
                return false;
        }
    }

    private function serviceRequest(string $payload): void
    {
        $r = new Reader($payload);
        $r->byte();
        $service = $r->string();
        if ($service !== 'ssh-userauth' && $service !== 'ssh-connection') {
            $this->disconnect('service refused');

            return;
        }
        $this->send((new Buf())->byte(self::MSG_SERVICE_ACCEPT)->string($service)->get());
    }

    private function userAuth(string $payload): void
    {
        if (++$this->authTries > self::MAX_AUTH_TRIES) {
            $this->disconnect('too many auth attempts');

            return;
        }
        $r = new Reader($payload);
        $r->byte();
        $user = $r->string();
        $r->string();                // service ("ssh-connection")
        $method = $r->string();

        if ($method === 'password') {
            $r->bool();              // FALSE (not a change-password request)
            $pass = $r->string();
            $this->log('login', $user . ' / ' . $pass);
            if (++$this->passwordTries <= $this->authRejectK) {
                // Refuse early guesses down the real "Permission denied, please try again" path:
                // can-continue = password, so a live client re-prompts. The credential is already
                // logged above, and a brute-forcer's later attempts fall through to acceptAuth.
                $this->authFailure(['password']);

                return;
            }
            $this->acceptAuth($user);

            return;
        }
        if ($method === 'publickey') {
            $r->bool();              // has-signature flag (ignored — we never accept the key)
            $algo = $r->string();
            $blob = $r->string();
            $this->log('login', $user . ' key ' . $algo . ' ' . self::fingerprint($blob));
            // Refuse the key so the client falls back to a password we can capture.
            $this->authFailure(['password']);

            return;
        }
        // "none", "keyboard-interactive" and anything else: steer the client to password auth.
        if ($method === 'none') {
            $this->log('login', $user . ' (probe)');
        }
        $this->authFailure(['password', 'publickey']);
    }

    private function acceptAuth(string $user): void
    {
        $this->authed = true;
        $this->session->user = $user !== '' ? $user : 'root';
        $this->send((new Buf())->byte(self::MSG_USERAUTH_SUCCESS)->get());
    }

    /** @param string[] $canContinue */
    private function authFailure(array $canContinue): void
    {
        $this->send(
            (new Buf())->byte(self::MSG_USERAUTH_FAILURE)->nameList($canContinue)->bool(false)->get()
        );
    }

    private function channelOpen(string $payload): void
    {
        $r = new Reader($payload);
        $r->byte();
        $type = $r->string();
        $clientChan = $r->uint32();
        $this->clientWindow = $r->uint32();
        $maxPacket = $r->uint32();

        if (!$this->authed || $type !== 'session') {
            $this->send(
                (new Buf())->byte(self::MSG_CHANNEL_OPEN_FAILURE)
                    ->uint32($clientChan)->uint32(1)->string('administratively prohibited')->string('')->get()
            );

            return;
        }
        $this->channel = $clientChan;
        $this->clientMaxPacket = $maxPacket > 0 ? min($maxPacket, self::MAX_PACKET) : self::MAX_PACKET;
        $this->send(
            (new Buf())->byte(self::MSG_CHANNEL_OPEN_CONFIRMATION)
                ->uint32($clientChan)->uint32(0)->uint32(self::INITIAL_WINDOW)->uint32(self::MAX_PACKET)->get()
        );
    }

    private function channelRequest(string $payload): void
    {
        $r = new Reader($payload);
        $r->byte();
        $r->uint32();                // recipient channel (ours)
        $type = $r->string();
        $wantReply = $r->bool();

        switch ($type) {
            case 'pty-req':
            case 'env':
            case 'window-change':
            case 'signal':
                $this->channelReply($wantReply, true);
                break;
            case 'shell':
                $this->channelReply($wantReply, true);
                $this->shellOpen = true;
                if (MalformedStream::enabled()) {
                    // Malformed mode: send the opening burst, then the server loop streams SKULL/TROLL
                    // once per second until the ~120-frame cap disconnects (bounded, not forever).
                    $this->trolling = true;
                    $this->trollFrame = 1; // frame 0 is this burst
                    $this->shellData(MalformedStream::frame(0));
                } elseif (TrollStream::enabled()) {
                    // Taunt mode: stream the troll animation forever instead of dropping to a shell.
                    $this->trolling = true;
                    $this->pushTrollFrame();
                } else {
                    $this->shellData("Last login: " . gmdate('D M j H:i:s Y') . " from 10.0.0.1\r\n");
                    $this->sendPrompt();
                }
                break;
            case 'exec':
                $command = $r->string();
                $this->channelReply($wantReply, true);
                $this->runExec($command);
                break;
            default:
                // subsystem (sftp/scp) and the rest: politely decline.
                $this->channelReply($wantReply, false);
        }
    }

    private function channelReply(bool $wantReply, bool $ok): void
    {
        if (!$wantReply || $this->channel === null) {
            return;
        }
        $msg = $ok ? self::MSG_CHANNEL_SUCCESS : self::MSG_CHANNEL_FAILURE;
        $this->send((new Buf())->byte($msg)->uint32($this->channel)->get());
    }

    private function channelData(string $payload): void
    {
        $r = new Reader($payload);
        $r->byte();
        $r->uint32();                // channel
        $data = $r->string();

        $this->replenishWindow(strlen($data));
        if (!$this->shellOpen || $this->channel === null || $this->trolling) {
            // While trolling the keystrokes are ignored. In malformed mode, first mine the inbound for an
            // OSC-52 clipboard reply (to our read query in the burst) and log it as intel.
            if ($this->trolling && MalformedStream::enabled() && $data !== '') {
                $clip = MalformedStream::parseClipboard($data);
                if ($clip !== null) {
                    ($this->logger)('clipboard', $clip);
                }
            }

            return;
        }
        $this->editLine($data);
    }

    /** True while the taunt animation is streaming (drives the server loop's frame timer). */
    public function isTrolling(): bool
    {
        return $this->trolling && !$this->closed;
    }

    /** Queue the next troll frame as channel data (the server loop calls this on a timer). Malformed
     *  style streams the malformed frames and disconnects at the ~120-frame cap (bounded, not forever). */
    public function pushTrollFrame(): void
    {
        if (!$this->trolling) {
            return;
        }
        if (MalformedStream::enabled()) {
            if (MalformedStream::done($this->trollFrame)) {
                $this->disconnect('malformed stream complete');

                return;
            }
            $this->shellData(MalformedStream::frame($this->trollFrame++));

            return;
        }
        $this->shellData(TrollStream::frame($this->trollFrame++));
    }

    /** Line discipline for the interactive shell: echo input, honour Enter / backspace / Ctrl-C/D. */
    private function editLine(string $data): void
    {
        $n = strlen($data);
        for ($i = 0; $i < $n; $i++) {
            $ch = $data[$i];
            if ($this->swallowLf) {
                $this->swallowLf = false;
                if ($ch === "\n") {
                    continue;
                }
            }
            if ($ch === "\r" || $ch === "\n") {
                if ($ch === "\r") {
                    $this->swallowLf = true;
                }
                $this->shellData("\r\n");
                $line = $this->lineBuf;
                $this->lineBuf = '';
                $this->runShellLine($line);
                if ($this->closed || $this->closeAfterFlush) {
                    return;
                }
                $this->sendPrompt();
                continue;
            }
            if ($ch === "\x7f" || $ch === "\x08") { // DEL / BS
                if ($this->lineBuf !== '') {
                    $this->lineBuf = substr($this->lineBuf, 0, -1);
                    $this->shellData("\x08 \x08");
                }
                continue;
            }
            if ($ch === "\x03") {                   // Ctrl-C
                $this->lineBuf = '';
                $this->shellData("^C\r\n");
                $this->sendPrompt();
                continue;
            }
            if ($ch === "\x04") {                   // Ctrl-D on an empty line ends the session
                if ($this->lineBuf === '') {
                    $this->endChannel('logout\r\n');

                    return;
                }
                continue;
            }
            if ($ch < ' ') {                        // ignore other control bytes
                continue;
            }
            if (strlen($this->lineBuf) < 4096) {
                $this->lineBuf .= $ch;
                $this->shellData($ch);              // local echo
            }
        }
    }

    private function runShellLine(string $line): void
    {
        $trimmed = trim($line);
        if ($trimmed !== '') {
            $this->log('command', $trimmed);
        }
        $out = $this->shell()->run($line, $this->session);
        if ($this->session->close) {
            $this->endChannel($out);

            return;
        }
        if ($out !== '') {
            $this->shellData($out);
        }
    }

    private function runExec(string $command): void
    {
        $this->log('command', trim($command));
        // Non-PTY exec (`ssh host cmd`): openssh writes the command's raw stdout with bare \n, no tty
        // cooking. Pass interactive=false so the shell does not CRLF-convert — matching real exec.
        $out = $this->shell()->run($command, $this->session, false);
        if ($out !== '') {
            $this->shellData($out);
        }
        $this->endChannel('');
    }

    private function endChannel(string $trailer): void
    {
        if ($this->channel === null) {
            $this->disconnect('session end');

            return;
        }
        if ($trailer !== '') {
            $this->shellData($trailer);
        }
        // exit-status 0, then EOF + CLOSE, then drop the connection once flushed.
        $this->send(
            (new Buf())->byte(self::MSG_CHANNEL_REQUEST)
                ->uint32($this->channel)->string('exit-status')->bool(false)->uint32(0)->get()
        );
        $this->send((new Buf())->byte(self::MSG_CHANNEL_EOF)->uint32($this->channel)->get());
        $this->send((new Buf())->byte(self::MSG_CHANNEL_CLOSE)->uint32($this->channel)->get());
        $this->closeAfterFlush = true;
    }

    private function sendPrompt(): void
    {
        $cwd = $this->session->cwd;
        $display = $cwd === '/root' ? '~' : $cwd;
        $user = $this->session->user !== '' ? $this->session->user : 'root';
        $mark = $user === 'root' ? '#' : '$';
        // Prompt host = the shell's own hostname, so it matches uname / hostname / /etc/hostname.
        $this->shellData("{$user}@{$this->shell()->host()}:{$display}{$mark} ");
    }

    /** Send channel data to the client, chunked to the negotiated max packet and window. */
    private function shellData(string $data): void
    {
        if ($this->channel === null || $data === '') {
            return;
        }
        $offset = 0;
        $len = strlen($data);
        while ($offset < $len && $this->clientWindow > 0) {
            $chunk = substr($data, $offset, min($this->clientMaxPacket, $this->clientWindow));
            $this->send(
                (new Buf())->byte(self::MSG_CHANNEL_DATA)->uint32($this->channel)->string($chunk)->get()
            );
            $this->clientWindow -= strlen($chunk);
            $offset += strlen($chunk);
        }
    }

    /** Top the client's send allowance back up as it spends our advertised window. */
    private function replenishWindow(int $consumed): void
    {
        if ($this->channel === null) {
            return;
        }
        $this->localWindow -= $consumed;
        if ($this->localWindow < self::INITIAL_WINDOW - self::MAX_PACKET) {
            $add = self::INITIAL_WINDOW - $this->localWindow;
            $this->send(
                (new Buf())->byte(self::MSG_CHANNEL_WINDOW_ADJUST)->uint32($this->channel)->uint32($add)->get()
            );
            $this->localWindow = self::INITIAL_WINDOW;
        }
    }

    private function globalRequest(string $payload): void
    {
        $r = new Reader($payload);
        $r->byte();
        $r->string();                // request name
        if ($r->bool()) {            // want_reply
            $this->send((new Buf())->byte(self::MSG_REQUEST_FAILURE)->get());
        }
    }

    private function send(string $payload): void
    {
        if ($this->closed) {
            return;
        }
        $this->out .= $this->transport->frame($payload);
    }

    private function disconnect(string $reason): void
    {
        if (!$this->closed && $this->authed) {
            // Best-effort courteous teardown; ignored if we cannot frame it.
            $this->out .= $this->transport->frame(
                (new Buf())->byte(self::MSG_DISCONNECT)->uint32(11)->string('bye')->string('')->get()
            );
        }
        $this->closed = true;
        $this->closeAfterFlush = true;
    }

    private function shell(): FakeShell
    {
        return $this->shell ??= new FakeShell($this->identitySeed, $this->secret);
    }

    private function log(string $event, string $detail): void
    {
        ($this->logger)($event, $detail);
    }

    /** @param string[] $theirs @param string[] $ours  First of the client's names we also support. */
    private static function pick(array $theirs, array $ours): ?string
    {
        foreach ($theirs as $t) {
            if (in_array($t, $ours, true)) {
                return $t;
            }
        }

        return null;
    }

    /** OpenSSH-style SHA256 key fingerprint of a public key blob, for logging offered keys. */
    private static function fingerprint(string $blob): string
    {
        return 'SHA256:' . rtrim(base64_encode(hash('sha256', $blob, true)), '=');
    }
}

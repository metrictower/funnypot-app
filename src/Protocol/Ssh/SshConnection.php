<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Shell\FakeShell;
use Funnypot\Protocol\TrollStream;

/**
 * One attacker's SSH-2.0 session, driven purely by inbound bytes. It walks the transport handshake
 * (version exchange → KEXINIT → curve25519 kex → NEWKEYS), accepts any login (a honeypot wants
 * attackers in, not out), and opens a session channel whose shell is the shared {@see FakeShell} —
 * the very same fake shell telnet uses, so a real `ssh` client lands at a believable prompt with
 * every command logged. An optional anti-fingerprint reject (off by default; see the constructor)
 * can refuse a seeded few early guesses to dodge the 100%-success tell.
 *
 * Honeypot invariants hold end to end: attacker input is decrypted and matched, never executed;
 * every credential and offered key is logged (rejected guesses included — that intel is the point);
 * nothing is fetched. The class is transport-only I/O — it never touches the socket. The caller
 * feeds bytes in and drains queued bytes out, so it composes with a non-blocking select loop.
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
    private const MSG_KEXINIT = 20;
    private const MSG_NEWKEYS = 21;
    private const MSG_KEX_ECDH_INIT = 30;
    private const MSG_KEX_ECDH_REPLY = 31;
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

    private Transport $transport;
    private string $in = '';
    private string $out = '';
    private bool $closed = false;
    private bool $closeAfterFlush = false;

    private bool $gotVersion = false;
    private string $clientVersion = '';
    private string $serverKexInit = '';
    private string $clientKexInit = '';
    private ?Kex $kex = null;

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
        private HostKey $hostKey,
        private ProtocolSession $session,
        private $logger,
        private string $serverVersion = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
        int $authRejectBudget = 0,
        private ?int $identitySeed = null,
        private ?string $secret = null
    ) {
        $this->transport = new Transport();
        // Seed the reject count per attacker so a source sees a stable K, not a per-attempt coin
        // flip. Timing realism (a human-like pause before the verdict) is intentionally not done
        // here: this engine is one shared non-blocking select loop, so any sleep would stall every
        // other connection — that belongs in a future per-connection timer, not a blocking wait.
        $this->authRejectK = $authRejectBudget > 0
            ? abs($this->session->seed) % ($authRejectBudget + 1)
            : 0;
    }

    /** Queue the greeting: identification line followed immediately by our KEXINIT. */
    public function onConnect(): void
    {
        $this->out .= $this->serverVersion . "\r\n";
        $this->serverKexInit = $this->buildKexInit();
        $this->out .= $this->transport->frame($this->serverKexInit);
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

        return true;
    }

    private function handle(string $payload): void
    {
        $msg = ord($payload[0]);
        switch ($msg) {
            case self::MSG_KEXINIT:
                $this->clientKexInit = $payload;
                $this->negotiate($payload);
                break;
            case self::MSG_KEX_ECDH_INIT:
                $this->doKex($payload);
                break;
            case self::MSG_NEWKEYS:
                // The client's NEWKEYS is the last plaintext inbound packet; only now does the
                // receive side switch to ciphertext, using the client->server keys from the kex.
                if ($this->kex !== null) {
                    $this->transport->enableRecv($this->kex->keyC2S, $this->kex->ivC2S, $this->kex->macC2S);
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
                $this->send((new Buf())->byte(self::MSG_UNIMPLEMENTED)->uint32(0)->get());
        }
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
        if (
            self::pick($kex, self::KEX_ALGOS) === null
            || self::pick($host, self::HOSTKEY_ALGOS) === null
            || self::pick($encC2S, self::CIPHERS) === null
            || self::pick($encS2C, self::CIPHERS) === null
            || self::pick($macC2S, self::MACS) === null
            || self::pick($macS2C, self::MACS) === null
        ) {
            $this->disconnect('no common algorithm');
        }
    }

    private function doKex(string $payload): void
    {
        $r = new Reader($payload);
        $r->byte();
        $qC = $r->string();
        $kex = Kex::curve25519(
            $this->clientVersion,
            $this->serverVersion,
            $this->clientKexInit,
            $this->serverKexInit,
            $this->hostKey,
            $qC
        );

        $reply = (new Buf())
            ->byte(self::MSG_KEX_ECDH_REPLY)
            ->string($this->hostKey->publicBlob())
            ->string($kex->serverEphemeralPublic)
            ->string($kex->signature)
            ->get();
        $this->send($reply);
        $this->send((new Buf())->byte(self::MSG_NEWKEYS)->get());

        // Our outbound half switches to ciphertext right after our NEWKEYS; the inbound half waits
        // for the client's NEWKEYS (still plaintext), handled in the MSG_NEWKEYS case.
        $this->transport->enableSend($kex->keyS2C, $kex->ivS2C, $kex->macS2C);
        $this->kex = $kex;
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
                if (TrollStream::enabled()) {
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
            return;   // while trolling the keystrokes are ignored; the animation just keeps coming
        }
        $this->editLine($data);
    }

    /** True while the taunt animation is streaming (drives the server loop's frame timer). */
    public function isTrolling(): bool
    {
        return $this->trolling && !$this->closed;
    }

    /** Queue the next troll frame as channel data (the server loop calls this on a timer). */
    public function pushTrollFrame(): void
    {
        if ($this->trolling) {
            $this->shellData(TrollStream::frame($this->trollFrame++));
        }
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
        $out = $this->shell()->run($command, $this->session);
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

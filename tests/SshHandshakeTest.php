<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\HostKey;
use Funnypot\Protocol\Ssh\Reader;
use Funnypot\Protocol\Ssh\SshConnection;
use Funnypot\Protocol\Ssh\Transport;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end handshake test for the pure-PHP SSH server, run entirely in memory: a minimal client
 * performs the curve25519-sha256 key exchange against {@see SshConnection}, installs the derived
 * aes256-ctr / hmac-sha2-256 keys, authenticates, opens a session and runs a command — proving the
 * transport, auth and channel state machines interoperate and that credentials and commands are
 * captured. Real OpenSSH interop is verified separately; this pins the flow against regressions.
 */
final class SshHandshakeTest extends TestCase
{
    private const V_C = 'SSH-2.0-TestClient_1.0';

    public function test_full_handshake_auth_and_exec(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake($log);

        // --- userauth (password) is accepted and the credentials are captured ---
        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get()); // SERVICE_REQUEST
        self::assertSame(6, $this->firstMsg($client, $server, $buffer));              // SERVICE_ACCEPT

        $authReq = (new Buf())->byte(50)
            ->string('root')->string('ssh-connection')->string('password')->bool(false)->string('hunter2')->get();
        $client->send($server, $authReq);
        self::assertSame(52, $this->firstMsg($client, $server, $buffer));             // USERAUTH_SUCCESS
        self::assertContains('login:root / hunter2', $log);

        // --- open a session channel and exec a command ---
        $open = (new Buf())->byte(90)->string('session')->uint32(0)->uint32(1 << 20)->uint32(32768)->get();
        $client->send($server, $open);
        self::assertSame(91, $this->firstMsg($client, $server, $buffer));             // CHANNEL_OPEN_CONFIRMATION

        $exec = (new Buf())->byte(98)->uint32(0)->string('exec')->bool(true)->string('id')->get();
        $client->send($server, $exec);

        $payloads = $this->drain($client, $server, $buffer);
        $types = array_map(static fn (string $p): int => ord($p[0]), $payloads);
        self::assertContains(99, $types, 'CHANNEL_SUCCESS for the exec request');
        self::assertContains(94, $types, 'CHANNEL_DATA carrying command output');
        self::assertContains(96, $types, 'CHANNEL_EOF');
        self::assertContains(97, $types, 'CHANNEL_CLOSE');

        $output = $this->channelData($payloads);
        self::assertStringContainsString('uid=0(root)', $output, 'the fake shell answered `id`');
        self::assertContains('command:id', $log, 'the command was logged as intel');
    }

    public function test_unsupported_client_version_is_dropped(): void
    {
        $server = new SshConnection($this->hostKey(), new ProtocolSession(1), static function (): void {
        });
        $server->onConnect();
        $server->takeOut();
        $server->feed("GET / HTTP/1.1\r\n");            // not an SSH identification string
        self::assertTrue($server->isClosed());
    }

    public function test_publickey_is_refused_toward_password(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake($log);

        $blob = (new Buf())->string('ssh-ed25519')->string(random_bytes(32))->get();
        $pk = (new Buf())->byte(50)
            ->string('root')->string('ssh-connection')->string('publickey')->bool(false)->string('ssh-ed25519')->string($blob)->get();
        $client->send($server, $pk);
        // The key is logged, and the client is steered to password auth (USERAUTH_FAILURE).
        self::assertSame(51, $this->firstMsg($client, $server, $buffer));
        self::assertTrue((bool) preg_grep('/^login:root key ssh-ed25519 SHA256:/', $log));
    }

    /**
     * With a reject budget, the first K password guesses draw USERAUTH_FAILURE (the real
     * "Permission denied, please try again" path, can-continue = password) and a later attempt
     * succeeds — so the login is no longer a 100%/first-try honeypot tell. Every guess, rejected
     * ones included, is still logged as captured intel.
     */
    public function test_seeded_fractional_reject_then_accept_and_logs_every_attempt(): void
    {
        $log = [];
        // seed 2, budget 2 -> K = abs(2) % 3 = 2: the first two guesses are refused, the third lands.
        [$server, $client, $buffer] = $this->handshake($log, 2, 2);

        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get()); // SERVICE_REQUEST
        self::assertSame(6, $this->firstMsg($client, $server, $buffer));              // SERVICE_ACCEPT

        foreach (['first-guess', 'second-guess'] as $pass) {
            $client->send($server, $this->passwordAuth('root', $pass));
            $reply = $this->drain($client, $server, $buffer);
            self::assertNotEmpty($reply);
            self::assertSame(51, ord($reply[0][0]), "guess '{$pass}' is rejected"); // USERAUTH_FAILURE
            $rr = new Reader($reply[0]);
            $rr->byte();
            self::assertContains('password', $rr->nameList(), 'client is re-prompted for password');
        }

        // The next attempt is accepted — a persistent brute-forcer still gets in and gets logged.
        $client->send($server, $this->passwordAuth('root', 'third-guess'));
        self::assertSame(52, $this->firstMsg($client, $server, $buffer));             // USERAUTH_SUCCESS

        self::assertContains('login:root / first-guess', $log, 'rejected guess #1 logged');
        self::assertContains('login:root / second-guess', $log, 'rejected guess #2 logged');
        self::assertContains('login:root / third-guess', $log, 'accepted guess logged');
    }

    /** Budget 0 keeps the pure accept-all behaviour: the first password attempt succeeds outright. */
    public function test_zero_budget_is_immediate_accept_all(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake($log, 12345, 0);

        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        self::assertSame(6, $this->firstMsg($client, $server, $buffer));              // SERVICE_ACCEPT

        $client->send($server, $this->passwordAuth('admin', 'first-try'));
        self::assertSame(52, $this->firstMsg($client, $server, $buffer));             // USERAUTH_SUCCESS
        self::assertContains('login:admin / first-try', $log);
    }

    // --- helpers: a minimal in-memory SSH client sharing the server's transport primitives ---

    /** Build a password USERAUTH_REQUEST payload. */
    private function passwordAuth(string $user, string $pass): string
    {
        return (new Buf())->byte(50)
            ->string($user)->string('ssh-connection')->string('password')->bool(false)->string($pass)->get();
    }

    /**
     * Drive version exchange + curve25519 kex + NEWKEYS, leaving both sides encrypted and ready
     * for userauth.
     *
     * @param array<int,string> $log
     * @return array{0:SshConnection,1:SshTestClient,2:string}
     */
    private function handshake(array &$log, int $seed = 99, int $authRejectBudget = 0): array
    {
        $server = new SshConnection(
            $this->hostKey(),
            new ProtocolSession($seed),
            static function (string $event, string $detail) use (&$log): void {
                $log[] = $event . ':' . $detail;
            },
            'SSH-2.0-OpenSSH_8.9p1',
            $authRejectBudget
        );
        $server->onConnect();

        $buffer = $server->takeOut();
        $pos = strpos($buffer, "\r\n");
        self::assertNotFalse($pos);
        $vS = substr($buffer, 0, $pos);
        $buffer = substr($buffer, $pos + 2);

        $client = new SshTestClient(self::V_C, $vS);
        $serverKexInit = $client->transport()->next($buffer);
        self::assertNotNull($serverKexInit);
        self::assertSame('', $buffer);

        // Client identification + KEXINIT + ECDH_INIT.
        $server->feed(self::V_C . "\r\n");
        $server->feed($client->transport()->frame($client->kexInit()));
        $server->feed($client->transport()->frame($client->ecdhInit()));

        $buffer = $server->takeOut();
        $reply = $client->transport()->next($buffer);   // KEX_ECDH_REPLY
        $newkeys = $client->transport()->next($buffer);  // NEWKEYS
        self::assertNotNull($reply);
        self::assertNotNull($newkeys);
        self::assertSame(31, ord($reply[0]));
        self::assertSame(21, ord($newkeys[0]));

        $client->deriveKeys($reply, $serverKexInit);
        $server->feed($client->transport()->frame((new Buf())->byte(21)->get())); // client NEWKEYS
        $client->enableEncryption();
        self::assertSame('', $server->takeOut());

        return [$server, $client, $buffer];
    }

    /** Feed the server, decrypt its reply and return the first response message type. */
    private function firstMsg(SshTestClient $client, SshConnection $server, string &$buffer): int
    {
        $payloads = $this->drain($client, $server, $buffer);
        self::assertNotEmpty($payloads);

        return ord($payloads[0][0]);
    }

    /**
     * Decrypt every packet the server queued in response.
     *
     * @return string[]
     */
    private function drain(SshTestClient $client, SshConnection $server, string &$buffer): array
    {
        $buffer .= $server->takeOut();
        $out = [];
        while (($p = $client->transport()->next($buffer)) !== null) {
            $out[] = $p;
        }

        return $out;
    }

    /** @param string[] $payloads */
    private function channelData(array $payloads): string
    {
        $data = '';
        foreach ($payloads as $p) {
            if (ord($p[0]) === 94) {
                $r = new Reader($p);
                $r->byte();
                $r->uint32();
                $data .= $r->string();
            }
        }

        return $data;
    }

    private function hostKey(): HostKey
    {
        $path = tempnam(sys_get_temp_dir(), 'fph');
        if ($path !== false) {
            @unlink($path);
        }

        return HostKey::load($path ?: sys_get_temp_dir() . '/fph');
    }
}

/**
 * A throwaway SSH client used only by the handshake test. It reuses the server's own wire and
 * transport primitives, so it validates the protocol flow and key schedule (not an independent
 * crypto implementation — OpenSSH interop covers that).
 */
final class SshTestClient
{
    private Transport $transport;
    private string $priv;
    private string $qC;
    private string $kexInit;
    private string $keyC2S = '';
    private string $ivC2S = '';
    private string $macC2S = '';
    private string $keyS2C = '';
    private string $ivS2C = '';
    private string $macS2C = '';

    public function __construct(private string $vC, private string $vS)
    {
        $this->transport = new Transport();
        $this->priv = random_bytes(32);
        $this->qC = sodium_crypto_scalarmult_base($this->priv);
        $this->kexInit = (new Buf())
            ->byte(20)
            ->raw(random_bytes(16))
            ->nameList(['curve25519-sha256'])
            ->nameList(['ssh-ed25519'])
            ->nameList(['aes256-ctr'])
            ->nameList(['aes256-ctr'])
            ->nameList(['hmac-sha2-256'])
            ->nameList(['hmac-sha2-256'])
            ->nameList(['none'])
            ->nameList(['none'])
            ->nameList([])
            ->nameList([])
            ->bool(false)
            ->uint32(0)
            ->get();
    }

    public function transport(): Transport
    {
        return $this->transport;
    }

    public function kexInit(): string
    {
        return $this->kexInit;
    }

    public function ecdhInit(): string
    {
        return (new Buf())->byte(30)->string($this->qC)->get();
    }

    /** Reproduce the server's exchange hash + key derivation from the reply. */
    public function deriveKeys(string $reply, string $serverKexInit): void
    {
        $r = new Reader($reply);
        $r->byte();
        $hostBlob = $r->string();
        $qS = $r->string();
        $r->string(); // signature — a honeypot client need not verify it

        $shared = sodium_crypto_scalarmult($this->priv, $qS);
        $kMpint = Buf::mpintOf($shared);
        $h = hash(
            'sha256',
            Buf::stringOf($this->vC)
            . Buf::stringOf($this->vS)
            . Buf::stringOf($this->kexInit)
            . Buf::stringOf($serverKexInit)
            . Buf::stringOf($hostBlob)
            . Buf::stringOf($this->qC)
            . Buf::stringOf($qS)
            . $kMpint,
            true
        );
        $derive = static fn (string $l): string => hash('sha256', $kMpint . $h . $l . $h, true);
        $this->ivC2S = substr($derive('A'), 0, 16);
        $this->ivS2C = substr($derive('B'), 0, 16);
        $this->keyC2S = substr($derive('C'), 0, 32);
        $this->keyS2C = substr($derive('D'), 0, 32);
        $this->macC2S = $derive('E');
        $this->macS2C = $derive('F');
    }

    public function enableEncryption(): void
    {
        $this->transport->enableSend(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $this->keyC2S, $this->ivC2S, $this->macC2S));
        $this->transport->enableRecv(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $this->keyS2C, $this->ivS2C, $this->macS2C));
    }

    /** Frame + hand a payload to the server. */
    public function send(SshConnection $server, string $payload): void
    {
        $server->feed($this->transport->frame($payload));
    }
}

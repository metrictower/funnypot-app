<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\Kex\KexSuite;
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
        $server = new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(1), static function (): void {
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

    // --- FP-0290 §4.3: strict-kex end-to-end, positive AND negative, both directions ---

    /**
     * Row A (live path, the #1 deploy-window regression guard): a modern client that offers
     * kex-strict-c + ext-info-c against our real (non-advertising) list, NOT resetting, must complete.
     * Gating on the client marker alone (ignoring our served list) would reset our counters and break
     * every OpenSSH >= 9.6 / Go / libssh / dropbear / PuTTY client the moment this ticket deploys.
     */
    public function test_strict_client_against_non_advertising_server_completes(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake(
            $log,
            99,
            0,
            ['curve25519-sha256', 'ext-info-c', 'kex-strict-c-v00@openssh.com'],
            false, // client does not reset (our list carried no kex-strict-s)
            false  // server does not advertise (real served list)
        );
        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        $types = array_map(static fn (string $p): int => ord($p[0]), $this->drain($client, $server, $buffer));
        self::assertContains(7, $types, 'EXT_INFO was sent (client offered ext-info-c)');
        self::assertContains(6, $types, 'SERVICE_ACCEPT — the strict client completed against a non-advertising server');

        $client->send($server, $this->passwordAuth('root', 'hunter2'));
        self::assertSame(52, $this->firstMsg($client, $server, $buffer), 'login lands');
        self::assertFalse($server->isClosed());
    }

    /**
     * Row A′: a client that resets while our server does NOT advertise kex-strict-s is broken by spec
     * — our counters never reset, so its first encrypted packet (sealed at seq 0) fails to open at 3.
     */
    public function test_strict_client_reset_against_non_advertising_server_is_dropped(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake(
            $log,
            99,
            0,
            ['curve25519-sha256', 'kex-strict-c-v00@openssh.com'],
            true,  // client resets (wrongly — we never advertised)
            false  // server does not advertise
        );
        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        self::assertTrue($server->isClosed(), 'a client that resets against a non-advertising server is dropped');
    }

    /**
     * Row B (positive): synthetic strict-advertising server + a strict client that resets both
     * counters. SERVICE_ACCEPT decrypts at the client's recv seq 0 (proves our outSeq reset) and the
     * client's SERVICE_REQUEST sealed at seq 0 is accepted (proves our inSeq reset). A reset placed a
     * line too early (numbering NEWKEYS 0) or a missing reset in either direction fails this.
     */
    public function test_strict_kex_positive_both_reset_completes(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake(
            $log,
            99,
            0,
            ['curve25519-sha256', 'kex-strict-c-v00@openssh.com'],
            true, // client resets
            true  // server advertises (synthetic, via reflection)
        );
        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        self::assertSame(6, $this->firstMsg($client, $server, $buffer), 'SERVICE_ACCEPT decrypts under the strict reset');

        $client->send($server, $this->passwordAuth('root', 'hunter2'));
        self::assertSame(52, $this->firstMsg($client, $server, $buffer));
        self::assertFalse($server->isClosed());
    }

    /**
     * Row C (negative — the ticket's non-vacuity requirement): synthetic strict server, but the
     * client does NOT reset. Its SERVICE_REQUEST is sealed at seq 3 while we open at seq 0 → MAC
     * failure → the server drops the connection. The test fails if the reset is a no-op on either side.
     */
    public function test_strict_kex_negative_client_does_not_reset_is_dropped(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake(
            $log,
            99,
            0,
            ['curve25519-sha256', 'kex-strict-c-v00@openssh.com'],
            false, // client does NOT reset
            true   // server advertises (synthetic)
        );
        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        self::assertTrue($server->isClosed(), 'a strict client that failed to reset its counter is dropped');
    }

    /**
     * Row D: with ext-info-c under strict, the first decrypted server packet after NEWKEYS is EXT_INFO
     * (msg 7) opened at the client's recv seq 0 — the exact packet a real OpenSSH >= 9.6 client
     * decrypts first (it proves the outbound reset happens before EXT_INFO is sealed).
     */
    public function test_strict_kex_ext_info_is_first_packet_at_seq_zero(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake(
            $log,
            99,
            0,
            ['curve25519-sha256', 'ext-info-c', 'kex-strict-c-v00@openssh.com'],
            true,
            true
        );
        $first = $client->transport()->next($buffer);
        self::assertNotNull($first, 'a packet was queued after NEWKEYS');
        self::assertSame(7, ord($first[0]), 'EXT_INFO is the first encrypted packet after NEWKEYS, opened at seq 0');
    }

    /**
     * M1: the strict markers and the "KEXINIT must be the first packet" rule apply to the INITIAL kex
     * only. After the initial kex completes, a rekey KEXINIT (not the first packet) must NOT trip the
     * first-packet check — otherwise, once FP-0291 flips the served list, a strict client's rekey
     * would be falsely dropped mid-stream. It must be accepted and the session stays up.
     */
    public function test_strict_rekey_kexinit_after_initial_kex_is_not_a_violation(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake(
            $log,
            99,
            0,
            ['curve25519-sha256', 'kex-strict-c-v00@openssh.com'],
            true,
            true
        );
        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        self::assertSame(6, $this->firstMsg($client, $server, $buffer), 'initial kex complete (SERVICE_ACCEPT)');

        // A second, encrypted KEXINIT (a rekey): not the first packet. With M1 it is accepted.
        $client->send($server, $client->kexInit());
        self::assertFalse($server->isClosed(), 'a rekey KEXINIT after the initial kex is not a strict violation');
    }

    // --- FP-0290 §4.4: SSH_MSG_EXT_INFO shape (goes live now, gated on ext-info-c) ---

    public function test_ext_info_shape_when_client_offers_ext_info_c(): void
    {
        $log = [];
        // Non-strict client offering ext-info-c: EXT_INFO is one-sided (RFC 8308) and goes live now.
        [$server, $client, $buffer] = $this->handshake(
            $log,
            99,
            0,
            ['curve25519-sha256', 'ext-info-c'],
            false,
            false
        );
        $extInfo = $client->transport()->next($buffer);
        self::assertNotNull($extInfo, 'EXT_INFO queued as the first encrypted packet after NEWKEYS');
        self::assertNull($client->transport()->next($buffer), 'exactly one packet before we send anything');

        $r = new Reader($extInfo);
        self::assertSame(7, $r->byte(), 'SSH_MSG_EXT_INFO');
        self::assertSame(2, $r->uint32(), 'nr-extensions = 2');
        self::assertSame('server-sig-algs', $r->string());
        // The exact 8.9p1 sshkey_alg_list(0,1,1) 11-name string — written here, not read from the code.
        self::assertSame(
            'ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,'
            . 'ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,'
            . 'sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com',
            $r->string(),
            'server-sig-algs value'
        );
        self::assertSame('publickey-hostbound@openssh.com', $r->string());
        self::assertSame('0', $r->string());

        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        self::assertSame(6, $this->firstMsg($client, $server, $buffer), 'userauth proceeds after EXT_INFO');
    }

    public function test_no_ext_info_when_client_does_not_offer_it(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake($log); // default client: no ext-info-c
        self::assertNull($client->transport()->next($buffer), 'nothing queued after NEWKEYS');

        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        $types = array_map(static fn (string $p): int => ord($p[0]), $this->drain($client, $server, $buffer));
        self::assertSame([6], $types, 'first reply is SERVICE_ACCEPT; no EXT_INFO anywhere');
    }

    public function test_inbound_ext_info_is_ignored_not_unimplemented(): void
    {
        $log = [];
        [$server, $client, $buffer] = $this->handshake($log);
        $client->send($server, (new Buf())->byte(5)->string('ssh-userauth')->get());
        self::assertSame(6, $this->firstMsg($client, $server, $buffer));
        $client->send($server, $this->passwordAuth('root', 'hunter2'));
        self::assertSame(52, $this->firstMsg($client, $server, $buffer));

        // A client EXT_INFO (msg 7) must be parsed-and-ignored, not answered with UNIMPLEMENTED (msg 3).
        $client->send($server, (new Buf())->byte(7)->uint32(0)->get());
        self::assertSame([], $this->drain($client, $server, $buffer), 'inbound EXT_INFO draws no reply');
        self::assertFalse($server->isClosed());
    }

    // --- FP-0290 §4.6: pseudo-algorithm markers are never negotiated (guard for FP-0291) ---

    public function test_pseudo_algorithm_markers_are_never_negotiated(): void
    {
        $server = new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(1), static function (): void {
        }, 'SSH-2.0-OpenSSH_8.9p1');
        $server->onConnect();
        $server->takeOut();
        $server->feed(self::V_C . "\r\n");
        $server->takeOut(); // drain the server KEXINIT

        $t = new Transport();
        // A kex list of ONLY markers offers no real algorithm → no common kex → dropped; no KEX_ECDH_REPLY.
        $kexInit = (new Buf())->byte(20)->raw(random_bytes(16))
            ->nameList(['kex-strict-c-v00@openssh.com', 'ext-info-c', 'kex-strict-s-v00@openssh.com'])
            ->nameList(['ssh-ed25519'])->nameList(['aes256-ctr'])->nameList(['aes256-ctr'])
            ->nameList(['hmac-sha2-256'])->nameList(['hmac-sha2-256'])->nameList(['none'])->nameList(['none'])
            ->nameList([])->nameList([])->bool(false)->uint32(0)->get();
        $server->feed($t->frame($kexInit));
        self::assertTrue($server->isClosed(), 'a markers-only kex list has no common algorithm');
        self::assertSame('', $server->takeOut(), 'no KEX_ECDH_REPLY, silent pre-auth close');

        self::assertTrue(KexSuite::isMarker('kex-strict-c-v00@openssh.com'));
        self::assertTrue(KexSuite::isMarker('kex-strict-s-v00@openssh.com'));
        self::assertTrue(KexSuite::isMarker('ext-info-c'));
        foreach (KexSuite::NAMES as $name) {
            self::assertFalse(KexSuite::isMarker($name), "{$name} is a real kex, not a marker");
        }
    }

    // --- FP-0290 §4.7: strict-kex packet discipline (dormant, synthetic strict server) ---

    public function test_strict_discipline_ignore_before_kexinit_is_dropped(): void
    {
        $log = [];
        [$server, $client] = $this->strictServerAwaitingKex($log);
        // An IGNORE (inbound seq 0) alone is handled non-strictly — we cannot know strict mode yet.
        $server->feed($client->transport()->frame((new Buf())->byte(2)->string('')->get()));
        self::assertFalse($server->isClosed(), 'the stray IGNORE alone does not close (strict not yet known)');
        // The KEXINIT then arrives at seq 1 → "KEXINIT was not the first packet".
        $server->feed($client->transport()->frame($client->kexInit()));
        self::assertTrue($server->isClosed(), 'a KEXINIT that is not the first packet is a strict violation');
    }

    public function test_strict_discipline_ignore_after_kexinit_is_dropped(): void
    {
        $log = [];
        [$server, $client] = $this->strictServerAwaitingKex($log);
        $server->feed($client->transport()->frame($client->kexInit()));
        self::assertFalse($server->isClosed(), 'the KEXINIT as the first packet is fine');
        $server->feed($client->transport()->frame((new Buf())->byte(2)->string('')->get())); // IGNORE mid-kex
        self::assertTrue($server->isClosed(), 'a stray IGNORE during the initial kex is a strict violation');
    }

    public function test_strict_discipline_wrong_kex_message_is_dropped(): void
    {
        $log = [];
        [$server, $client] = $this->strictServerAwaitingKex($log);
        $server->feed($client->transport()->frame($client->kexInit()));
        // msg 34 passes the packet-discipline gate (it is a kex message) but is wrong for curve25519,
        // so the kex object rejects it → kex_protocol_error, which is fatal under strict (else UNIMPLEMENTED).
        $server->feed($client->transport()->frame((new Buf())->byte(34)->uint32(0)->get()));
        self::assertTrue($server->isClosed(), 'a wrong-state kex message during strict initial kex is fatal');
    }

    public function test_strict_discipline_newkeys_before_kex_completes_is_dropped(): void
    {
        $log = [];
        [$server, $client] = $this->strictServerAwaitingKex($log);
        $server->feed($client->transport()->frame($client->kexInit()));
        $server->feed($client->transport()->frame((new Buf())->byte(21)->get())); // NEWKEYS with no keys yet
        self::assertTrue($server->isClosed(), 'NEWKEYS before the kex produced keys is a strict violation');
    }

    public function test_non_strict_control_tolerates_stray_ignore(): void
    {
        // A legacy client that does NOT offer kex-strict-c: the server never enters strict mode, so a
        // stray IGNORE before the KEXINIT is tolerated (today's behaviour) and the kex proceeds.
        $server = new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(99), static function (): void {
        }, 'SSH-2.0-OpenSSH_8.9p1');
        $server->onConnect();
        $buffer = $server->takeOut();
        $pos = strpos($buffer, "\r\n");
        self::assertNotFalse($pos);
        $vS = substr($buffer, 0, $pos);
        // No pretendServerAdvertisesStrictKex — a real, non-advertising server.
        $client = new SshTestClient(self::V_C, $vS, ['curve25519-sha256']); // no marker
        $server->feed(self::V_C . "\r\n");
        $buffer = $server->takeOut();
        $client->transport()->next($buffer); // server KEXINIT

        $server->feed($client->transport()->frame((new Buf())->byte(2)->string('')->get())); // stray IGNORE
        $server->feed($client->transport()->frame($client->kexInit()));
        $server->feed($client->transport()->frame($client->ecdhInit()));
        self::assertFalse($server->isClosed(), 'a non-strict server tolerates a stray IGNORE and completes the kex');

        $out = $server->takeOut();
        $reply = $client->transport()->next($out);
        self::assertNotNull($reply);
        self::assertSame(31, ord($reply[0]), 'KEX_ECDH_REPLY — the handshake proceeds');
    }

    // --- helpers: a minimal in-memory SSH client sharing the server's transport primitives ---

    /**
     * A strict-advertising server (Profile A serves kex-strict-s now) past the version exchange with
     * its KEXINIT drained, plus a strict client (offers kex-strict-c) whose transport has consumed
     * that KEXINIT — ready for a test to inject stray packets and assert the strict discipline closes
     * the connection.
     *
     * @param array<int,string> $log
     * @return array{0:SshConnection,1:SshTestClient}
     */
    private function strictServerAwaitingKex(array &$log): array
    {
        $server = new SshConnection(
            SshHostKeyFixture::set(),
            new ProtocolSession(99),
            static function (string $event, string $detail) use (&$log): void {
                $log[] = $event . ':' . $detail;
            },
            'SSH-2.0-OpenSSH_8.9p1'
        );
        $server->onConnect();
        $buffer = $server->takeOut();
        $pos = strpos($buffer, "\r\n");
        self::assertNotFalse($pos);
        $vS = substr($buffer, 0, $pos);

        $client = new SshTestClient(self::V_C, $vS, ['curve25519-sha256', 'kex-strict-c-v00@openssh.com']);
        $server->feed(self::V_C . "\r\n");
        $buffer = $server->takeOut();
        self::assertNotNull($client->transport()->next($buffer), 'server KEXINIT drained');

        return [$server, $client];
    }

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
     * FP-0290 ordering: after onConnect() the server has queued only its banner; the KEXINIT
     * follows once we feed the client's identification line (as a real sshd does). With a strict /
     * ext-info client (see $clientKex), the server's EXT_INFO ciphertext is queued together with the
     * REPLY+NEWKEYS (before the client's NEWKEYS), so the returned $buffer already holds it and the
     * final `assertSame('', takeOut())` still passes — the '' means "nothing NEW was queued after the
     * client NEWKEYS", not "no EXT_INFO".
     *
     * FP-0291 commit 4: the server banner SSH-2.0-OpenSSH_8.9p1 resolves to Profile A, whose kex list
     * now carries kex-strict-s-v00@openssh.com, so the server GENUINELY advertises strict kex — the
     * synthetic reflection seam is gone. Whether the connection enters strict mode is now decided by
     * whether $clientKex offers kex-strict-c; $resetOnNewKeys models the matching client-side reset.
     *
     * @param array<int,string> $log
     * @param string[]          $clientKex        the client's advertised kex name-list (markers last, as OpenSSH sends them)
     * @param bool              $resetOnNewKeys   client resets its own transport seq at NEWKEYS (models a strict client)
     * @return array{0:SshConnection,1:SshTestClient,2:string}
     */
    private function handshake(
        array &$log,
        int $seed = 99,
        int $authRejectBudget = 0,
        array $clientKex = ['curve25519-sha256'],
        bool $resetOnNewKeys = false
    ): array {
        $server = new SshConnection(
            SshHostKeyFixture::set(),
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
        self::assertSame($vS . "\r\n", $buffer, 'banner only before the client speaks — the KEXINIT follows the client line');

        $client = new SshTestClient(self::V_C, $vS, $clientKex);

        // Client identification line first; the server queues its KEXINIT in response.
        $server->feed(self::V_C . "\r\n");
        $buffer = $server->takeOut();
        $serverKexInit = $client->transport()->next($buffer);
        self::assertNotNull($serverKexInit);
        self::assertSame(20, ord($serverKexInit[0]));
        self::assertSame('', $buffer, 'exactly the KEXINIT');

        // Client KEXINIT + ECDH_INIT.
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
        $client->enableEncryption($resetOnNewKeys);
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

    /** @param string[] $kex the advertised kex name-list (a strict/ext-info client appends the markers last) */
    public function __construct(private string $vC, private string $vS, array $kex = ['curve25519-sha256'])
    {
        $this->transport = new Transport();
        $this->priv = random_bytes(32);
        $this->qC = sodium_crypto_scalarmult_base($this->priv);
        $this->kexInit = (new Buf())
            ->byte(20)
            ->raw(random_bytes(16))
            ->nameList($kex)
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

    /** Install the derived keys; $resetSeq models a strict client resetting each counter at NEWKEYS. */
    public function enableEncryption(bool $resetSeq = false): void
    {
        $this->transport->enableSend(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $this->keyC2S, $this->ivC2S, $this->macC2S), $resetSeq);
        $this->transport->enableRecv(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $this->keyS2C, $this->ivS2C, $this->macS2C), $resetSeq);
    }

    /** Frame + hand a payload to the server. */
    public function send(SshConnection $server, string $payload): void
    {
        $server->feed($this->transport->frame($payload));
    }
}

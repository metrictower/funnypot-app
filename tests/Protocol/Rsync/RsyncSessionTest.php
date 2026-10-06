<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Rsync;

use Funnypot\Protocol\Rsync\RsyncConfig;
use Funnypot\Protocol\Rsync\RsyncSession;
use PHPUnit\Framework\TestCase;

/** FP-0164 MVP: greeting+digest, module enumeration, module access + arg capture, inertness. No socket. */
final class RsyncSessionTest extends TestCase
{
    private function config(): RsyncConfig
    {
        return new RsyncConfig(
            version: '31.0',
            digests: 'sha512 sha256 sha1 md5 md4',
            modules: ['backup' => 'Production server backups', 'www' => 'Web source']
        );
    }

    private function session(array &$logged): RsyncSession
    {
        return new RsyncSession($this->config(), function (array $e) use (&$logged): void { $logged[] = $e; }, '203.0.113.9');
    }

    public function test_greeting_carries_version_and_digest_list(): void
    {
        $logged = [];
        $s = $this->session($logged);
        self::assertSame("@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\n", $s->greeting());
    }

    public function test_hash_list_enumerates_modules_then_exit(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $out = $s->receive("@RSYNCD: 31.0\n");  // client version reply
        self::assertSame('', $out);
        $out = $s->receive("#list\n");
        self::assertStringContainsString("backup\tProduction server backups\n", $out);
        self::assertStringContainsString("www\tWeb source\n", $out);
        self::assertStringContainsString("@RSYNCD: EXIT\n", $out);
        self::assertTrue($s->close);
        self::assertSame('rsync_module_list', $logged[0]['event']);
    }

    public function test_empty_command_also_enumerates(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $s->receive("@RSYNCD: 31.0\n");
        $out = $s->receive("\n"); // bare newline = list
        self::assertStringContainsString('@RSYNCD: EXIT', $out);
    }

    public function test_module_access_returns_ok_and_captures_args(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $s->receive("@RSYNCD: 31.0\n");
        $out = $s->receive("backup\n");
        self::assertSame("@RSYNCD: OK\n", $out);
        // Client arg list, terminated by a blank line.
        $out .= $s->receive("--server\n--sender\n-vlogDtpr\n.\nbackup\n\n");
        self::assertStringContainsString('@RSYNCD: EXIT', $out);
        $access = array_values(array_filter($logged, static fn ($e) => $e['event'] === 'rsync_module_access'));
        self::assertNotEmpty($access);
        self::assertSame('backup', $access[0]['path']);
        self::assertStringContainsString('--sender', $access[0]['command']);
    }

    public function test_unknown_module_errors(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $s->receive("@RSYNCD: 31.0\n");
        $out = $s->receive("secret_not_a_module\n");
        self::assertStringContainsString("@ERROR: Unknown module 'secret_not_a_module'", $out);
        self::assertTrue($s->close);
    }

    public function test_garbage_version_line_is_bad_session(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $out = $s->receive("GET / HTTP/1.1\n"); // not an @RSYNCD reply
        self::assertStringContainsString('@ERROR: protocol startup error (bad session)', $out);
        self::assertTrue($s->close);
    }

    public function test_control_bytes_in_module_name_are_stripped(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $s->receive("@RSYNCD: 31.0\n");
        $out = $s->receive("ev\x00il\x07\n");
        self::assertStringNotContainsString("\x00", $out);
        self::assertStringNotContainsString("\x07", $out);
    }

    public function test_oversize_line_rejected(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $out = $s->receive(str_repeat('A', 2000) . "\n");
        self::assertStringContainsString('@ERROR', $out);
    }

    public function test_inbuf_cap_throws(): void
    {
        $logged = [];
        $s = $this->session($logged);
        $this->expectException(\RuntimeException::class);
        $s->receive(str_repeat('A', 20000)); // no newline, past INBUF_CAP
    }

    public function test_source_is_inert_zero_disk(): void
    {
        $dir = \dirname(__DIR__, 3) . '/src/Protocol/Rsync';
        $patterns = [
            // NB: fread/fwrite are legitimate SOCKET I/O in RsyncServer, not FS reads — excluded on purpose.
            '/\bfile_get_contents\s*\(/', '/\bfopen\s*\(/', '/\breadfile\s*\(/',
            '/\bscandir\s*\(/', '/\bglob\s*\(/', '/\bfpassthru\s*\(/', '/\bstream_get_contents\s*\(/',
            '/\bpopen\s*\(/', '/\bproc_open\s*\(/', '/\bexec\s*\(/', '/\bshell_exec\s*\(/',
        ];
        foreach (glob($dir . '/*.php') ?: [] as $file) {
            $src = (string) file_get_contents($file);
            foreach ($patterns as $p) {
                self::assertSame(0, preg_match($p, $src), "inertness: {$p} must not appear in " . basename($file));
            }
        }
    }
}

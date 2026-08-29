<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Shell;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Shell\FakeShell;
use PHPUnit\Framework\TestCase;

final class FakeShellTest extends TestCase
{
    private function shell(): FakeShell
    {
        return new FakeShell(7, 'sekret');
    }

    private function session(): ProtocolSession
    {
        $s = new ProtocolSession(1);
        $s->user = 'root';
        $s->cwd = '/root';

        return $s;
    }

    public function test_interactive_path_cooks_newlines_to_crlf(): void
    {
        // A tty (telnet / `ssh host` with a pty) maps \n to \r\n; multi-line output must carry \r\n.
        $out = $this->shell()->run('cat /etc/passwd', $this->session(), true);
        self::assertStringContainsString("\r\n", $out);
        self::assertStringNotContainsString("\n\n", str_replace("\r\n", '', $out)); // no bare \n left over
        self::assertStringNotContainsString("\n", str_replace("\r\n", '', $out), 'interactive output is fully CRLF');
    }

    public function test_non_pty_exec_keeps_bare_lf(): void
    {
        // `ssh host cmd` with no pty: real openssh writes the raw command stdout with bare \n. Cooking
        // it to \r\n would be a tell, so the exec path must not convert.
        $out = $this->shell()->run('cat /etc/passwd', $this->session(), false);
        self::assertStringContainsString("\n", $out);
        self::assertStringNotContainsString("\r\n", $out, 'non-pty exec must not CRLF-cook');
        self::assertStringNotContainsString("\r", $out);
    }

    public function test_default_is_interactive(): void
    {
        // The default (telnet + interactive ssh) stays CRLF — only the exec path opts out.
        $a = $this->shell()->run('cat /etc/passwd', $this->session());
        $b = $this->shell()->run('cat /etc/passwd', $this->session(), true);
        self::assertSame($b, $a);
    }
}

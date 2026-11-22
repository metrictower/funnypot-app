<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Cmdi;

use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Tarpit\Cmdi\FootholdFacts;
use Funnypot\App\Tarpit\Cmdi\FootholdIdentity;
use Funnypot\App\Tarpit\FootholdRewriter;
use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * The shared command table behind the fake console. Every surface (header, landing, command output)
 * must tell one story per identity, recon must never come back empty, and every path an answer prints
 * must itself exist.
 */
final class FootholdFactsTest extends TestCase
{
    private const SEED = 4242;
    private const NOW = 1795000000;

    /** The stock applets the landing and a post-exploitation checklist reach for. */
    private const APPLETS = [
        'cat', 'ls', 'grep', 'egrep', 'fgrep', 'find', 'head', 'tail', 'wc', 'sort', 'uniq', 'cut', 'tr', 'sed',
        'awk', 'xargs', 'tee', 'printf', 'env', 'printenv', 'uname', 'hostname', 'id', 'whoami', 'date', 'df',
        'du', 'free', 'uptime', 'ps', 'which', 'stat', 'readlink', 'realpath', 'basename', 'dirname', 'md5sum',
        'sha1sum', 'sha256sum', 'base64', 'tar', 'gzip', 'gunzip', 'zcat', 'sleep', 'timeout', 'nc', 'wget',
        'ping', 'nslookup', 'ip', 'ifconfig', 'netstat', 'mount', 'touch', 'mkdir', 'rm', 'cp', 'mv', 'chmod',
        'chown', 'ln', 'vi', 'less', 'more', 'ash', 'sh', 'su',
    ];

    /** @var list<string> */
    private const RECON = [
        'ps', 'ps aux', 'ip a', 'ip addr', 'ifconfig', 'netstat -tlnp', 'netstat -an', 'ss -tlnp', 'df', 'df -h',
        'mount', 'free', 'free -m', 'uptime', 'w', 'who', 'date', 'du -sh', 'uname -a', 'env', 'printenv',
    ];

    private static function facts(FootholdIdentity $id, string $poweredBy = ''): FootholdFacts
    {
        return FootholdFacts::forPersona(self::SEED, $id, $poweredBy, static fn (): int => self::NOW);
    }

    private static function sh(FootholdFacts $f, string $cmd): string
    {
        $out = $f->run(explode(' ', $cmd));
        self::assertNotNull($out, "{$cmd} must render when reflection is allowed");

        return $out;
    }

    /** @return array<string,array{0:FootholdIdentity}> */
    public static function identities(): array
    {
        return ['www-data' => [FootholdIdentity::www()], 'root' => [FootholdIdentity::root()]];
    }

    // --- (a) one identity, every surface agrees ---------------------------------------------------

    /** @dataProvider identities */
    public function test_every_surface_agrees_on_the_identity(FootholdIdentity $id): void
    {
        $f = self::facts($id);
        $rewriter = new FootholdRewriter(self::SEED, LabyrinthController::entryHint());
        $landing = $rewriter->landing($id);

        self::assertSame($id->idLine() . "\n", self::sh($f, 'id'));
        self::assertSame($id->name . "\n", self::sh($f, 'whoami'));
        self::assertSame(CannedData::PASSWD, self::sh($f, 'cat /etc/passwd'), 'byte-parity with core LFI answers');
        self::assertSame(CannedData::GROUP, self::sh($f, 'cat /etc/group'));

        $environ = self::sh($f, 'cat /proc/self/environ');
        self::assertStringContainsString("USER={$id->name}\x00", $environ);
        self::assertStringContainsString("HOME={$id->home}\x00", $environ);
        self::assertStringContainsString("USER={$id->name}\n", self::sh($f, 'env'));

        if ($id->isRoot()) {
            self::assertSame(".\n..\n", self::sh($f, 'ls -a /root'), 'root sees an empty home');
            self::assertSame(CannedData::SHADOW, self::sh($f, 'cat /etc/shadow'), 'root reads the same inert shadow core serves');
            self::assertStringNotContainsString('<b>user:</b>', $landing, 'the root header has no user line');
        } else {
            self::assertSame(CannedData::ENVIRON, $environ, 'www-data matches core environ byte for byte');
            self::assertStringContainsString('Permission denied', self::sh($f, 'ls -a /root'));
            self::assertSame("cat: can't open '/etc/shadow': Permission denied\n", self::sh($f, 'cat /etc/shadow'));
            self::assertStringContainsString('<b>user:</b> ' . $id->idLine() . '<br>', $landing, 'the header user line is the id output');
            self::assertStringContainsString("\$ id\n" . $id->idLine() . "\n", $landing, 'the landing id line is the id output');
        }
    }

    public function test_www_data_landing_is_the_base_transcript_bar_the_shell_prefix(): void
    {
        $f = self::facts(FootholdIdentity::www());
        $registry = $f->registry();
        $expected = "\$ id\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n\$ sudo -i\nsh: sudo: not found\n"
            . "\$ cat /etc/shadow\ncat: can't open '/etc/shadow': Permission denied\n\$ ls -a /root\nls: /root: Permission denied\n"
            . "\$ cat /etc/os-release\nNAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME=\"Alpine Linux v3.19\"\n"
            . "\$ ls -a /home /srv /opt /data /var/www/html\n/home:\n.\n..\n\n/srv:\n.\n..\n\n/opt:\n.\n..\n\n/data:\n.\n..\n\n/var/www/html:\n.\n..\nindex.php\n"
            . "\$ touch /var/www/html/probe\ntouch: /var/www/html/probe: Read-only file system\n"
            . "\$ mount | grep ' / '\n" . FootholdFacts::OVERLAY_LINE . "\n"
            . "\$ grep Cap /proc/self/status\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
            . "\$ wget -T 3 -qO- https://{$registry}/v2/\nwget: can't connect to remote host: Connection refused\n"
            . "\$ cat /run/deploy/app.env\n# rendered by the deploy controller at rollout; application secrets are mounted at runtime, not in this file\n"
            . "APP_ROLE=web\nAPP_DB_HOST=db.svc.gateway.internal\nAPP_REGISTRY={$registry}\n"
            . "# admin console + customer DB are reachable only through the egress gateway, not from this pod\n"
            . "# legacy audit-archive export is still live during the SIEM cutover\n\$ ";

        self::assertSame($expected, $f->landingTranscript());
    }

    // --- (b) closure ------------------------------------------------------------------------------

    /** @dataProvider identities */
    public function test_no_stock_applet_answers_not_found(FootholdIdentity $id): void
    {
        $f = self::facts($id);
        foreach (self::APPLETS as $applet) {
            self::assertTrue($f->isCommand($applet), "{$applet} is on PATH or a builtin");
            self::assertStringNotContainsString(': not found', self::sh($f, $applet), "{$applet} with no arguments");
            if ($applet !== 'printf') {
                self::assertNotSame('', self::sh($f, "which {$applet}") . (in_array($applet, FootholdFacts::BUILTINS, true) ? 'builtin' : ''), "which {$applet}");
            }
        }
        self::assertSame("sh: curl: not found\n", self::sh($f, 'curl'), 'a tool the minimal image lacks');
    }

    public function test_php_version_follows_the_effective_powered_by(): void
    {
        $default = 'PHP/' . PersonaIdentity::fromSeed(self::SEED)->productVersion('php');
        self::assertStringStartsWith('PHP ' . substr($default, 4) . ' (cli)', self::sh(self::facts(FootholdIdentity::www(), $default), 'php -v'));
        self::assertStringStartsWith('PHP ' . substr($default, 4) . ' (cli)', self::sh(self::facts(FootholdIdentity::www()), 'php -v'), 'no override: the persona version');
        self::assertStringStartsWith('PHP 7.4.33 (cli)', self::sh(self::facts(FootholdIdentity::www(), 'PHP/7.4.33'), 'php -v'), 'the FUNNYPOT_POWERED_BY override');
        self::assertSame('Could not open input file: nope.php' . "\n", self::sh(self::facts(FootholdIdentity::www()), 'php nope.php'));
    }

    /** Paths printed by any output. Error lines and failed-write commands name paths that need not exist. */
    private static function printedPaths(string $text): array
    {
        $paths = [];
        foreach (explode("\n", str_replace("\x00", "\n", $text)) as $line) {
            if (preg_match('~No such file or directory|Read-only file system|not found|can\'t create|No space left~', $line) === 1
                || preg_match('~^\$ (touch|mkdir|rm|cp|mv|tee) ~', $line) === 1) {
                continue;
            }
            if (preg_match_all('~(?:^|[\s\'"(:])(/[A-Za-z0-9._-][A-Za-z0-9._/-]*)~', $line, $m) > 0) {
                foreach ($m[1] as $p) {
                    $paths[rtrim($p, '.')] = true;
                }
            }
        }

        return array_keys($paths);
    }

    public function test_every_printed_path_exists(): void
    {
        $seen = [];
        foreach ([FootholdIdentity::www(), FootholdIdentity::root()] as $id) {
            $f = self::facts($id);
            $texts = [$f->landingTranscript()];
            foreach (array_merge(self::RECON, ['cat /etc/passwd', 'cat /etc/group', 'cat /proc/self/environ', 'cat /etc/hosts', 'cat /proc/mounts',
                'cat /run/deploy/app.env', 'cat /etc/profile', 'cat /etc/shells', 'cat /usr/local/etc/php-fpm.conf', 'which ls cat id php sh bash',
                'type id cd', 'ls -la /', 'ls -l /bin', 'ls -la /dev', 'find /', 'stat /etc/passwd', 'pwd', 'cd /']) as $cmd) {
                $texts[] = self::sh($f, $cmd);
            }
            $queue = [];
            foreach ($texts as $t) {
                array_push($queue, ...self::printedPaths($t));
            }
            // Follow each printed path one level: what it lists or holds must be closed too.
            for ($i = 0; $i < count($queue) && $i < 2000; $i++) {
                $p = $queue[$i];
                if ($p === '/nonexistent' || isset($seen[$id->name][$p])) {
                    continue;
                }
                $seen[$id->name][$p] = true;
                self::assertTrue($f->exists($p), "{$id->name}: printed path {$p} must exist");
                foreach (["ls -d {$p}", "cat {$p}"] as $probe) {
                    $out = self::sh($f, $probe);
                    self::assertStringNotContainsString('No such file or directory', $out, "{$id->name}: {$probe}");
                    if (str_starts_with($probe, 'cat') && !str_starts_with($p, '/proc/self/fd')) {
                        array_push($queue, ...self::printedPaths($out));
                    }
                }
            }
        }
        $all = array_merge(array_keys($seen['www-data']), array_keys($seen['root']));
        self::assertNotEmpty($all);
        foreach (['/bin/bash', '/usr/sbin/nologin', '/root', '/etc/shadow', '/run/deploy/app.env', '/bin/false', '/run/sshd'] as $must) {
            self::assertContains($must, $all, "{$must} is printed and checked");
        }
    }

    public function test_passwd_shells_behave(): void
    {
        $f = self::facts(FootholdIdentity::www());
        self::assertSame('', self::sh($f, 'bash'), 'bash with stdin /dev/null prints nothing');
        self::assertSame("This account is not available\n", self::sh($f, '/usr/sbin/nologin'));
        self::assertSame('', self::sh($f, '/bin/false'));
        self::assertStringContainsString('sshd', self::sh($f, 'ls -la /run'));
    }

    // --- (c)–(h) recon, which, globs, tilde, onward pointer ---------------------------------------

    /** @dataProvider identities */
    public function test_recon_outputs_are_pairwise_distinct(FootholdIdentity $id): void
    {
        $f = self::facts($id);
        $outs = array_map(static fn (string $c): string => self::sh($f, $c), ['id', 'whoami', 'hostname', 'pwd', 'env']);
        self::assertSame($outs, array_values(array_unique($outs)), 'id/whoami/hostname/pwd/env must not share an answer');
    }

    public function test_which_prints_nothing_for_absent_tools(): void
    {
        self::assertSame('', self::sh(self::facts(FootholdIdentity::www()), 'which python3 psql'));
    }

    public function test_globs_and_tilde_expand_against_the_table(): void
    {
        $www = self::facts(FootholdIdentity::www());
        self::assertSame("/var/www/html/index.php\n", self::sh($www, 'ls /var/www/html/*.php'));
        self::assertSame("index.php\n", self::sh($www, 'ls *.php'));
        self::assertSame("cat: can't open '/var/www/.profile': No such file or directory\n", self::sh($www, 'cat ~/.profile'));
        self::assertSame("cat: can't open '/root/.profile': No such file or directory\n", self::sh(self::facts(FootholdIdentity::root()), 'cat ~/.profile'));
        self::assertSame("ls: /etc/*.nomatch: No such file or directory\n", self::sh($www, 'ls /etc/*.nomatch'), 'an unmatched glob stays literal');
    }

    public function test_deploy_file_points_onward(): void
    {
        self::assertStringContainsString('legacy audit-archive export is still live', self::sh(self::facts(FootholdIdentity::www()), 'cat /run/deploy/app.env'));
    }

    // --- (i) identity draw ------------------------------------------------------------------------

    public function test_identity_draw_is_deterministic_and_about_a_quarter_root(): void
    {
        $key = random_bytes(32);
        self::assertSame(FootholdIdentity::forSource($key, '198.51.100.7')->name, FootholdIdentity::forSource($key, '198.51.100.7')->name);
        $root = 0;
        for ($i = 0; $i < 10000; $i++) {
            if (FootholdIdentity::forSource($key, '10.' . intdiv($i, 256) % 256 . '.' . ($i % 256) . '.' . ($i % 7))->isRoot()) {
                $root++;
            }
        }
        self::assertGreaterThanOrEqual(2000, $root);
        self::assertLessThanOrEqual(3000, $root);
        self::assertSame('root', FootholdIdentity::resolve('root', $key, '1.2.3.4')->name, 'the operator pin wins');
        self::assertSame('www-data', FootholdIdentity::resolve('www-data', $key, '1.2.3.4')->name);
    }

    // --- (j) recon is never empty, and the outputs agree with each other --------------------------

    /** @dataProvider identities */
    public function test_recon_is_never_empty_and_cross_consistent(FootholdIdentity $id): void
    {
        $f = self::facts($id);
        foreach (self::RECON as $cmd) {
            self::assertNotSame('', trim(self::sh($f, $cmd)), "{$cmd} as {$id->name}");
            self::assertStringNotContainsString('not found', self::sh($f, $cmd), $cmd);
        }
        self::assertStringContainsString(FootholdFacts::OVERLAY_LINE, self::sh($f, 'mount'));
        self::assertStringContainsString(FootholdFacts::OVERLAY_LINE, $f->landingTranscript());
        self::assertMatchesRegularExpression('~^overlay\s+\d+\s+\d+\s+\d+\s+\d+% /$~m', self::sh($f, 'df'));

        $users = array_map(static fn (string $l): string => explode(':', $l)[0], array_filter(explode("\n", CannedData::PASSWD)));
        foreach (array_slice(explode("\n", trim(self::sh($f, 'ps aux'))), 1) as $row) {
            self::assertContains(preg_split('~\s+~', trim($row))[1], $users, "ps user in passwd: {$row}");
        }
        self::assertStringContainsString(':9000', self::sh($f, 'netstat -tlnp'));
        self::assertStringContainsString(':9000', self::sh($f, 'ss -tlnp'));

        $host = trim(self::sh($f, 'hostname'));
        self::assertSame("Linux {$host} 5.15.0 x86_64 Linux\n", self::sh($f, 'uname -a'));
        self::assertSame($host . "\n", self::sh($f, 'cat /etc/hostname'));
        self::assertStringContainsString(FootholdFacts::POD_IP . "\t" . $host, self::sh($f, 'cat /etc/hosts'));
        self::assertStringContainsString('inet ' . FootholdFacts::POD_IP . '/24', self::sh($f, 'ip a'));

        self::assertSame("        0         0         0\n", self::sh($f, 'wc'));
        self::assertSame("d41d8cd98f00b204e9800998ecf8427e  -\n", self::sh($f, 'md5sum'));
        self::assertSame("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -\n", self::sh($f, 'sha256sum'));
        self::assertSame('', self::sh($f, 'grep x'));
        self::assertSame('', self::sh($f, 'sort'));
    }

    /** @dataProvider identities */
    public function test_the_pool_config_and_process_list_agree_with_the_identity(FootholdIdentity $id): void
    {
        $f = self::facts($id);
        $conf = self::sh($f, 'cat /usr/local/etc/php-fpm.d/www.conf');
        self::assertStringContainsString("user = {$id->name}\ngroup = {$id->name}\n", $conf);
        $ps = self::sh($f, 'ps aux');
        self::assertMatchesRegularExpression('~^\s+12 ' . preg_quote($id->name, '~') . '\s.*pool www$~m', $ps, 'the workers run as the pool user');
        self::assertStringContainsString($id->isRoot() ? '/sbin/tini -- php-fpm -R' : "/sbin/tini -- php-fpm\n", $ps, 'a root pool needs -R');
        $cmdline = self::sh($f, 'cat /proc/1/cmdline');
        self::assertSame($id->isRoot(), str_contains($cmdline, "-R\x00"), '/proc agrees with ps');
        self::assertStringContainsString('Uid:' . "\t{$id->uid}\t", self::sh($f, 'cat /proc/12/status'));
    }

    public function test_empty_words_never_raise_warnings(): void
    {
        $f = self::facts(FootholdIdentity::www());
        foreach (FootholdFacts::commandNames() as $n) {
            $f->run([$n, '']);
            $f->run([$n, '', '']);
        }
        foreach (['timeout', 'id', 'df', 'du', 'nice'] as $n) {
            self::assertIsString($f->run([$n, '', 'id']));
        }
        self::assertSame("sh: : not found\n", $f->run(['']));
    }

    // --- (k) the root landing never volunteers credential material --------------------------------

    public function test_root_landing_holds_no_credential_material(): void
    {
        $landing = (new FootholdRewriter(self::SEED, LabyrinthController::entryHint()))->landing(FootholdIdentity::root());
        foreach (['$6$', 'uid=', 'gid=0', 'root:', '<b>user:</b>'] as $needle) {
            self::assertStringNotContainsString($needle, $landing);
        }
        self::assertSame(CannedData::SHADOW, self::sh(self::facts(FootholdIdentity::root()), 'cat /etc/shadow'), 'shadow only when asked');
    }

    // --- reflection rules -------------------------------------------------------------------------

    public function test_attacker_text_needs_a_reflectable_value(): void
    {
        $f = self::facts(FootholdIdentity::www());
        self::assertNull($f->run(['echo', 'FPCANARY7Q'], false), 'echo needs a slot');
        self::assertNull($f->run(['FPCANARY7Q'], false), 'an unknown command name is attacker text');
        self::assertNull($f->run(['cat', '/etc/shadow-'], false), 'an unknown path is attacker text');
        self::assertSame("sh: curl: not found\n", $f->run(['curl'], false), 'a fixed absent-tool word is not attacker text');
        self::assertSame(FootholdIdentity::www()->idLine() . "\n", $f->run(['id'], false));
        self::assertSame(CannedData::PASSWD, $f->run(['cat', '/etc/passwd'], false), 'a known file is closed-set');
        self::assertSame("Linux app-prod-01 5.15.0 x86_64 Linux\n", $f->run(['uname', '-a'], false));
        self::assertSame("app-prod-01\n", $f->run(['cut', '-dQ', '-f1,1', '/etc/hostname'], false), 'no delimiter in the line: printed whole, no attacker byte');
        self::assertNull($f->run(['cut', '-d-', '-f1,3', '/etc/hostname'], false), 'joining fields would show the typed delimiter: a GET gets the landing');
        self::assertSame("app-01\n", $f->run(['cut', '-d-', '-f1,3', '/etc/hostname']), 'from a body it is a slot');

        self::assertSame("FPCANARY7Q\n", $f->run(['echo', 'FPCANARY7Q']));
        self::assertSame('', $f->run(['echo', '<b>x</b>']), 'unsafe characters never reflect, even from a body');
        self::assertNull($f->run(['echo', '<b>x</b>'], false));
        self::assertSame(str_repeat('A', FootholdFacts::ECHO_CAP) . "\n", $f->run(['echo', str_repeat('A', 300)]), 'echo is capped');
    }

    /** @dataProvider identities */
    public function test_expansions_agree_with_the_environment(FootholdIdentity $id): void
    {
        $f = self::facts($id);
        $exp = static fn (string $line): ?string => $f->run(\Funnypot\App\Tarpit\Cmdi\ShellLexer::lex($line)->argv);
        foreach (['PATH', 'HOME', 'USER', 'PWD', 'SHELL'] as $var) {
            self::assertSame(self::sh($f, "printenv {$var}"), $exp('echo $' . $var), "\${$var} expands from the same environment printenv prints");
            self::assertSame(self::sh($f, "printenv {$var}"), $exp('echo ${' . $var . '}'));
        }
        self::assertSame($id->home . "\n", $exp('echo $HOME'), 'identity-aware');
        self::assertSame("end\n", $exp('echo $NOT_SET end'), 'an unset name is empty');
        self::assertSame("0 213\n", $exp('echo $? $$'));
        self::assertSame(self::sh($f, 'cat /etc/hostname'), $exp('cat${IFS}/etc/hostname'), 'an unquoted expansion splits on blanks');
        self::assertSame("cat: can't open '{$id->home}/.profile': No such file or directory\n", $exp('cat $HOME/.profile'));
    }

    public function test_every_spelling_of_a_command_gets_one_answer(): void
    {
        foreach ([FootholdIdentity::www(), FootholdIdentity::root()] as $id) {
            foreach ([true, false] as $reflect) {
                $runs = static fn (string $line): ?string => self::facts($id)->run(\Funnypot\App\Tarpit\Cmdi\ShellLexer::lex($line)->argv, $reflect);
                foreach ([['cat /etc/passwd', 'cat${IFS}/etc/passwd', 'cat$IFS/etc/passwd', "cat\t/etc/passwd", 'cat  /etc/passwd'],
                    ['uname -a', 'uname${IFS}-a', "uname\t-a"], ['kill 1', 'kill${IFS}0000001', 'kill 0001']] as $spellings) {
                    $first = $runs($spellings[0]);
                    foreach ($spellings as $s) {
                        self::assertSame($first, $runs($s), "{$s} answers like {$spellings[0]}");
                    }
                }
            }
        }
        self::assertSame("sh: can't kill pid 1: Operation not permitted\n", self::facts(FootholdIdentity::www())->run(\Funnypot\App\Tarpit\Cmdi\ShellLexer::lex('kill${IFS}0000001')->argv, false), 'busybox prints the number, not the padding');
    }

    public function test_globs_list_every_match(): void
    {
        $f = self::facts(FootholdIdentity::www());
        $names = explode("\n", trim(self::sh($f, 'ls /usr/bin')));
        self::assertGreaterThan(64, count($names), 'sanity: more entries than the operand cap');
        self::assertCount(count($names), explode("\n", trim(self::sh(self::facts(FootholdIdentity::www()), 'ls /usr/bin/*'))), 'the glob lists them all');
        self::assertStringContainsString("/usr/bin/yes\n", self::sh(self::facts(FootholdIdentity::www()), 'ls /usr/bin/*'));
    }

    public function test_cut_and_kill_follow_busybox(): void
    {
        $f = self::facts(FootholdIdentity::www());
        self::assertSame(self::sh($f, 'cut -d: -f1 /etc/passwd'), self::sh($f, 'cut -d: -f1,1 /etc/passwd'), 'a selected field prints once');
        self::assertStringStartsWith("root:0\n", self::sh($f, 'cut -d: -f1,3 /etc/passwd'), 'fields in order, joined by the delimiter');
        self::assertSame("app-prod-01\n", self::sh($f, 'cut -d: -f2 /etc/hostname'), 'a line without the delimiter passes through whole');
        self::assertSame("sh: can't kill pid 31337: No such process\n", self::sh($f, 'kill 31337'));
        self::assertSame("sh: can't kill pid 1: Operation not permitted\n", self::sh($f, 'kill 1'));
        self::assertSame('', self::sh($f, 'kill 12'), 'www-data may signal its own worker');
        self::assertSame('', self::sh(self::facts(FootholdIdentity::root()), 'kill 1'));
    }

    /** One request's work is bounded whatever the line asks for: time, memory, and no warnings. */
    public function test_worst_case_commands_stay_within_the_budget(): void
    {
        $roots = array_fill(0, 2000, '/');
        $cases = [
            'grep -r' => array_merge(['grep', '-r', 'a'], $roots),
            'grep -rv' => array_merge(['grep', '-rv', 'Q'], $roots),
            'find' => array_merge(['find'], $roots),
            'find -name long' => array_merge(['find'], array_fill(0, 3, '/'), ['-name', str_repeat('a', 1100)]),
            'du' => array_merge(['du', '-sh'], $roots),
            'ls -la' => array_merge(['ls', '-la'], array_fill(0, 2000, '/usr/bin')),
            'cat' => array_merge(['cat'], array_fill(0, 2000, '/etc/passwd')),
            'glob' => array_merge(['ls'], array_fill(0, 2000, '/usr/bin/*')),
            'grep long pattern' => ['grep', '-r', str_repeat('a.', 2000), '/'],
        ];
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            $warnings[] = $msg;

            return true;
        });
        try {
            foreach ($cases as $name => $argv) {
                foreach ([FootholdIdentity::www(), FootholdIdentity::root()] as $id) {
                    $f = self::facts($id);
                    memory_reset_peak_usage();
                    $base = memory_get_usage();
                    $t = hrtime(true);
                    $out = $f->run($argv);
                    $ms = (hrtime(true) - $t) / 1e6;
                    self::assertIsString($out, $name);
                    self::assertLessThanOrEqual(12288, strlen((string) $out), "{$name}: the output is capped");
                    self::assertLessThan(60.0, $ms, sprintf('%s as %s took %.1f ms', $name, $id->name, $ms));
                    self::assertLessThan(8 * 1048576, memory_get_peak_usage() - $base, "{$name}: peak memory");
                }
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $warnings, 'no warning ever reaches the log');
    }

    /** Linux's NAME_MAX / PATH_MAX, after expansion: busybox's ENAMETOOLONG line, with a capped prefix. */
    public function test_long_paths_answer_file_name_too_long(): void
    {
        $fill = static function (string $head, string $unit): string {
            while (strlen($head) + strlen($unit) <= \Funnypot\App\Tarpit\Cmdi\ShellLexer::MAX_INPUT) {
                $head .= $unit;
            }

            return $head;
        };
        $f = self::facts(FootholdIdentity::www());
        $lex = static fn (string $line): array => \Funnypot\App\Tarpit\Cmdi\ShellLexer::lex($line)->argv;
        $long = '/' . str_repeat('a', 300);
        self::assertSame("cat: can't open '" . substr($long, 0, FootholdFacts::PATH_CAP) . "...': File name too long\n", $f->run(['cat', $long]), 'a component over 255 bytes');
        $path = self::sh($f, 'printenv PATH');
        $prefix = substr(str_repeat(trim($path), 3), 0, FootholdFacts::PATH_CAP);
        self::assertSame("cat: can't open '{$prefix}...': File name too long\n", $f->run($lex($fill('cat ', '$PATH'))), 'a 42 KB path from $PATH');
        self::assertSame("ls: {$prefix}...: File name too long\n", $f->run($lex($fill('ls -la ', '$PATH'))));
        self::assertSame("stat: can't stat '{$prefix}...': File name too long\n", $f->run($lex($fill('stat ', '$PATH'))));
        self::assertStringStartsWith("sh: cd: line 0: can't cd to {$prefix}...: File name too long", (string) $f->run($lex($fill('cd ', '$PATH'))));
        self::assertSame("sh: {$prefix}...: File name too long\n", $f->run($lex($fill('', '$PATH'))), 'the shell resolving a too-long command');
        self::assertNull($f->run($lex($fill('cat ', '$PATH')), false), 'from a GET the attacker path is never shown');
        self::assertNull($f->run(['cat', $long], false));
    }

    public function test_expansion_growth_is_capped(): void
    {
        // More markers than a 4 KB line can hold: the cap answers E2BIG instead of building the value.
        $argv = ['cat', str_repeat("\x00uPATH\x00", 1200)];
        $f = self::facts(FootholdIdentity::www());
        $t = hrtime(true);
        self::assertSame("sh: cat: Argument list too long\n", $f->run($argv));
        self::assertLessThan(30.0, (hrtime(true) - $t) / 1e6);
    }

    public function test_the_long_path_repro_stays_within_the_budget(): void
    {
        $line = 'cat ';
        while (strlen($line) + 5 <= \Funnypot\App\Tarpit\Cmdi\ShellLexer::MAX_INPUT) {
            $line .= '$PATH';
        }
        $argv = \Funnypot\App\Tarpit\Cmdi\ShellLexer::lex($line)->argv;
        foreach ([FootholdIdentity::www(), FootholdIdentity::root()] as $id) {
            foreach ([true, false] as $reflect) {
                $t = hrtime(true);
                self::facts($id)->run($argv, $reflect);
                self::assertLessThan(30.0, (hrtime(true) - $t) / 1e6, "{$id->name}, reflect=" . var_export($reflect, true));
            }
        }
    }

    public function test_getent_matches_whole_fields(): void
    {
        $f = self::facts(FootholdIdentity::www());
        self::assertSame("root:x:0:0:root:/root:/bin/bash\n", self::sh($f, 'getent passwd root'));
        self::assertSame("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", self::sh($f, 'getent passwd 33'), 'by numeric id');
        self::assertSame('', self::sh($f, 'getent passwd ro'), 'a prefix is not a match');
        self::assertSame('', self::sh($f, 'getent passwd .*'), 'a key is never a pattern');
        self::assertSame("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", self::sh($f, 'getent passwd root daemon'));
        self::assertSame("www-data:x:33:\n", self::sh($f, 'getent group www-data'));
        self::assertSame(FootholdFacts::POD_IP . "\tapp-prod-01\n", self::sh($f, 'getent hosts app-prod-01'));
        self::assertSame("127.0.0.1\tlocalhost\n", self::sh($f, 'getent hosts 127.0.0.1'));
    }

    /** No attacker text is ever compiled into a regex: long or hostile keys raise no warning anywhere. */
    public function test_hostile_keys_raise_no_warnings(): void
    {
        $long = str_repeat(trim(self::sh(self::facts(FootholdIdentity::www()), 'printenv PATH')), 70);
        $keys = [$long, str_repeat('(', 5000), '(*', '[', '\\', ')', 'a{1000000}', "a\x00b", "\xff\xfe", '~', '.*', str_repeat('.', 4000), str_repeat('a', 100000)];
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            $warnings[] = $msg;

            return true;
        });
        try {
            foreach ([FootholdIdentity::www(), FootholdIdentity::root()] as $id) {
                foreach ($keys as $k) {
                    foreach ([
                        ['getent', 'passwd', $k], ['getent', 'group', $k], ['getent', 'hosts', $k], ['getent', 'passwd', 'root', $k],
                        ['grep', $k, '/etc/passwd'], ['grep', '-i', $k, '/etc/passwd'], ['grep', '-rv', $k, '/etc'], ['egrep', $k, '/etc/group'],
                        ['find', '/etc', '-name', $k], ['ls', '/usr/bin/' . $k . '*'], ['date', '+' . $k], ['cut', '-d' . $k, '-f' . $k, '/etc/passwd'],
                        ['which', $k], ['type', $k], ['id', $k], ['printenv', $k], ['kill', $k], ['head', '-n', $k, '/etc/passwd'], ['stat', $k], ['cat', $k],
                        ['printf', $k], ['echo', $k], ['sysctl', $k], ['pidof', $k], [$k],
                    ] as $argv) {
                        foreach ([true, false] as $reflect) {
                            $out = self::facts($id)->run($argv, $reflect);
                            self::assertTrue($out === null || is_string($out));
                        }
                    }
                    \Funnypot\App\Tarpit\Cmdi\ShellLexer::lex('getent passwd ' . $k);
                    \Funnypot\App\Tarpit\Cmdi\AdaptiveShell::sleepOf(['sleep', $k]);
                }
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $warnings, 'no warning reaches the log');
    }

    public function test_writes_and_egress_always_fail(): void
    {
        foreach ([FootholdIdentity::www(), FootholdIdentity::root()] as $id) {
            $f = self::facts($id);
            self::assertStringContainsString('Read-only file system', self::sh($f, 'touch /tmp/x'));
            self::assertStringContainsString('Read-only file system', self::sh($f, 'mkdir /var/www/html/up'));
            self::assertStringContainsString('No space left on device', self::sh($f, 'touch /dev/shm/x'));
            self::assertStringContainsString("bad address 'example.com'", self::sh($f, 'wget http://example.com/x'));
            self::assertStringContainsString('Connection refused', self::sh($f, 'nc 10.0.0.5 4444'));
        }
        self::assertSame("ping: permission denied (are you root?)\n", self::sh(self::facts(FootholdIdentity::www()), 'ping 8.8.8.8'));
        self::assertStringContainsString('Network unreachable', self::sh(self::facts(FootholdIdentity::root()), 'ping 8.8.8.8'));
        self::assertSame("su: must be suid to work properly\n", self::sh(self::facts(FootholdIdentity::www()), 'su'));
        self::assertSame("cat: can't open '/root/.ssh/id_rsa': Permission denied\n", self::sh(self::facts(FootholdIdentity::www()), 'cat /root/.ssh/id_rsa'), 'www-data cannot even look inside /root');
        self::assertSame("cat: can't open '/root/.ssh/id_rsa': No such file or directory\n", self::sh(self::facts(FootholdIdentity::root()), 'cat /root/.ssh/id_rsa'), 'root finds no key');
    }

    public function test_output_is_deterministic_for_a_fixed_clock(): void
    {
        foreach (['uptime', 'date', 'ps aux', 'cat /etc/hosts'] as $cmd) {
            self::assertSame(self::sh(self::facts(FootholdIdentity::www()), $cmd), self::sh(self::facts(FootholdIdentity::www()), $cmd), $cmd);
        }
    }
}

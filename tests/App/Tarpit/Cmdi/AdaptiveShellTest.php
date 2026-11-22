<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Cmdi;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Tarpit\Cmdi\AdaptiveShell;
use Funnypot\App\Tarpit\Cmdi\FootholdIdentity;
use Funnypot\App\Tarpit\Cmdi\Outcome;
use Funnypot\App\Tarpit\Cmdi\ShellTurn;
use Funnypot\App\Tarpit\Cmdi\SourceState;
use Funnypot\App\Tarpit\FootholdRewriter;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\TemplateMatch;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

/** AdaptiveShell on its own: the gates, ownership, the page it writes and what it records. */
final class AdaptiveShellTest extends TestCase
{
    /** @var list<ConsoleHarness> */
    private array $harnesses = [];

    protected function tearDown(): void
    {
        foreach ($this->harnesses as $h) {
            $h->cleanup();
        }
        $this->harnesses = [];
    }

    /** @param array<string,mixed> $o */
    private function harness(array $o = []): ConsoleHarness
    {
        return $this->harnesses[] = ConsoleHarness::build($o);
    }

    private static function policy(array $overrides = []): EmulationPolicy
    {
        $f = tempnam(sys_get_temp_dir(), 'fpv');
        file_put_contents($f, json_encode(['vulns' => $overrides]));
        $p = EmulationPolicy::fromPackage($f);
        @unlink($f);

        return $p;
    }

    private static function ctx(string $method, string $path, string $query = '', ?string $body = null): RequestContext
    {
        return new RequestContext($method, $path, $query, $body !== null ? ['Content-Type' => 'application/x-www-form-urlencoded'] : [], $body);
    }

    private static function detection(string $id, array $tags): Detection
    {
        return new Detection(true, [new TemplateMatch($id, 'critical', $tags)], 'cluster', 'critical');
    }

    /** The engine's real answer for a request, as handle() would get it. */
    private static function engine(RequestContext $ctx, AppConfig $config): SynthesizedResponse
    {
        $hp = Honeypot::default(IdentityTestSupport::coreConfigFactory()->build($config, EmulationPolicy::fromPackage(null), static fn () => 'x'));
        $r = $hp->respond($ctx);
        self::assertNotNull($r);

        return $r;
    }

    public function test_keys_are_distinct_and_deterministic(): void
    {
        $fs = IdentityTestSupport::httpIdentity()->filesystemKey();
        [$a, $b, $c] = AdaptiveShell::keysFrom($fs);
        self::assertSame([$a, $b, $c], AdaptiveShell::keysFrom($fs));
        self::assertCount(3, array_unique([$a, $b, $c]));
        self::assertNotSame([$a, $b, $c], AdaptiveShell::keysFrom($fs . 'x'));
    }

    public function test_the_console_honours_every_existing_gate(): void
    {
        self::assertTrue($this->harness()->shell->armed(self::policy()));
        self::assertFalse($this->harness()->shell->armed(self::policy(['attack-webshell-panel' => false])), 'catalog off');
        self::assertFalse($this->harness(['env' => ['FUNNYPOT_CEILING' => 'high']])->shell->armed(self::policy()), 'ceiling below critical');
        self::assertFalse($this->harness(['env' => ['FUNNYPOT_TARPIT_CMDI_SYNTAX' => '0']])->shell->armed(self::policy()), 'console flag off');
        self::assertFalse($this->harness(['env' => ['FUNNYPOT_TARPIT' => '0']])->shell->armed(self::policy()), 'tarpit off');
        self::assertNull($this->harness(['env' => ['FUNNYPOT_CEILING' => 'high']])->shell->fallbackIdentity('1.2.3.4', self::policy()), 'no identity change when not armed');
    }

    public function test_console_paths_and_owned_rules(): void
    {
        foreach (['/admin/root/html', '/admin/root/post', '/admin/root/link', '/admin/root/post/', '/uploads/shell.php', '/x/WSO.php', '/c99.php'] as $p) {
            self::assertTrue(AdaptiveShell::isConsolePath($p), $p);
        }
        foreach (['/admin/root', '/upload.php', '/index.php', '/shell.php.bak', '/admin/root/html/x'] as $p) {
            self::assertFalse(AdaptiveShell::isConsolePath($p), $p);
        }
        self::assertTrue(AdaptiveShell::ownsDetection(self::detection('attack-webshell-panel', ['attack'])));
        self::assertTrue(AdaptiveShell::ownsDetection(self::detection('attack-cmdi-unix', ['attack'])));
        self::assertTrue(AdaptiveShell::ownsDetection(self::detection('attack-lfi-shadow', ['attack'])));
        self::assertTrue(AdaptiveShell::ownsDetection(self::detection('other', ['attack', 'command-injection'])));
        self::assertFalse(AdaptiveShell::ownsDetection(self::detection('attack-sqli', ['attack', 'sqli'])));
        self::assertFalse(AdaptiveShell::ownsDetection(Detection::none()));
    }

    public function test_prepare_stands_down_without_a_command_or_on_static_paths(): void
    {
        $h = $this->harness();
        $det = self::detection('attack-webshell-panel', ['webshell']);
        self::assertNull($h->shell->prepare(self::ctx('GET', '/uploads/shell.php'), '1.2.3.4', $det, self::policy()), 'no cmd parameter');
        self::assertNull($h->shell->prepare(self::ctx('GET', '/x.js', 'cmd=id'), '1.2.3.4', $det, self::policy()), 'static asset');
        self::assertNull($h->shell->prepare(self::ctx('POST', '/index.php', '', 'cmd=id'), '1.2.3.4', Detection::none(), self::policy()), 'neither a console path nor an owned rule');
        $landing = $h->shell->prepare(self::ctx('POST', '/admin/root/post', '', 'csrf=x&cmd='), '1.2.3.4', $det, self::policy());
        self::assertNotNull($landing);
        self::assertTrue($landing->landingOnly, 'an empty command shows the landing');
        self::assertNotNull($h->shell->prepare(self::ctx('POST', '/upload.php', '', 'cmd=id'), '1.2.3.4', $det, self::policy()), 'Rule B predicted from the detection');
    }

    public function test_render_writes_an_html_shell_page_over_any_core_answer(): void
    {
        $h = $this->harness();
        foreach (['id', 'psql -c "select * from information_schema.tables"', 'cat /etc/shadow', "echo '<script>alert(1)</script>' > /var/www/html/x.html"] as $cmd) {
            $ctx = self::ctx('POST', '/admin/root/post', '', ConsoleHarness::form($cmd));
            $core = self::engine($ctx, $h->config);
            $before = $core->satisfies;
            $turn = $h->shell->prepare($ctx, '198.51.100.9', $core->satisfies, self::policy());
            self::assertNotNull($turn, $cmd);
            self::assertTrue($h->shell->serve($turn, $core), $cmd);
            self::assertSame(200, $core->status);
            self::assertSame('text/html; charset=utf-8', $core->headers['Content-Type']);
            self::assertArrayHasKey('X-Powered-By', $core->headers, 'the engine\'s other headers are kept');
            self::assertCount(1, array_filter(array_keys($core->headers), static fn ($k) => strcasecmp($k, 'content-type') === 0));
            self::assertStringContainsString('<title>Shell</title>', $core->body);
            self::assertSame($before, $core->satisfies, 'the logged verdict is untouched');
            self::assertSame('A', $turn->consoleRule);
        }
    }

    /** @return array<string,array{0:RequestContext,1:string,2:string}> request, rule the engine serves, header it sets */
    public static function headerCarryingAnswers(): array
    {
        return [
            'command output header' => [self::ctx('POST', '/admin/root/post', '', ConsoleHarness::form('${@java.lang.Runtime@getRuntime().exec("id")}', 'pct20')), 'attack-confluence-26134', 'X-Cmd-Response'],
            'command output header, recon line' => [self::ctx('POST', '/admin/root/post', '', ConsoleHarness::form('ls ${JAVA_HOME}/lib | grep Runtime', 'pct20')), 'attack-confluence-26134', 'X-Cmd-Response'],
            'redirect' => [self::ctx('GET', '/admin/root/html', 'cmd=id&next=https://evil.example/x'), 'attack-open-redirect', 'Location'],
            'protocol-relative redirect' => [self::ctx('GET', '/admin/root/link', 'cmd=whoami&url=//evil.example/'), 'attack-open-redirect', 'Location'],
        ];
    }

    /** @dataProvider headerCarryingAnswers */
    public function test_the_page_never_keeps_the_replaced_rules_headers(RequestContext $ctx, string $rule, string $header): void
    {
        $h = $this->harness();
        $core = self::engine($ctx, $h->config);
        self::assertSame($rule, $core->satisfies->templateIds()[0] ?? '', 'sanity: the engine answers with that rule');
        self::assertArrayHasKey($header, $core->headers, "sanity: the engine answer carries {$header}");
        $request = $core->headers['X-Request-Id'] ?? null;

        $turn = $h->shell->prepare($ctx, '198.51.100.9', $core->satisfies, self::policy());
        self::assertNotNull($turn);
        self::assertTrue($h->shell->serve($turn, $core), 'Rule A: the console owns its path');

        $names = array_map('strtolower', array_keys($core->headers));
        self::assertNotContains(strtolower($header), $names, "the console page drops {$header}");
        self::assertNotContains('location', $names, 'never a redirect from the console');
        self::assertSame(['content-type', 'x-powered-by', 'x-request-id'], array_values(array_intersect(['content-type', 'x-powered-by', 'x-request-id'], $names)));
        self::assertSame([], array_values(array_diff($names, ['content-type', 'x-powered-by', 'x-request-id'])), 'nothing else carries over');
        self::assertSame('text/html; charset=utf-8', $core->headers['Content-Type']);
        self::assertSame($request, $core->headers['X-Request-Id'], 'the engine\'s per-response headers are kept as they were');
        self::assertSame(200, $core->status);
        self::assertStringNotContainsString('uid=0', implode("\n", $core->headers), 'no header contradicts the page');
    }

    public function test_sleep_forms_the_facts_table_runs_are_recognised(): void
    {
        foreach ([['sleep', '3'], ['/bin/sleep', '3'], ['busybox', 'sleep', '3'], ['timeout', '9', 'sleep', '3'], ['timeout', '-s', '9', 'sleep', '3s'], ['x=1', 'nice', 'sleep', '3.5']] as $argv) {
            self::assertSame(3, AdaptiveShell::sleepOf($argv), implode(' ', $argv));
        }
        foreach ([['sleep'], ['sleep', 'x'], ['echo', 'sleep', '3'], ['sleep', '-3']] as $argv) {
            self::assertNull(AdaptiveShell::sleepOf($argv), implode(' ', $argv));
        }
        self::assertSame(300, AdaptiveShell::sleepOf(['sleep', '99999']), 'clamped');
    }

    public function test_the_body_is_capped(): void
    {
        $h = $this->harness();
        $turn = new ShellTurn('1.2.3.4', '/admin/root/post', FootholdIdentity::www(), 'body', true, false, true, null, str_repeat("<x>\n", 20000), null, false, SourceState::empty());
        $core = new SynthesizedResponse(200, ['Content-Type' => 'text/plain', 'Content-Length' => '9'], 'x', Detection::none());
        $h->shell->render($turn, $core);
        self::assertLessThanOrEqual(16384, strlen($core->body));
        self::assertArrayNotHasKey('Content-Length', $core->headers);
    }

    public function test_serve_needs_ownership_off_the_console_paths(): void
    {
        $h = $this->harness();
        $det = self::detection('attack-webshell-panel', ['webshell']);
        $turn = $h->shell->prepare(self::ctx('POST', '/upload.php', '', 'cmd=id'), '1.2.3.4', $det, self::policy());
        $sqli = new SynthesizedResponse(200, ['Content-Type' => 'text/html'], 'SQL error', self::detection('attack-sqli', ['sqli']));
        self::assertFalse($h->shell->serve($turn, $sqli), 'off the console paths an SQL answer is not owned');
        self::assertSame('SQL error', $sqli->body, 'and is left untouched');
        $web = new SynthesizedResponse(200, ['Content-Type' => 'text/html'], 'core', $det);
        self::assertTrue($h->shell->serve($turn, $web));
        self::assertSame('B', $turn->consoleRule);
    }

    public function test_commit_records_only_served_turns_and_makes_rule_b_paths_sticky(): void
    {
        $h = $this->harness();
        $det = self::detection('attack-webshell-panel', ['webshell']);
        $turn = $h->shell->prepare(self::ctx('POST', '/upload.php', '', 'cmd=id'), '1.2.3.4', $det, self::policy());
        $h->shell->commit($turn, 0);
        self::assertSame([], $h->store->writes, 'not served: nothing written');
        $h->shell->serve($turn, new SynthesizedResponse(200, [], 'core', $det));
        $h->shell->commit($turn, 120);
        self::assertCount(1, $h->store->writes);
        self::assertSame(120, $h->store->writes[0]['delay_ms']);
        self::assertSame('B', $h->store->writes[0]['console_rule']);
        self::assertSame('attack-webshell-panel', $h->store->writes[0]['owned_by_rule']);
        self::assertTrue($h->store->load('1.2.3.4')->isSticky('/upload.php'));
    }

    public function test_overlapping_turns_from_one_source_keep_both_answers(): void
    {
        $h = $this->harness();
        $identity = IdentityTestSupport::httpIdentity();
        [$pick, $idKey, $storeKey] = AdaptiveShell::keysFrom($identity->filesystemKey());
        $db = $h->dir . '/overlap.sqlite';
        // Each worker has its own connection, as separate php-fpm processes do.
        $worker = fn (): AdaptiveShell => new AdaptiveShell($h->config, $h->rewriter, new \Funnypot\App\Storage\CmdiShellStateStore($db, $storeKey), $pick, $idKey);
        $det = self::detection('attack-webshell-panel', ['attack', 'webshell']);
        $prep = fn (AdaptiveShell $s, string $cmd): array => [$s, $s->prepare(self::ctx('POST', '/admin/root/post', '', 'cmd=' . rawurlencode($cmd)), '198.51.100.9', $det, self::policy())];
        $done = static function (array $p) use ($det): string {
            [$s, $t] = $p;
            $r = new SynthesizedResponse(200, ['Content-Type' => 'text/html'], 'core', $det);
            $s->serve($t, $r);
            $s->commit($t, 0);

            return (string) preg_replace('~^.*<pre>|</pre>.*$~s', '', $r->body);
        };
        $a = $prep($worker(), 'id; whoami');
        $b = $prep($worker(), 'cat /etc/hosts | head');
        $first = $done($a);
        $second = $done($b);
        self::assertSame($first, $done($prep($worker(), 'id; whoami')), 'the resend of an overlapped turn replays its answer');
        self::assertSame($second, $done($prep($worker(), 'cat /etc/hosts | head')), 'and so does the other one');
    }

    /**
     * The permanent guard on operator decision 2: a canary argument sent by GET never appears in the
     * served page, whatever the applet, the argument shape, or the spelling that gets it to the applet.
     */
    public function test_a_get_canary_never_reaches_the_page_under_any_spelling(): void
    {
        $shapes = ['FPCANARYQ7', '/FPCANARYQ7', '-dFPCANARYQ7 -f1,1 /etc/hostname', '-d- -f1,3 /etc/hostname', '31337424242', '0000031337424242', '-n 31337424242 /etc/passwd', 'FPCANARYQ7=1 /etc/passwd'];
        $spell = [
            'plain' => static fn (string $a, string $x): string => "{$a} {$x}",
            '${IFS}' => static fn (string $a, string $x): string => $a . '${IFS}' . $x,
            '$IFS' => static fn (string $a, string $x): string => $a . '$IFS ' . $x,
            'tab' => static fn (string $a, string $x): string => "{$a}\t{$x}",
            'single quotes' => static fn (string $a, string $x): string => "{$a} '{$x}'",
            'double quotes' => static fn (string $a, string $x): string => "{$a} \"{$x}\"",
            'backslash' => static fn (string $a, string $x): string => $a . ' ' . substr($x, 0, 1) . '\\' . substr($x, 1),
            'glob *' => static fn (string $a, string $x): string => "{$a} {$x}*",
            'glob ?' => static fn (string $a, string $x): string => "{$a} {$x}?",
            '${IFS} + quotes' => static fn (string $a, string $x): string => $a . '${IFS}\'' . $x . '\'',
        ];
        $det = self::detection('attack-webshell-panel', ['attack', 'webshell']);
        $checked = 0;
        foreach (['www-data', 'root'] as $pin) {
            $h = $this->harness(['pin' => $pin]);
            foreach (array_merge(\Funnypot\App\Tarpit\Cmdi\FootholdFacts::commandNames(), \Funnypot\App\Tarpit\Cmdi\FootholdFacts::BUILTINS) as $applet) {
                foreach ($shapes as $x) {
                    // Reflection is decided by the slot rules, not the identity: root re-checks a few spellings.
                    foreach ($pin === 'root' ? array_intersect_key($spell, ['plain' => 1, '${IFS}' => 1, 'single quotes' => 1]) : $spell as $how => $make) {
                        $line = $make($applet, $x);
                        $turn = $h->shell->prepare(self::ctx('GET', '/admin/root/html', 'cmd=' . rawurlencode($line)), '198.51.100.44', $det, self::policy());
                        if ($turn === null) {
                            continue;
                        }
                        $r = new SynthesizedResponse(200, ['Content-Type' => 'text/html'], 'core', $det);
                        self::assertTrue($h->shell->serve($turn, $r));
                        self::assertStringNotContainsStringIgnoringCase('fpcanaryq7', $r->body, "{$pin}, {$how}: GET {$line}");
                        self::assertStringNotContainsString('31337424242', $r->body, "{$pin}, {$how}: GET {$line}");
                        $checked++;
                    }
                }
            }
        }
        self::assertGreaterThan(25000, $checked, 'every applet x shape x spelling');
    }

    /** Lines that expansion amplifies stay inside one request's budget, for every applet, POST and GET. */
    public function test_expansion_amplification_stays_within_the_budget(): void
    {
        $fill = static function (string $head, string $unit): string {
            while (strlen($head) + strlen($unit) <= \Funnypot\App\Tarpit\Cmdi\ShellLexer::MAX_INPUT) {
                $head .= $unit;
            }

            return $head;
        };
        $forms = [
            '$PATH joined' => static fn (string $a): string => $fill("{$a} ", '$PATH'),
            '$PATH args' => static fn (string $a): string => $fill($a, ' $PATH'),
            '${PATH} joined' => static fn (string $a): string => $fill("{$a} ", '${PATH}'),
            '$HOME path' => static fn (string $a): string => $fill("{$a} ", '$HOME/'),
            '${IFS}$PATH' => static fn (string $a): string => $fill($a, '${IFS}$PATH'),
            'brace' => static fn (string $a): string => $fill("{$a} ", '{a,b}'),
        ];
        $h = $this->harness();
        $det = self::detection('attack-webshell-panel', ['attack', 'webshell']);
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            $warnings[] = $msg;

            return true;
        });
        $worst = 0.0;
        try {
            foreach (\Funnypot\App\Tarpit\Cmdi\FootholdFacts::commandNames() as $applet) {
                foreach ($forms as $name => $make) {
                    $line = $make($applet);
                    foreach (['POST', 'GET'] as $m) {
                        $ctx = $m === 'POST' ? self::ctx('POST', '/admin/root/post', '', 'cmd=' . rawurlencode($line)) : self::ctx('GET', '/admin/root/html', 'cmd=' . rawurlencode($line));
                        $t = hrtime(true);
                        $turn = $h->shell->prepare($ctx, '198.51.100.45', $det, self::policy());
                        $ms = (hrtime(true) - $t) / 1e6;
                        self::assertNotNull($turn, "{$name}: {$applet}");
                        $worst = max($worst, $ms);
                        self::assertLessThan(30.0, $ms, sprintf('%s %s %s took %.1f ms', $m, $applet, $name, $ms));
                    }
                }
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $warnings, 'no warning reaches the log');
        self::assertGreaterThan(0.0, $worst);
    }

    public function test_a_store_fault_never_escapes(): void
    {
        $spy = new SpyCmdiStore();
        $spy->throw = true;
        $h = $this->harness(['store' => $spy]);
        $det = self::detection('attack-webshell-panel', ['webshell']);
        self::assertNull($h->shell->prepare(self::ctx('POST', '/admin/root/post', '', 'cmd=id'), '1.2.3.4', $det, self::policy()));
        $turn = new ShellTurn('1.2.3.4', '/x', FootholdIdentity::www(), 'body', true, false, true, null, '', new Outcome(Outcome::ACCEPT, Outcome::FACTS, '', '', null, 'simple'), true, SourceState::empty());
        $turn->served = true;
        $h->shell->commit($turn, 0);
        $this->addToAssertionCount(1);
    }

    public function test_identity_pin_and_draw(): void
    {
        self::assertSame('root', $this->harness(['pin' => 'root'])->shell->identityFor('1.2.3.4')->name);
        self::assertSame('www-data', $this->harness(['pin' => 'www-data'])->shell->identityFor('1.2.3.4')->name);
        $auto = $this->harness(['pin' => 'auto'])->shell;
        $names = [];
        for ($i = 0; $i < 64; $i++) {
            $names[$auto->identityFor("10.9.8.{$i}")->name] = true;
        }
        self::assertCount(2, $names, 'auto draws both identities across sources');
    }

    public function test_the_page_renderer_is_the_foothold_chrome(): void
    {
        $seed = IdentityTestSupport::httpIdentity()->personaSeed();
        $r = new FootholdRewriter($seed, LabyrinthController::entryHint());
        $page = $r->page(FootholdIdentity::www(), "x\n");
        self::assertStringContainsString("<pre>x\n\$ </pre>", $page);
        self::assertStringContainsString('<b>user:</b> uid=33(www-data)', $page);
        self::assertStringNotContainsString('<b>user:</b>', $r->page(FootholdIdentity::root(), ''));
        self::assertStringContainsString('<pre>$ </pre>', $r->page(FootholdIdentity::root(), ''), 'empty output: just the prompt');
    }
}

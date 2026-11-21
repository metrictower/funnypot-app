<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Tarpit\Cmdi\FootholdIdentity;
use Funnypot\App\Tarpit\FootholdRewriter;
use Funnypot\App\Tarpit\LlmOnlyLink;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\Detection;
use Funnypot\Core\RequestContext;
use Funnypot\Core\TemplateMatch;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0806 — the quick-win webshell must read as a low-privilege FOOTHOLD, not a completed RCE, so an
 * AI pentester keeps pivoting (toward the labyrinth) instead of filing one critical finding and ending
 * the engagement. {@see FootholdRewriter} rewrites ONLY the served body of the terminal
 * `attack-webshell-panel` decoy (app-tier, no funnypot-core change) into a believable locked-down
 * container foothold whose onward pointer is the labyrinth entry.
 *
 * The coherence window is the whole game (plan review=max): the mechanism must visibly fire, the goal
 * must be blocked for a REAL system reason (never "clearly secure", never a self-contradiction), the
 * body must stay static (no reflected input → no XSS / fingerprint surface), the logged/reported verdict
 * must stay critical, and the whole thing must be a no-op when the tarpit is off.
 */
final class FootholdRewriteTest extends TestCase
{
    /** The installed v0.6.3 core `attack-webshell-panel` body — the terminal quick win this rewrites. */
    private const CORE_WEBSHELL_BODY =
        "<html><head><title>Shell</title></head><body bgcolor=\"black\" text=\"green\">\n"
        . "<b>uname:</b> Linux web01 5.15.0 x86_64 GNU/Linux<br>\n"
        . "<b>user:</b> uid=33(www-data) gid=33(www-data) groups=33(www-data)<br>\n"
        . "<pre>\$ id\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n\$ </pre>\n"
        . "</body></html>\n";

    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm', '.sqlite', '.sqlite-wal', '.sqlite-shm', '.csv'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function tmpPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fpfoothold_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    private function rewriter(int $seed = 4242): FootholdRewriter
    {
        return new FootholdRewriter($seed, LabyrinthController::entryHint());
    }

    private static function detection(string $id, array $tags): Detection
    {
        return new Detection(true, [new TemplateMatch($id, 'critical', $tags)], 'cluster', 'critical');
    }

    // --- appliesTo: the tiny explicit allowlist, not every attack --------------------------------

    public function test_applies_to_the_webshell_template_id(): void
    {
        self::assertTrue($this->rewriter()->appliesTo(self::detection('attack-webshell-panel', ['attack', 'webshell'])));
    }

    public function test_applies_to_a_webshell_tag_even_under_another_id(): void
    {
        self::assertTrue($this->rewriter()->appliesTo(self::detection('some-other-id', ['attack', 'webshell', 'backdoor'])));
    }

    public function test_does_not_apply_to_an_unrelated_attack(): void
    {
        self::assertFalse($this->rewriter()->appliesTo(self::detection('attack-sqli', ['attack', 'sqli'])));
        self::assertFalse($this->rewriter()->appliesTo(Detection::none()));
    }

    public function test_does_not_apply_on_a_static_asset_path(): void
    {
        $webshell = self::detection('attack-webshell-panel', ['attack', 'webshell']);
        self::assertFalse($this->rewriter()->appliesTo($webshell, '/x.js'), 'an HTML shell for a .js request would be a tell');
        self::assertTrue($this->rewriter()->appliesTo($webshell, '/uploads/shell.php'));
    }

    // --- rewrite(): mechanism fires, goal blocked coherently, static, routes onward --------------

    /** @return array<string,array{0:?FootholdIdentity}> */
    public static function identities(): array
    {
        return ['www-data (default)' => [null], 'root' => [FootholdIdentity::root()]];
    }

    /** @dataProvider identities */
    public function test_rewrite_shows_the_mechanism_firing_but_the_goal_blocked(?FootholdIdentity $id): void
    {
        $body = $this->rewriter()->rewrite(self::CORE_WEBSHELL_BODY, $id);

        if ($id === null) {
            // Mechanism fires: the command ran and returned a non-root identity, which keeps the agent
            // engaged because the foothold visibly works.
            self::assertStringContainsString('uid=33(www-data)', $body, 'the mechanism must visibly fire');
            self::assertStringContainsString('Permission denied', $body, 'shadow/root are unreadable as www-data (exfil blocked)');
        } else {
            // Root is never revealed unprompted: no id line, no shadow, no /root listing.
            self::assertStringNotContainsString('uid=', $body, 'the root landing does not volunteer who it is');
            self::assertStringNotContainsString('$6$', $body, 'no credential material on the first page');
            self::assertStringNotContainsString('root:', $body);
        }

        // Neither landing prints a root id.
        self::assertStringNotContainsString('uid=0', $body, 'the landing never prints a root id');
        self::assertStringNotContainsString('gid=0', $body);
        // The privesc / exfil attempts fail for believable hardened-container reasons.
        self::assertStringContainsString('sudo: not found', $body, 'no sudo in the image (privesc blocked)');
        self::assertStringContainsString('Read-only file system', $body, 'rootfs is read-only (persistence blocked)');
        self::assertStringContainsString('Connection refused', $body, 'egress is refused (pivot blocked)');
        self::assertStringContainsString("CapEff:\t0000000000000000", $body, 'capabilities are dropped');
        // Reads as "real cmdi, controlled impact", never "clearly secure" — it does not deny the finding.
        self::assertStringNotContainsStringIgnoringCase('access denied', $body);
        self::assertStringNotContainsStringIgnoringCase('forbidden', $body);
    }

    public function test_the_sudo_line_uses_the_shell_prefix_ash_prints(): void
    {
        $body = $this->rewriter()->rewrite(self::CORE_WEBSHELL_BODY);
        self::assertStringContainsString("\nsh: sudo: not found\n", $body, 'popen runs sh -c, so ash prefixes with sh:');
        self::assertStringNotContainsString('/bin/sh: sudo', $body);
    }

    public function test_rewrite_is_coherent_with_the_distroless_contradiction_avoided(): void
    {
        // A distroless image has no shell/coreutils — claiming it while running id/cat/ls would be a
        // self-contradiction an adversarial agent eliminates on. The foothold claims a minimal Alpine
        // image (busybox), which DOES provide the shell the transcript uses.
        $body = $this->rewriter()->rewrite(self::CORE_WEBSHELL_BODY);
        self::assertStringContainsStringIgnoringCase('alpine', $body, 'claims a shell-bearing minimal image');
        self::assertStringNotContainsStringIgnoringCase('distroless', $body, 'must not claim a shell-less base while running a shell');
    }

    public function test_rewrite_routes_onward_to_the_labyrinth_with_no_followable_href(): void
    {
        $body = $this->rewriter()->rewrite(self::CORE_WEBSHELL_BODY);

        // The onward pointer is the SAME base64 breadcrumb the GET-recon hint carries (convergence), so
        // it decodes to the labyrinth root …
        self::assertSame(1, preg_match('~base path \(base64\):\s*([A-Za-z0-9+/=]+)~', $body, $m), 'onward base64 pointer present');
        self::assertSame(LabyrinthController::ENTRY_BASE, base64_decode($m[1]), 'the onward pointer decodes to the maze root');
        // … and it is LLM-only: a `href`/`src` regex finds nothing to follow (crawler-undiscoverable).
        self::assertFalse(LlmOnlyLink::containsFollowableLink($body), 'the foothold exposes no followable link');
        self::assertStringNotContainsString('/admin/audit-archive', $body, 'the maze path never appears as plain text');
    }

    public function test_rewrite_body_is_static_and_never_reflects_the_attackers_command(): void
    {
        // MF1b: the rewrite ignores the probe entirely; it cannot carry an attacker-controlled string.
        // (The body is produced from $coreBody + persona only — this test proves it does not depend on
        // any request input, so no reflection / XSS / fingerprint surface can exist.)
        $body = $this->rewriter()->rewrite(self::CORE_WEBSHELL_BODY);
        foreach (['<script>alert(1)</script>', '; cat /etc/passwd', '$(whoami)', 'rm -rf /', '"><svg onload=1>'] as $payload) {
            self::assertStringNotContainsString($payload, $body, "a reflected payload leaked: {$payload}");
        }
        self::assertStringNotContainsString('<script', $body, 'the static body carries no script');
    }

    public function test_rewrite_names_the_same_persona_as_the_labyrinth(): void
    {
        // Persona coherence: the foothold must name the SAME company the labyrinth pages show for the
        // same seed, so the foothold and the maze the agent lands in next do not contradict each other.
        $seed = IdentityTestSupport::httpIdentity()->personaSeed();
        $company = \Funnypot\Core\Support\PersonaIdentity::fromSeed($seed)->field('company.name');
        self::assertNotNull($company);
        $body = $this->rewriter($seed)->rewrite(self::CORE_WEBSHELL_BODY);
        self::assertStringContainsString($company, $body, 'the foothold names the persona company the maze also names');
        // host.name is not a persona field, so both the maze and the foothold fall back to this host.
        self::assertStringContainsString('app-prod-01', $body, 'same host fallback the labyrinth renders');
    }

    // --- MF4 / FP-0800 coordination: no-op when the core template stops being terminal -----------

    public function test_rewrite_is_a_noop_when_the_core_body_is_not_the_known_terminal_webshell(): void
    {
        $r = $this->rewriter();
        // If funnypot-core later makes the template non-terminal, its body no longer carries the known
        // terminal signature, so this tier stands down and serves the core body verbatim (no double-rewrite).
        $alreadyBlocked = '<html><head><title>Shell</title></head><body>operation recorded; no further access</body></html>';
        self::assertSame($alreadyBlocked, $r->rewrite($alreadyBlocked), 'a body without uid=33 is left untouched');
        $noChrome = '<pre>uid=33(www-data)</pre>';
        self::assertSame($noChrome, $r->rewrite($noChrome), 'a body without the Shell chrome is left untouched');
    }

    // --- handle()-level integration: real engine + store, rewriter wired vs null -----------------

    /** @return array{0:string,1:array<string,mixed>} [served body, main logged row] */
    private function handleWebshell(?FootholdRewriter $rewriter): array
    {
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $geo = new \Geo($this->tmpPath('geo') . '.csv');
        $c = new HoneypotController(
            $store,
            $geo,
            $config,
            dirname(__DIR__, 3) . '/demo/decoys',
            IdentityTestSupport::coreConfigFactory(),
            null, null, null, null,
            new AttackClassifier(),
            null, null,
            $rewriter,
        );

        ob_start();
        // An independent cmdi probe (the breadcrumb does NOT itself fire the webshell — the agent sends
        // this). A non-index path so the webshell template wins (CVE-2018-12613 owns index.php).
        @$c->handle(new RequestContext('GET', '/uploads/shell.php', 'cmd=id', ['User-Agent' => 'curl/8.0'], null), '9.9.9.9', 'off');
        $body = (string) ob_get_clean();

        $rows = $store->delta(0)['rows'];
        $main = array_values(array_filter($rows, static fn (array $r): bool => ($r['path'] ?? '') === '/uploads/shell.php'));
        self::assertCount(1, $main, 'exactly one main row for the probe');

        return [$body, $main[0]];
    }

    /** @return array<string,array{0:string}> */
    public static function landingIdentities(): array
    {
        return ['www-data' => ['www-data'], 'root' => ['root']];
    }

    /** @dataProvider landingIdentities */
    public function test_armed_handle_serves_the_foothold_but_keeps_the_critical_verdict(string $who): void
    {
        if ($who === 'www-data') {
            [$body, $row] = $this->handleWebshell($this->rewriter(IdentityTestSupport::httpIdentity()->personaSeed()));
            self::assertStringContainsString('uid=33(www-data)', $body, 'mechanism fires');
        } else {
            // A root source behind the console: with no command the webshell shows its landing, which
            // never reveals root unprompted.
            $h = \Funnypot\Tests\App\Tarpit\Cmdi\ConsoleHarness::build(['pin' => 'root']);
            try {
                $r = $h->fetch('GET', '/uploads/shell.php', '', null, '9.9.9.9');
            } finally {
                $h->cleanup();
            }
            [$body, $row] = [$r['body'], $r['row']];
            self::assertStringNotContainsString('uid=', $body, 'root is not revealed unprompted');
        }

        // The served body is the rewritten foothold …
        self::assertStringContainsString('Connection refused', $body, 'goal blocked (no egress)');
        self::assertStringContainsString('base path (base64):', $body, 'routes onward to the maze');
        self::assertStringNotContainsString('Linux web01', $body, 'the core terminal body was replaced');

        // … but $response->satisfies is untouched, so the hit still logs/reports as a critical webshell.
        self::assertTrue($row['matched'], 'the probe still logs as matched');
        self::assertSame('critical', $row['severity'], 'severity stays critical (prod ceiling unchanged)');
        self::assertContains('attack-webshell-panel', (array) $row['templates'], 'the template verdict is preserved');
        self::assertTrue($row['served'], 'the foothold was served');
    }

    public function test_disarmed_handle_serves_the_unmodified_core_webshell_body(): void
    {
        [$body, $row] = $this->handleWebshell(null);

        // Default-off safety: with no rewriter the served bytes are the core template's own terminal body.
        self::assertStringContainsString('Linux web01', $body, 'the unmodified core body is served');
        self::assertStringNotContainsString('base path (base64):', $body, 'no onward maze pointer when the tarpit is off');
        self::assertStringNotContainsString('Connection refused', $body);
        self::assertSame('critical', $row['severity']);
        self::assertContains('attack-webshell-panel', (array) $row['templates']);
    }
}

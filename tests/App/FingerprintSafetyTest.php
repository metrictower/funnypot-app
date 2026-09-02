<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Docker\DockerDaemon;
use Funnypot\App\Llm\LlmPromptBuilder;
use Funnypot\Core\Support\Chrome\GenericSkin;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\Chrome\WordpressSkin;
use Funnypot\App\Render\SkinSet;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * App-side mirror of funnypot-core's compile-time fingerprint-safety gate (invariant 5 in
 * ARCHITECTURE.md): scans every hand-authored skin's rendered output, and every LLM prompt-builder
 * exemplar, for the app's own denylist (resources/app-fingerprint-denylist.php). Nothing else in this
 * repo scans this app's hand-authored HTML/CSS surface or its prompt exemplars for a leaked
 * upstream-detector signature or a retired public bait literal — funnypot-core's gate only sees
 * funnypot-core's own compiled artifacts.
 *
 * Every denylist string is loaded from the resource file rather than written into this test's source,
 * on purpose: that keeps a real signature string out of this repo's PHP source entirely (append-only
 * in exactly one tracked file) and means adding a new denylist entry needs no test change to be
 * enforced here.
 */
final class FingerprintSafetyTest extends TestCase
{
    /** @return array{literals: list<string>, patterns: list<string>} */
    private static function denylist(): array
    {
        $d = require dirname(__DIR__, 2) . '/resources/app-fingerprint-denylist.php';

        return [
            'literals' => array_values((array) ($d['literals'] ?? [])),
            'patterns' => array_values((array) ($d['patterns'] ?? [])),
        ];
    }

    /** @return list<string> every denylist signature found in $text (empty => clean) */
    private static function scan(string $text): array
    {
        $d = self::denylist();
        $hits = [];
        foreach ($d['literals'] as $needle) {
            if ($needle !== '' && stripos($text, $needle) !== false) {
                $hits[] = $needle;
            }
        }
        foreach ($d['patterns'] as $pattern) {
            if (@preg_match('~' . $pattern . '~i', $text) === 1) {
                $hits[] = '/' . $pattern . '/';
            }
        }

        return $hits;
    }

    private static function assertClean(string $text, string $source): void
    {
        $hits = self::scan($text);
        self::assertSame([], $hits, "fingerprint leak in {$source}: " . implode(', ', $hits));
    }

    /**
     * Renders through the production path (PageShellRenderer -> SkinSet::select -> Skin::render) with
     * every skin registered in the same priority order demo/index.php uses, so marker resolution
     * (APITOKEN/EMAIL/AWSKEY -> persona-coherent fakes) runs exactly as it does for a real visitor
     * before the assertion looks at the bytes.
     */
    private static function renderPath(string $path, int $seed): string
    {
        $skins = new SkinSet(
            [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()],
            new GenericSkin()
        );
        $renderer = new PageShellRenderer($skins);
        $slots = PageSlots::fromArray([
            'app_name' => 'Internal Portal',
            'page_title' => 'Dashboard',
            'heading' => 'Welcome back',
            'intro' => 'Recent activity for your account.',
            'nav_items' => ['Home', 'Reports', 'Settings'],
            'table' => [
                'cols' => ['User', 'Role', 'Token'],
                'rows' => [
                    ['j.doe', 'admin', 'APITOKEN'],
                    ['k.chen', 'editor', 'EMAIL'],
                ],
            ],
            'form_fields' => ['Search'],
            'flash' => 'Saved successfully.',
            'footer_note' => 'All rights reserved.',
        ]);

        return $renderer->render($slots, VisualPersona::fromSeed($seed), new RequestContext('GET', $path));
    }

    /** One path per skin's matches(), plus a path that falls through to GenericSkin. A fixed,
     *  distinct seed per row keeps each render's seed-derived CSS/persona bytes deterministic and
     *  independent of the others. @return array<string,array{0:string,1:int}> */
    public static function skinPaths(): array
    {
        return [
            'wordpress (wp-login.php)' => ['/wp-login.php', 101],
            'phpmyadmin' => ['/phpmyadmin/', 102],
            'grafana' => ['/grafana/d/x', 103],
            'adminlte (admin)' => ['/admin/users', 104],
            'adminlte fleet console' => ['/admin/fleet', 106],
            'generic (no product analog)' => ['/hr/portal', 105],
        ];
    }

    /** @dataProvider skinPaths */
    public function test_skin_render_carries_no_denylisted_signature(string $path, int $seed): void
    {
        $html = self::renderPath($path, $seed);
        self::assertClean($html, "skin render of {$path} (seed {$seed})");
    }

    /** @return array<string,list<string>> factory method name => args, so the provider stays
     *  serializable (an object instance is built per-test, not carried through the provider). */
    public static function exemplarFactories(): array
    {
        return [
            'forHtml' => ['forHtml', ['nginx']],
            'forHtmlSlots' => ['forHtmlSlots', ['nginx', 'Velthora']],
            'forJson' => ['forJson', ['nginx']],
            'forCss' => ['forCss', ['nginx']],
            'forJs' => ['forJs', ['nginx']],
            'forXml' => ['forXml', ['nginx']],
            'forPlaintext' => ['forPlaintext', ['nginx']],
        ];
    }

    /** @dataProvider exemplarFactories
     * @param list<string> $args */
    public function test_prompt_exemplar_carries_no_denylisted_signature(string $factory, array $args): void
    {
        /** @var LlmPromptBuilder $builder */
        $builder = LlmPromptBuilder::{$factory}(...$args);
        $prompt = $builder->build('GET', '/x');
        self::assertClean($prompt, "LlmPromptBuilder::{$factory}(...) exemplar prompt");
    }

    /** The persona-accepting factories, each with a distinct seed so the built persona differs per
     *  row. A seed (int) rather than a VisualPersona instance keeps the provider serializable — the
     *  instance is built inside the test. @return array<string,array{0:string,1:int}> */
    public static function personaExemplarFactories(): array
    {
        return [
            'forJson' => ['forJson', 201],
            'forJs' => ['forJs', 202],
            'forXml' => ['forXml', 203],
            'forPlaintext' => ['forPlaintext', 204],
        ];
    }

    /**
     * Production (demo/index.php) always calls these factories WITH a VisualPersona — the null-path
     * test above only covers the neutral-placeholder exemplars, never the persona-coherent ones that
     * actually ship. Same denylist, same scan, through the PERSONA branch instead.
     *
     * @dataProvider personaExemplarFactories
     */
    public function test_persona_path_prompt_exemplar_carries_no_denylisted_signature(string $factory, int $seed): void
    {
        $persona = VisualPersona::fromSeed($seed);
        /** @var LlmPromptBuilder $builder */
        $builder = LlmPromptBuilder::{$factory}('nginx', $persona);
        $prompt = $builder->build('GET', '/x');
        self::assertClean($prompt, "LlmPromptBuilder::{$factory}('nginx', persona seed {$seed}) exemplar prompt");
    }

    /**
     * Regression for the bare-CRS-id pattern: a seed-derived 6-hex-digit accent color that happens
     * to be all decimal digits (e.g. #912345) must NOT be misread as a CRS rule id. The `#` gives
     * `\b` a false word boundary that a plain `\b9\d{5}\b` pattern would match; a hex color is not
     * a fingerprint leak.
     */
    public function test_hex_accent_color_starting_with_9_is_not_flagged_as_crs_rule_id(): void
    {
        self::assertClean(
            '<style>:root { --accent: #912345; } .btn { color: #987654; }</style>',
            'synthetic hex-accent-color snippet'
        );
    }

    /** Same pattern must still catch a genuine bare CRS rule id sitting in prose (not hex-adjacent). */
    public function test_bare_crs_rule_id_in_prose_is_still_flagged(): void
    {
        $hits = self::scan('blocked by rule 942100 during the scan');
        self::assertNotSame([], $hits, 'expected the bare CRS rule id 942100 to be flagged');
    }

    /** @return array<string,array{0:string}> role => provider row (FP-0036 fake-filesystem engine). */
    public static function fakeFilesystemRoles(): array
    {
        return ['developer' => ['developer'], 'finance' => ['finance'], 'hr' => ['hr'],
            'sales' => ['sales'], 'ops' => ['ops'], 'generic' => ['generic']];
    }

    /**
     * The FS/shell/fleet engine emits runtime-generated content the compiled-artifact CI gate never
     * sees. Scan a representative slice — directory listings, pinned system files, a generated file's
     * bytes, and a listing at depth — against the same app denylist.
     *
     * @dataProvider fakeFilesystemRoles
     */
    public function test_fake_filesystem_output_carries_no_denylisted_signature(string $role): void
    {
        $fs = new \Funnypot\Shell\Fs\FakeFilesystem(
            \Funnypot\Shell\Fs\Draw::seed("fp-safety-secret\0host\0" . $role),
            $role,
            77
        );
        $lsLa = static function (array $nodes): string {
            $out = '';
            foreach ($nodes as $n) {
                $out .= sprintf(
                    "%s %d %d %6d %s %s%s\n",
                    $n->isDir() ? 'drwxr-xr-x' : ($n->isLink() ? 'lrwxrwxrwx' : '-rw-r--r--'),
                    $n->uid,
                    $n->gid,
                    $n->size,
                    date('M j H:i', $n->mtime),
                    $n->name,
                    $n->target !== null ? ' -> ' . $n->target : ''
                );
            }
            return $out;
        };

        $blob = $lsLa($fs->list('/'))
            . $lsLa($fs->list('/etc'))
            . $lsLa($fs->list('/srv/app'))
            . $lsLa($fs->list('/usr/lib'))
            . $fs->read('/etc/passwd')
            . $fs->read('/etc/os-release')
            . $fs->read('/etc/hostname');

        // a generated file's bytes + a listing one level deeper
        foreach ($fs->list('/srv/app') as $n) {
            if ($n->isFile()) {
                $blob .= $fs->read('/srv/app/' . $n->name);
            } elseif ($n->isDir()) {
                $blob .= $lsLa($fs->list('/srv/app/' . $n->name));
            }
        }

        self::assertClean($blob, "fake-filesystem output for role {$role}");
    }

    /**
     * The fake Docker daemon emits runtime-generated JSON (version/info/containers/images + a created
     * container id) the compiled-artifact CI gate never sees. Scan the whole surface against the same
     * app denylist across a spread of seeds, so no seed-derived value can leak a detector signature.
     *
     * @dataProvider hostFactsSeeds
     */
    public function test_docker_daemon_output_carries_no_denylisted_signature(int $seed): void
    {
        $d = DockerDaemon::fromSeed($seed);
        $phantom = [
            'id' => str_repeat('b', 64), 'image' => 'alpine', 'command' => 'sh', 'cmd' => ['sh'],
            'entrypoint' => [], 'env' => ['A=1'], 'binds' => ['/:/host'], 'mounts' => [],
            'name' => '', 'created' => 1_700_000_000, 'started' => true, 'privileged' => true,
            'pid_mode' => 'host', 'network_mode' => 'host', 'user' => '', 'hostname' => '', 'tty' => false,
        ];
        $blob = json_encode($d->version())
            . json_encode($d->info(1_700_000_000, 2, 1, 3, 1))
            . json_encode($d->containers([$phantom], [], true))
            . json_encode($d->images(['docker.io/library/alpine:latest', 'evil.example:5000/x/miner:latest']))
            . $d->createdId('xmrig/xmrig', '-o pool.example:4444 -u wallet')
            // FP-0264 engagement generators the compiled-artifact gate never sees:
            . json_encode($d->pullStream('alpine:latest'))
            . json_encode($d->pullStream('evil.example:5000/x/miner:latest'))
            . json_encode($d->inspectPhantom($phantom, 1_700_000_000))
            . json_encode($d->inspectImage('alpine', 1_700_000_000))
            . json_encode($d->execInspect($d->execId('cid', 'id'), 'cid', ['sh', '-c', 'id']))
            . json_encode($d->notFound('container', 'deadbeef'))
            . json_encode(['message' => 'page not found']);
        for ($i = 0; $i < $d->fleetCount(); $i++) {
            $blob .= json_encode($d->inspectFleet($i, 1_700_000_000)) . json_encode($d->logsFleet($i));
        }
        // The whole container-name generator table, over a spread of ids.
        foreach (['0011223344ff', 'abcdef012345', str_repeat('c', 64), str_repeat('9', 12), 'feedface0000'] as $cid) {
            $blob .= ' ' . $d->containerName($cid);
        }

        self::assertClean((string) $blob, "Docker daemon output for seed {$seed}");
    }

    /**
     * FP-0264 review B (M1): the pull stream's seeded byte-counts are ATTACKER-REF-DEPENDENT, so a
     * two-ref sample can pass while a broad class of refs leaks a bare six-digit `9xxxxx` (a CRS
     * rule-id token the denylist bans). Sweep MANY refs × seeds through the real gate so a regression of
     * that shape (e.g. lowering the layer-total floor) trips here. This is the test that was widened
     * after it under-sampled and passed the M1 defect falsely.
     *
     * @dataProvider hostFactsSeeds
     */
    public function test_pull_stream_never_serves_a_denylisted_token_across_many_refs(int $seed): void
    {
        $d = DockerDaemon::fromSeed($seed);
        $repos = ['alpine', 'nginx', 'redis', 'busybox', 'ubuntu', 'python', 'xmrig/xmrig', 'library/postgres'];
        $regs = ['', 'evil.example:5000/', 'r.example/ns/', 'localhost:5000/'];
        $tags = ['latest', '1', '3.18', 'v2', 'stable'];
        $scanned = 0;
        // ~800 refs per seed: enough that a value in the 900000–999999 band would surface.
        for ($i = 0; $i < 1000; $i++) {
            $ref = $regs[$i % count($regs)] . $repos[$i % count($repos)] . ':' . $tags[$i % count($tags)] . $i;
            $bytes = (string) json_encode($d->pullStream($ref));
            self::assertClean($bytes, "pullStream({$ref}) at seed {$seed}");
            // Belt: assert the specific M1 property directly, independent of the denylist wiring.
            self::assertSame(0, preg_match('/(?<![#0-9a-fA-F])9\d{5}(?![0-9a-fA-F])/', $bytes), "bare 9xxxxx in pullStream({$ref})");
            $scanned++;
        }
        self::assertGreaterThan(500, $scanned);
    }

    /** @return array<string,array{0:int}> label => identity seed (a spread of host identities) */
    public static function hostFactsSeeds(): array
    {
        return ['id-1' => [1], 'id-7' => [7], 'id-42' => [42], 'id-1000' => [1000]];
    }

    /**
     * HostFacts output (uname, /proc/cpuinfo|meminfo|loadavg|uptime|version, df, netstat, ps) is
     * runtime-generated and equally unseen by the compiled-artifact CI gate — scan it too.
     *
     * @dataProvider hostFactsSeeds
     */
    public function test_host_facts_output_carries_no_denylisted_signature(int $seed): void
    {
        $hf = new \Funnypot\Shell\Host\HostFacts($seed);
        $blob = $hf->uname() . "\n"
            . (string) $hf->proc('cpuinfo')
            . (string) $hf->proc('meminfo')
            . (string) $hf->proc('loadavg')
            . (string) $hf->proc('uptime')
            . (string) $hf->proc('version');
        foreach ($hf->processTable() as $p) {
            $blob .= $p['user'] . ' ' . $p['command'] . "\n";
        }
        foreach ($hf->df() as $d) {
            $blob .= implode(' ', $d) . "\n";
        }
        foreach ($hf->netstat() as $n) {
            $blob .= implode(' ', $n) . "\n";
        }
        self::assertClean($blob, "HostFacts output for identity seed {$seed}");
    }
}

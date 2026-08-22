<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmPromptBuilder;
use Funnypot\App\Render\GenericSkin;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\App\Render\Skins\PhpMyAdminSkin;
use Funnypot\App\Render\Skins\WordpressSkin;
use Funnypot\App\Render\SkinSet;
use Funnypot\App\Render\VisualPersona;
use Funnypot\RequestContext;
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
}

<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;

use Funnypot\App\Render\Skins\{GrafanaSkin, AdminLteSkin};
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\Core\Support\Chrome\{GenericSkin, PageSlots, PhpMyAdminSkin, WordpressSkin};
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * Golden safety tests: an adversarial model response must never surface as active HTML through any
 * skin, and a disclosure word must never survive to a served body — even when no single skin's
 * per-slot escaping would have caught it. Cache poisoning here is permanent (an LLM fake response is
 * cached and re-served to later visitors), so these are non-negotiable: no mocks, real renderers.
 *
 * Two separate concerns:
 *  (A) Per-skin escaping — every Skin implementation neutralizes adversarial slot values on its own.
 *  (B) The whole-assembled-page pass (LlmOutputSanitizer::pageBodyOk) — a backstop that catches a
 *      disclosure word in rendered text even though every slot was individually escaped correctly.
 */
final class SkinEscapingGoldenTest extends TestCase
{
    /** @return iterable<string,array{0:object}> */
    public static function skins(): iterable
    {
        yield 'generic' => [new GenericSkin()];
        yield 'wordpress' => [new WordpressSkin()];
        yield 'phpmyadmin' => [new PhpMyAdminSkin()];
        yield 'grafana' => [new GrafanaSkin()];
        yield 'adminlte' => [new AdminLteSkin()];
    }

    /**
     * (A) Every slot carries an adversarial value. A skin that doesn't render a given slot trivially
     * passes for it — the point is that no rendered model value is ever active HTML, not that every
     * skin renders every slot.
     *
     * @dataProvider skins
     */
    public function test_adversarial_slots_are_neutralized_per_skin(object $skin): void
    {
        $slots = PageSlots::fromArray([
            'app_name' => '<script>a()</script>',
            'heading' => '"><svg onload=alert(1)>',
            // Disclosure attempt built by concatenation so this file's own source never contains the
            // literal word — a naive source-grep for the disclosure term must not flag this test file.
            'intro' => 'honey' . 'pot',
            'table' => ['cols' => ['<b>', 'x'], 'rows' => [['<iframe>', 'APITOKEN']]],
            'nav_items' => ['<img src=x onerror=1>'],
            'form_fields' => ['<b>'],
            'flash' => '"><svg onload=1>',
        ]);

        $html = $skin->render($slots, VisualPersona::fromSeed(9), '/x');

        // Each entry is the *unescaped* opening of one adversarial payload above — i.e. proof the
        // literal `<` from a MODEL slot survived un-neutralized. The script token is the app_name
        // payload's exact live opening (`<script>a(`), NOT a bare `<script`: a skin may legitimately
        // emit its own TRUSTED constant chrome script (e.g. the panel's service-worker registration),
        // which the trusted-chrome body pass (pageBodyOk(..., true)) allows — the injection backstop is
        // that no model-controlled value becomes active HTML, not that no script tag exists at all.
        // Correctly-escaped output also still contains inert substrings like "onerror=" as plain text
        // inside `&lt;img ... &gt;`, so checking those (rather than the live tag opening) would false-flag.
        foreach (['<script>a(', '<svg onload', '<iframe', '<img'] as $bad) {
            self::assertStringNotContainsString($bad, $html, get_class($skin) . " leaked unescaped {$bad}");
        }
    }

    /**
     * (B) A disclosure word split coherently across trusted chrome + one model slot must still be
     * caught by the whole-body pass, even though the per-slot escaping above has nothing to reject
     * (plain text "honeypot" is not active HTML — no skin's escaping logic has any reason to strip
     * it). Confirm the word actually reaches the rendered body first, so the assertion below is
     * testing the sanitizer and not a renderer that silently dropped the slot.
     */
    public function test_page_body_pass_catches_disclosure_that_per_slot_escaping_cannot(): void
    {
        $html = (new GenericSkin())->render(
            PageSlots::fromArray(['app_name' => 'Internal Tools', 'heading' => 'honey' . 'pot']),
            VisualPersona::fromSeed(1),
            '/x'
        );

        self::assertStringContainsString('honey' . 'pot', $html, 'precondition: disclosure word must actually reach the rendered body');
        self::assertFalse((new LlmOutputSanitizer())->pageBodyOk($html), 'pageBodyOk must reject a body carrying the disclosure word');
    }

    /**
     * (B, cont'd) The whole-body pass must not be a trivial always-false rejector: a legitimately
     * rendered page — trusted <style> block, relative "#"/path hrefs, no disclosure — must PASS.
     */
    public function test_page_body_pass_accepts_a_clean_rendered_page(): void
    {
        $cleanHtml = (new GenericSkin())->render(
            PageSlots::fromArray([
                'app_name' => 'HR Portal',
                'heading' => 'Employee Directory',
                'intro' => 'Search current staff records.',
                'nav_items' => ['Home', 'Reports'],
                'table' => ['cols' => ['Name', 'Dept'], 'rows' => [['A. Rios', 'Finance']]],
                'form_fields' => ['Search'],
                'flash' => 'Welcome back.',
            ]),
            VisualPersona::fromSeed(1),
            '/x'
        );

        self::assertStringContainsString('<style>', $cleanHtml, 'precondition: trusted chrome must include inline CSS');
        self::assertTrue((new LlmOutputSanitizer())->pageBodyOk($cleanHtml), 'pageBodyOk must accept a legitimately-rendered page');
    }
}

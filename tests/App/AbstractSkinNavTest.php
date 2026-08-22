<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;

use Funnypot\App\Render\GenericSkin;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * AbstractSkin::navHtml (item 9): nav hrefs are sanitized relative sibling paths derived from the
 * label, not dead '#' anchors, so a crawl of the honeypot can follow a nav link to another path the
 * honeypot itself answers. Exercised through GenericSkin since AbstractSkin is abstract and every
 * skin shares this one implementation.
 */
final class AbstractSkinNavTest extends TestCase
{
    private function render(array $navItems): string
    {
        return (new GenericSkin())->render(
            PageSlots::fromArray(['nav_items' => $navItems]),
            VisualPersona::fromSeed(3),
            '/x'
        );
    }

    public function test_label_slugifies_to_relative_sibling_path(): void
    {
        $html = $this->render(['User Settings']);
        self::assertStringContainsString('href="/user-settings"', $html);
    }

    public function test_symbols_collapse_to_a_single_dash(): void
    {
        $html = $this->render(['Reports & Stats']);
        self::assertStringContainsString('href="/reports-stats"', $html);
    }

    public function test_adversarial_label_yields_a_safe_relative_slug_href(): void
    {
        $html = $this->render(['<img src=x onerror=1>']);
        self::assertSame(1, preg_match('/<a[^>]*\shref="([^"]*)"/', $html, $m), 'nav anchor must carry an href attribute');
        $href = $m[1];
        self::assertMatchesRegularExpression('/^\/[a-z0-9-]*$/', $href, 'href must be a bare relative slug path');
        self::assertStringNotContainsString('<', $href);
        self::assertStringNotContainsString(':', $href);
        self::assertStringNotContainsString('//', $href);
    }

    public function test_all_symbol_label_falls_back_to_hash(): void
    {
        $html = $this->render(['!!!???']);
        self::assertStringContainsString('href="#"', $html);
    }

    public function test_label_text_stays_escaped(): void
    {
        $html = $this->render(['<b>Bold</b>']);
        self::assertStringContainsString('&lt;b&gt;Bold&lt;/b&gt;', $html);
        self::assertStringNotContainsString('<b>Bold</b>', $html);
    }
}

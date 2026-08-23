<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;

use Funnypot\App\Render\AbstractSkin;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * The Phase-0 deep-panel widget helpers on AbstractSkin (pill/gauge/sparkline/breadcrumb/controlResultCard).
 * Each must escape every model value it renders and emit its expected SVG/CSS structure, deterministically.
 * Exercised through a tiny concrete subclass because AbstractSkin is abstract; the helpers are shared by
 * every skin.
 */
final class PanelWidgetsTest extends TestCase
{
    private WidgetProbeSkin $s;

    protected function setUp(): void
    {
        $this->s = new WidgetProbeSkin();
    }

    // --- pillHtml ---

    public function test_pill_escapes_label_and_carries_status_colour(): void
    {
        $html = $this->s->pill('<script>x</script>', 'ok');
        self::assertStringContainsString('&lt;script&gt;', $html);
        self::assertStringNotContainsString('<script>', $html);
        self::assertStringContainsString('#2e8b57', $html); // ok background
        self::assertStringContainsString('class="fp-pill"', $html);
    }

    public function test_pill_unknown_status_is_neutral_and_never_reflected(): void
    {
        $html = $this->s->pill('State', '"><img onerror=1>');
        self::assertStringNotContainsString('<img', $html);          // status is never emitted
        self::assertStringContainsString('#e3e6e8', $html);          // idle background
    }

    // --- gaugeHtml ---

    public function test_gauge_renders_svg_and_escapes_label_and_text(): void
    {
        $html = $this->s->gauge('<b>Load</b>', 42, '182 <kW>');
        self::assertStringContainsString('<svg', $html);
        self::assertStringContainsString('<polyline', $this->s->spark([1, 2, 3])); // sanity: distinct helper
        self::assertStringContainsString('42%', $html);
        self::assertStringContainsString('&lt;b&gt;Load&lt;/b&gt;', $html);
        self::assertStringContainsString('182 &lt;kW&gt;', $html);
        self::assertStringNotContainsString('<b>Load</b>', $html);
        self::assertStringContainsString('#2e8b57', $html);          // <=60 -> ok band
    }

    public function test_gauge_clamps_out_of_range_and_bands_by_threshold(): void
    {
        self::assertStringContainsString('100%', $this->s->gauge('x', 250, 'y'));
        self::assertStringContainsString('0%', $this->s->gauge('x', -9, 'y'));
        self::assertStringContainsString('#c07a1a', $this->s->gauge('x', 75, 'y'));  // warn band
        self::assertStringContainsString('#b23b3b', $this->s->gauge('x', 99, 'y'));  // crit band
    }

    public function test_gauge_is_deterministic(): void
    {
        self::assertSame($this->s->gauge('CPU', 55, '55%'), $this->s->gauge('CPU', 55, '55%'));
    }

    // --- sparklineHtml ---

    public function test_sparkline_polyline_has_one_point_per_reading(): void
    {
        $html = $this->s->spark([0, 5, 10, 5]);
        self::assertSame(1, preg_match('/<polyline points="([^"]*)"/', $html, $m));
        self::assertCount(4, explode(' ', trim($m[1])));
        // Coordinates are pure numbers, never text sinks.
        self::assertMatchesRegularExpression('/^[0-9. ,]+$/', $m[1]);
    }

    public function test_sparkline_empty_is_blank_and_single_point_is_flat(): void
    {
        self::assertSame('', $this->s->spark([]));
        $one = $this->s->spark([7]);
        self::assertSame(1, preg_match('/points="([^"]*)"/', $one, $m));
        self::assertCount(2, explode(' ', trim($m[1]))); // duplicated into a flat 2-point line
    }

    // --- breadcrumbHtml ---

    public function test_breadcrumb_links_all_but_last_and_escapes_labels(): void
    {
        $html = $this->s->crumbs([['<Home>', '/admin'], ['Finance', '/admin/finance'], ['AP & GL', '']]);
        self::assertStringContainsString('href="/admin"', $html);
        self::assertStringContainsString('href="/admin/finance"', $html);
        self::assertStringContainsString('&lt;Home&gt;', $html);
        self::assertStringContainsString('AP &amp; GL', $html);
        // Last crumb is the current page: plain text, not a link.
        self::assertStringContainsString('<span class="fp-breadcrumb-cur">AP &amp; GL</span>', $html);
    }

    public function test_breadcrumb_rejects_unsafe_href(): void
    {
        $html = $this->s->crumbs([['Evil', 'javascript:alert(1)'], ['Now', '/admin']]);
        self::assertStringNotContainsString('javascript:', $html);
        // A non-rooted/unsafe href degrades to plain text rather than a link.
        self::assertStringContainsString('<span class="fp-breadcrumb-cur">Evil</span>', $html);
    }

    public function test_breadcrumb_empty_is_blank(): void
    {
        self::assertSame('', $this->s->crumbs([]));
    }

    // --- controlResultCard ---

    public function test_control_result_card_escapes_title_and_pairs(): void
    {
        $html = $this->s->result('Setpoint <x>', [['Zone', 'Zone 3F <NW>'], ['Job', 'cmd-8f3a21']]);
        self::assertStringContainsString('fp-result-card', $html);
        self::assertStringContainsString('Queued', $html);                 // canned inert badge
        self::assertStringContainsString('Setpoint &lt;x&gt;', $html);
        self::assertStringContainsString('Zone 3F &lt;NW&gt;', $html);
        self::assertStringContainsString('cmd-8f3a21', $html);
        self::assertStringNotContainsString('<x>', $html);
        self::assertStringNotContainsString('<NW>', $html);
    }
}

/**
 * Minimal concrete skin exposing the protected widget helpers for direct assertion. Implements the
 * abstract Skin contract with inert stubs; only the widget helpers are under test.
 */
final class WidgetProbeSkin extends AbstractSkin
{
    public function matches(string $path): bool
    {
        return false;
    }

    public function key(): string
    {
        return 'widget-probe';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        return '';
    }

    public function pill(string $label, string $status): string
    {
        return $this->pillHtml($label, $status);
    }

    public function gauge(string $label, int $valuePct, string $text): string
    {
        return $this->gaugeHtml($label, $valuePct, $text);
    }

    public function spark(array $points): string
    {
        return $this->sparklineHtml($points);
    }

    public function crumbs(array $crumbs): string
    {
        return $this->breadcrumbHtml($crumbs);
    }

    public function result(string $title, array $detailPairs): string
    {
        return $this->controlResultCard($title, $detailPairs);
    }
}

<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\Support\Chrome\PageSlots;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class GrafanaSkinTest extends TestCase
{
    public function test_matches_grafana_paths(): void
    {
        $s = new GrafanaSkin();
        self::assertTrue($s->matches('/grafana/login'));
        self::assertTrue($s->matches('/d/abc123/some-dashboard'));
        self::assertFalse($s->matches('/hr/portal'));
    }

    public function test_key_is_grafana(): void
    {
        self::assertSame('grafana', (new GrafanaSkin())->key());
    }

    public function test_resembles_grafana_and_escapes(): void
    {
        $html = (new GrafanaSkin())->render(
            PageSlots::fromArray([
                'heading' => '<x onerror=1>',
                'app_name' => 'Ops Dashboard',
                'table' => ['cols' => ['metric', 'value'], 'rows' => [['cpu', '42%']]],
            ]),
            VisualPersona::fromSeed(4), '/d/abc123/some-dashboard'
        );
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('panel', strtolower($html)); // resemblance marker
        self::assertStringNotContainsString('<x onerror', $html);     // escaping holds
    }
}

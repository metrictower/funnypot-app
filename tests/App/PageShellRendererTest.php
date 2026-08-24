<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;
use Funnypot\App\Render\{PageShellRenderer, SkinSet};
use Funnypot\RequestContext;
use Funnypot\Support\Chrome\GenericSkin;
use Funnypot\Support\Chrome\PageSlots;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class PageShellRendererTest extends TestCase
{
    private function renderer(): PageShellRenderer
    {
        return new PageShellRenderer(new SkinSet([], new GenericSkin()));
    }

    public function test_renders_a_full_page(): void
    {
        $html = $this->renderer()->render(
            PageSlots::fromArray(['app_name' => 'Portal', 'heading' => 'Users']),
            VisualPersona::fromSeed(3),
            new RequestContext('GET', '/hr/portal')
        );
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('Portal', $html);
    }

    public function test_escapes_the_request_path(): void
    {
        $html = $this->renderer()->render(
            PageSlots::fromArray(['heading' => 'X']),
            VisualPersona::fromSeed(3),
            new RequestContext('GET', '/a"><svg onload=alert(1)>')
        );
        self::assertStringNotContainsString('<svg onload', $html);
    }
}

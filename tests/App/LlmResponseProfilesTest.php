<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmResponseProfiles;
use PHPUnit\Framework\TestCase;

/**
 * The extension → response-shape map: the right kind + Content-Type per path, with unknown /
 * no-extension / dangerous extensions falling back to the HTML profile.
 */
final class LlmResponseProfilesTest extends TestCase
{
    private LlmResponseProfiles $p;

    protected function setUp(): void
    {
        $this->p = new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"');
    }

    /**
     * @dataProvider paths
     */
    public function test_resolve_maps_extension_to_kind_and_type(string $path, string $kind, string $type): void
    {
        $profile = $this->p->resolve($path);
        self::assertSame($kind, $profile->kind, $path);
        self::assertSame($type, $profile->contentType, $path);
    }

    /** @return array<int,array{0:string,1:string,2:string}> */
    public static function paths(): array
    {
        return [
            ['/static/js/app.js', 'js', 'application/javascript'],
            ['/api/v2/report.json', 'json', 'application/json'],
            ['/assets/app.css', 'css', 'text/css; charset=utf-8'],
            ['/config/services.xml', 'xml', 'application/xml; charset=utf-8'],
            ['/config/app.env', 'text', 'text/plain; charset=utf-8'],
            ['/var/log/app.log', 'text', 'text/plain; charset=utf-8'],
            ['/db/dump.sql', 'text', 'text/plain; charset=utf-8'],
            ['/index.php', 'html', 'text/html; charset=utf-8'],
            ['/admin/users', 'html', 'text/html; charset=utf-8'],            // no extension
            ['/backup/keystore.pem', 'html', 'text/html; charset=utf-8'],    // dangerous -> html fallback
            ['/static/App.JS', 'js', 'application/javascript'],              // case-insensitive
            ['/static/js/app.js?v=2', 'js', 'application/javascript'],       // query ignored
            ['/static/js/app.js.bak', 'html', 'text/html; charset=utf-8'],  // only last segment ext (known limit)
        ];
    }

    public function test_html_profile_gets_renderer_and_slots_grammar_when_provided(): void
    {
        $renderer = new \Funnypot\App\Render\PageShellRenderer(
            new \Funnypot\App\Render\SkinSet([], new \Funnypot\Support\Chrome\GenericSkin())
        );
        $profiles = new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"', $renderer, 'root ::= "{"', 'Velthora');
        $html = $profiles->resolve('/hr/portal');
        self::assertSame('text/html; charset=utf-8', $html->contentType);
        self::assertNotNull($html->renderer);
    }

    public function test_html_profile_has_no_renderer_by_default(): void
    {
        $profiles = new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"');
        self::assertNull($profiles->resolve('/hr/portal')->renderer);   // legacy path preserved
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Render\Panel\FleetSection;
use Funnypot\App\Render\Panel\PanelRegistry;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class FleetSectionTest extends TestCase
{
    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = ''): array
    {
        return ['module' => 'fleet', 'section' => $section, 'entity' => $entity, 'subtab' => '', 'action' => '', 'arg' => '', 'page' => 1, 'filter' => ''];
    }

    private function thisBoxHost(): string
    {
        return strtolower(Fleet::fromSeed(4242, 24)->servers()[0]['host']);
    }

    public function test_registered_in_panel_registry(): void
    {
        $r = new PanelRegistry();
        self::assertTrue($r->has('fleet'));
        self::assertInstanceOf(FleetSection::class, $r->sectionFor('fleet'));
        self::assertInstanceOf(FleetSection::class, $r->sectionFor('hosts')); // alias
    }

    public function test_list_view_lists_linked_hosts(): void
    {
        $out = (new FleetSection())->render($this->route(), VisualPersona::fromSeed(4242), '/admin');
        self::assertStringContainsString('Servers', $out);
        self::assertStringContainsString('/admin/fleet/', $out);       // hosts link to their detail
        self::assertGreaterThan(20, substr_count($out, '<tr>'));       // ~24 hosts + header
    }

    public function test_detail_shows_gauges_services_and_console_button(): void
    {
        $host = $this->thisBoxHost();
        $out = (new FleetSection())->render($this->route($host), VisualPersona::fromSeed(4242), '/admin');
        self::assertStringContainsString('fp-gauge-svg', $out);        // live gauges (this box is running)
        self::assertStringContainsString('Services', $out);
        self::assertStringContainsString('/admin/fleet/' . $host . '/console', $out);
    }

    public function test_action_console_and_not_found(): void
    {
        $sec = new FleetSection();
        $p = VisualPersona::fromSeed(4242);
        $host = $this->thisBoxHost();
        self::assertStringContainsString('Queued', $sec->render($this->route($host, 'reboot'), $p, '/admin'));
        self::assertStringContainsString('Linux', $sec->render($this->route($host, 'console'), $p, '/admin'));
        self::assertStringContainsString('not found', $sec->render($this->route('no-such-zzz'), $p, '/admin'));
    }
}

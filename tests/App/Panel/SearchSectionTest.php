<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Panel\SearchSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

final class SearchSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new SearchSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    /** Render from a hand-built route (to inject a value the parser would otherwise slug away). */
    private function renderRoute(array $route, int $seed = 7): string
    {
        $base = [
            'module' => 'search', 'section' => '', 'entity' => '', 'subtab' => '',
            'action' => '', 'arg' => '', 'page' => 1, 'filter' => '',
        ];
        return (new SearchSection())->render(array_merge($base, $route), VisualPersona::fromSeed($seed), '/admin');
    }

    // --- landing (empty query) ---

    public function test_empty_query_shows_landing_with_suggested_and_recent(): void
    {
        $html = $this->render('/admin/search');
        self::assertStringContainsString('Suggested searches', $html);
        self::assertStringContainsString('Recent searches', $html);
        // The search box posts to the path-form action so a typed query can route back here.
        self::assertStringContainsString('action="/admin/search"', $html);
        // Suggested/recent chips are links into other canned queries.
        self::assertStringContainsString('href="/admin/search/', $html);
    }

    // --- results deep-link into the real modules ---

    public function test_results_deep_link_into_every_module(): void
    {
        $html = $this->render('/admin/search/payroll');
        self::assertStringContainsString('Results for', $html);
        self::assertStringContainsString('href="/admin/hr/employees/emp-', $html);   // People / Employees
        self::assertStringContainsString('href="/admin/it/assets/', $html);          // Assets / CMDB
        self::assertStringContainsString('href="/admin/finance/ap/', $html);         // Invoices
        self::assertStringContainsString('href="/admin/vendors/', $html);            // Vendors
        self::assertStringContainsString('href="/admin/facilities/rooms/room-', $html); // Rooms
        self::assertStringContainsString('href="/admin/helpdesk/hd-', $html);        // Tickets
        self::assertStringContainsString('href="/admin/bank/acct-', $html);          // Bank accounts
    }

    public function test_teasing_queries_all_return_confident_hits(): void
    {
        // "always returns plausible hits" — sensitive queries surface confident rows, all inert.
        foreach (['password', 'admin', 'wire', 'root', 'ssn'] as $q) {
            $html = $this->render('/admin/search/' . $q);
            self::assertStringContainsString('matches across', $html, "query $q");
            self::assertStringContainsString('href="/admin/hr/employees/emp-', $html, "query $q");
        }
    }

    // --- determinism ---

    public function test_results_are_byte_identical_per_seed_and_query(): void
    {
        self::assertSame($this->render('/admin/search/payroll'), $this->render('/admin/search/payroll'));
        // A different query gives a different page (the selection is a function of the query).
        self::assertNotSame($this->render('/admin/search/payroll'), $this->render('/admin/search/vpn'));
        // A different seed gives a different page (the estate varies per deploy).
        self::assertNotSame(
            $this->render('/admin/search/payroll', 7),
            $this->render('/admin/search/payroll', 8)
        );
    }

    public function test_pagination_slot_is_accepted(): void
    {
        // A trailing pN peels into page and must not break the query slot.
        $html = $this->render('/admin/search/payroll/p2');
        self::assertStringContainsString('Results for', $html);
    }

    // --- escaping / safety ---

    public function test_script_query_renders_inert(): void
    {
        // Even if a raw query reaches the section (defense-in-depth, not relying on the parser), it is
        // esc()'d everywhere it is echoed and never used to build a link.
        $html = $this->renderRoute(['section' => '<script>alert(1)</script>']);
        self::assertStringNotContainsString('<script>alert(1)</script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
        // The reflected value must appear in the echo and the pre-filled box, both escaped.
        self::assertStringContainsString('Results for', $html);
    }

    public function test_quote_query_cannot_break_out_of_the_value_attribute(): void
    {
        $html = $this->renderRoute(['section' => '"><img src=x onerror=alert(1)>']);
        self::assertStringNotContainsString('<img src=x', $html);
        self::assertStringContainsString('&quot;', $html);
    }

    public function test_no_public_ip_leaks_anywhere(): void
    {
        foreach (['/admin/search', '/admin/search/payroll', '/admin/search/root'] as $path) {
            self::assertSame(0, preg_match(self::PUBLIC_IP, $this->render($path)), $path);
        }
    }
}

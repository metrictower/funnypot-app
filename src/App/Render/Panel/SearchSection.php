<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Search;
use Funnypot\Support\VisualPersona;

/**
 * Global search (spec §D.6) — the cross-module lure that ties the whole estate into one company. The query
 * is the first path slot after the mount (`/admin/search/<query>`); a query string never routes (PanelRoute
 * cuts it), so the query only ever arrives as a slugged path segment. The section:
 *
 *   - EMPTY query -> a landing: the search box, suggested searches, and seeded "recent searches", each a
 *     link into another canned query (deep engagement with nothing to type);
 *   - a query -> fabricated result GROUPS (People / Employees / Assets / Invoices / Vendors / Rooms /
 *     Tickets / Bank accounts) from `Fake\Search`, each hit a deep link into that module's OWN detail page
 *     so the surfaced record reads identically there (one roster/estate holds end-to-end). A query always
 *     returns confident-looking hits ("password" / "admin" / a name all resolve), and every hit is inert.
 *
 * SAFETY: the echoed query is the one reflected value on the page and is always run through esc() (it is
 * never used to build a link — hrefs are fixed module paths or generator ids), so a `<script>` query is
 * structurally inert. The query is never treated as routing and never persisted. A tiny progressive
 * enhancement rewrites the GET form to the path form so a typed search reaches this section; with no JS the
 * form falls back to the landing (a query string cannot route), never an error.
 */
final class SearchSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $search = Search::fromSeed($persona->seed(), $persona->domain());
        $query = $route['section'];
        if ($query === '') {
            return $this->landing($search, $navBase);
        }
        return $this->results($search, $navBase, $query);
    }

    // --- empty-query landing ---

    private function landing(Search $search, string $navBase): string
    {
        $crumbs = $this->baseCrumbs($navBase, 'Search');
        $form = $this->searchForm($navBase, '');

        $suggested = $this->chipCloud($navBase, $search->suggestions());
        $recent = $this->chipCloud($navBase, $search->recentSearches());

        return $this->breadcrumbHtml($crumbs)
            . $this->card('Search', $form, 'people · assets · invoices · vendors · rooms · tickets · bank')
            . $this->card('Suggested searches', $suggested, 'quick jumps')
            . $this->card('Recent searches', $recent, 'this workspace');
    }

    // --- results for a query ---

    private function results(Search $search, string $navBase, string $query): string
    {
        $groups = $search->groups($query);

        $crumbs = [
            ['Corevance', $navBase],
            ['Search', $navBase . '/search'],
            ['"' . $query . '"', ''],
        ];

        $total = 0;
        foreach ($groups as $g) {
            $total += count($g['items']);
        }

        // The one reflected value on the page — esc() it, and never build a link from it.
        $heading = '<p style="margin:0 0 4px;font-size:1.05em;color:#2c3136">Results for '
            . '<strong>"' . $this->esc($query) . '"</strong></p>'
            . '<p class="fp-muted" style="margin:0;font-size:.86em;color:#6c757d">'
            . number_format($total) . ' matches across ' . count($groups) . ' areas</p>';

        $body = $this->breadcrumbHtml($crumbs)
            . $this->card('Search', $this->searchForm($navBase, $query) . '<div style="margin-top:10px">' . $heading . '</div>',
                'global')
            . $this->documentsCard($navBase, $query);

        foreach ($groups as $g) {
            if ($g['items'] === []) {
                continue;
            }
            $body .= $this->card($g['label'], $this->hitList($navBase, $g['items']),
                count($g['items']) . ' matches');
        }
        return $body;
    }

    /**
     * A "top match" documents teaser that folds the query back in (the confident echo the spec calls for:
     * search "password" and a shared-drive row is right there). It links to real in-panel decoy handlers,
     * never to a query-derived path, so the query stays a text-only, escaped value.
     */
    private function documentsCard(string $navBase, string $query): string
    {
        $items = [
            [
                'title' => '"' . $query . '" — matches in shared drive',
                'sub' => 'Documents / reports · restricted',
                'path' => '/hr/documents',
            ],
            [
                'title' => $query . ' (export).xlsx',
                'sub' => 'Files · last opened by Finance',
                'path' => '/files',
            ],
        ];
        return $this->card('Files & documents', $this->hitList($navBase, $items), '2 matches');
    }

    /**
     * A group's hit list: each hit a deep link into its module's detail page. The href is $navBase + a
     * generator-authored relative path (already [a-z0-9-]/id-shaped) then esc()'d; the title and sub are
     * escaped text. No model value reaches the markup un-escaped.
     *
     * @param list<array{title:string,sub:string,path:string}> $items
     */
    private function hitList(string $navBase, array $items): string
    {
        $html = '<ul style="list-style:none;margin:0;padding:0">';
        foreach ($items as $it) {
            $href = $this->esc($navBase . $it['path']);
            $html .= '<li style="padding:8px 0;border-bottom:1px solid #eef1f3">'
                . '<a class="fp-dl" style="color:#3b7ea1;text-decoration:none;font-weight:600" href="' . $href . '">'
                . $this->esc($it['title']) . '</a>'
                . '<div class="fp-muted" style="font-size:.82em;color:#6c757d">' . $this->esc($it['sub']) . '</div>'
                . '</li>';
        }
        return $html . '</ul>';
    }

    // --- shared UI ---

    /**
     * The GET search form + a progressive-enhancement script that rewrites a submit into the path form
     * (`/admin/search/<slug>`) so the query reaches this section (a query string never routes). Without JS
     * the form still submits and lands on the landing page — never an error. $value pre-fills the box and is
     * escaped (the box is the only place the raw query re-enters the page besides the heading).
     */
    private function searchForm(string $navBase, string $value): string
    {
        $action = $this->esc($navBase . '/search');
        $val = $value === '' ? '' : ' value="' . $this->esc($value) . '"';
        $form = '<form id="gsform" method="get" action="' . $action . '" style="display:flex;gap:8px;flex-wrap:wrap">'
            . '<input id="gsq" name="q" type="search" placeholder="Search people, assets, invoices, rooms…" '
            . 'autocomplete="off"' . $val
            . ' style="flex:1;min-width:240px;padding:8px 12px;border:1px solid #cfd6dc;border-radius:4px;box-sizing:border-box">'
            . '<button type="submit" style="padding:8px 18px;border:0;border-radius:4px;background:#3b7ea1;'
            . 'color:#fff;font-weight:600;cursor:pointer">Search</button></form>';
        // Slugify client-side with the SAME rule the router uses, so a typed query and its results agree.
        $script = '<script>(function(){var f=document.getElementById("gsform");if(!f)return;'
            . 'f.addEventListener("submit",function(e){e.preventDefault();'
            . 'var v=(f.q.value||"").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"");'
            . 'window.location.href=f.getAttribute("action")+(v?"/"+v:"");});})();</script>';
        return $form . $script;
    }

    /**
     * A cloud of query chips, each a link to `/admin/search/<slug>`. The href is built from a
     * navBase-safe slug of the label (never the raw label), so it can only ever be another search path
     * this section answers; the visible label is escaped.
     *
     * @param list<string> $labels
     */
    private function chipCloud(string $navBase, array $labels): string
    {
        $html = '<div style="display:flex;flex-wrap:wrap;gap:8px">';
        foreach ($labels as $label) {
            $slug = $this->slug($label);
            $href = $this->esc($navBase . '/search' . ($slug === '' ? '' : '/' . $slug));
            $html .= '<a href="' . $href . '" style="display:inline-block;padding:5px 12px;border-radius:14px;'
                . 'border:1px solid #cfd6dc;color:#3b7ea1;text-decoration:none;font-size:.84em">'
                . $this->esc($label) . '</a>';
        }
        return $html . '</div>';
    }

    /** The exact slug rule PanelRoute uses, so a chip href routes back to a query this section answers. */
    private function slug(string $s): string
    {
        return trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($s)), '-');
    }
}

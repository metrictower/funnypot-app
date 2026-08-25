<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Activity;
use Funnypot\Core\Support\VisualPersona;

/**
 * Activity Feed (spec §B Overview) — the one global, reverse-chronological timeline that ties every
 * module together: sign-ins, config changes, door/badge events, work orders, pending approvals, payroll
 * runs, certificate expiries and fire/sensor alarms, newest first. Each row names a real `Org` person
 * and (where it has one) a real `Building` room / `Access` door, and deep-links back into the module that
 * owns the event — so following a row lands on the same entity it names, reinforcing the one-company
 * fiction rather than dead-ending.
 *
 * The whole surface is INERT and read-only: it renders the seeded `Fake\Activity` view, escapes every
 * value, and slugs every id into a sibling link. Timestamps are strictly monotonic descending from the
 * frozen clock, so a static reload is byte-identical.
 *
 * Route slots (PanelRoute): module=activity; section = '' (all) or a type filter (signin/door/config/
 * workorder/approval/alarm/cert/payroll); pagination lives in the path as a trailing `pN`.
 */
final class ActivitySection extends AbstractPanelSection
{
    private const PAGE_SIZE = 50;

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $activity = Activity::fromSeed($persona->seed(), $persona->domain());

        // The section slot is a type filter; an unknown token shows the unfiltered stream (never a 404).
        $filter = $route['section'];
        if ($filter !== '' && !in_array($filter, $activity->typeSlugs(), true)) {
            $filter = '';
        }

        return $this->landing($activity, $navBase, $filter, $route['page']);
    }

    private function landing(Activity $activity, string $navBase, string $filter, int $page): string
    {
        $counts = $activity->typeCounts();
        $tiles = $this->headlineTiles($activity, $counts);
        $filterBar = $this->filterBar($activity, $navBase, $filter, $counts);

        $feed = $activity->feed($page, self::PAGE_SIZE, $filter);
        $timeline = $this->timeline($feed['events'], $navBase);

        $basePath = $navBase . '/activity' . ($filter !== '' ? '/' . $filter : '');
        $summary = 'Showing ' . number_format($feed['from']) . '&ndash;' . number_format($feed['to'])
            . ' of ' . number_format($feed['total']) . ' events';
        $pager = $this->pagerHtml($basePath, $feed['page'], $feed['totalPages'], $summary);

        $title = $filter === '' ? 'Activity Feed' : 'Activity Feed — ' . $activity->typeLabel($filter);
        $crumbs = $filter === ''
            ? $this->baseCrumbs($navBase, 'Activity Feed')
            : [['Corevance', $navBase], ['Activity Feed', $navBase . '/activity'], [$activity->typeLabel($filter), '']];

        return $this->breadcrumbHtml($crumbs)
            . $tiles
            . $filterBar
            . $this->card($title, $timeline . $pager, 'global timeline · newest first (cached ~30 s)');
    }

    /**
     * Headline stat tiles derived from the per-type counts so nothing contradicts the feed. Every label is
     * an explicit historical window ("(30 d)") — these are activity-stream counts (hundreds of events over
     * a month), not a live gauge, so they never read as the same concept as Dashboard's "Active alarms:
     * 0-3" current-state tile for the same word.
     */
    private function headlineTiles(Activity $activity, array $counts): string
    {
        $by = [];
        foreach ($counts as $c) {
            $by[$c['slug']] = $c['count'];
        }
        return $this->statCardsHtml([
            ['label' => 'Events (30 d)', 'value' => number_format($activity->total())],
            ['label' => 'Sign-ins (30 d)', 'value' => number_format($by['signin'] ?? 0)],
            ['label' => 'Access events (30 d)', 'value' => number_format($by['door'] ?? 0)],
            ['label' => 'Approval events (30 d)', 'value' => number_format($by['approval'] ?? 0)],
            ['label' => 'Alarm events (30 d)', 'value' => number_format($by['alarm'] ?? 0)],
            ['label' => 'Cert expiries (30 d)', 'value' => number_format($by['cert'] ?? 0)],
        ], 'fp-tiles', 'fp-tile');
    }

    /** The type-filter bar: an All chip plus one chip per type; the active filter renders as plain text. */
    private function filterBar(Activity $activity, string $navBase, string $filter, array $counts): string
    {
        $chips = $this->filterChip($navBase . '/activity', 'All', $filter === '');
        foreach ($counts as $c) {
            $label = $c['label'] . ' (' . number_format($c['count']) . ')';
            $chips .= $this->filterChip($navBase . '/activity/' . $c['slug'], $label, $filter === $c['slug']);
        }
        return '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:6px;margin:12px 0">' . $chips . '</div>';
    }

    private function filterChip(string $href, string $label, bool $active): string
    {
        if ($active) {
            return '<span class="alte-chip is-active" style="display:inline-block;padding:5px 11px;border-radius:14px;'
                . 'background:#3b7ea1;color:#fff;font-size:.82em;font-weight:600">' . $this->esc($label) . '</span>';
        }
        return '<a class="alte-chip" style="display:inline-block;padding:5px 11px;border-radius:14px;'
            . 'background:#eef1f3;color:#3b7ea1;font-size:.82em;text-decoration:none" href="'
            . $this->esc($href) . '">' . $this->esc($label) . '</a>';
    }

    /**
     * The reverse-chronological timeline table. Every field is escaped; the event summary is a deep link
     * into the owning module, built from navBase plus the generator's already-slugged relative path.
     */
    private function timeline(array $events, string $navBase): string
    {
        if ($events === []) {
            return '<p class="fp-muted">No events in this view.</p>';
        }
        $rows = '';
        foreach ($events as $e) {
            $href = $this->esc($navBase . $e['link']);
            $when = '<div>' . $this->esc($e['datetime']) . '</div>'
                . '<div class="fp-muted" style="font-size:.82em">' . $this->esc($e['ago']) . '</div>';
            $summary = '<a class="fp-dl" href="' . $href . '">' . $this->esc($e['summary']) . '</a>';
            $rows .= '<tr>'
                . '<td style="white-space:nowrap">' . $when . '</td>'
                . '<td>' . $this->pillHtml($e['typeLabel'], 'info') . '</td>'
                . '<td>' . $this->pillHtml($this->severityLabel($e['severity']), $e['severity']) . '</td>'
                . '<td>' . $summary . '</td>'
                . '</tr>';
        }
        return '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Event</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
    }

    /** Human word for a severity token; the token itself still selects the pill colour. */
    private function severityLabel(string $severity): string
    {
        $map = ['ok' => 'normal', 'info' => 'info', 'warn' => 'warning', 'crit' => 'critical'];
        return isset($map[$severity]) ? $map[$severity] : $severity;
    }
}

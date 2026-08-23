<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\VisualPersona;

/**
 * The panel landing: business / operations metrics ONLY (spec T1/E1). No secrets, and specifically NO
 * password_hash column — that loot moved one drill-down deep to the Databases `users` Browse. The
 * landing shows headline stat tiles + a benign "recent sign-ins" table (name/role/last sign-in), all
 * reconciled off the one seeded roster (Org) and building topology (Building), so the numbers agree
 * with every other module.
 */
final class DashboardSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $seed = $persona->seed();
        // One host = one domain: the roster reads the persona domain, never a second invented one.
        $org = Org::fromSeed($seed, $persona->domain());
        $bld = Building::fromSeed($seed);
        $site = $bld->site();

        $headcount = $org->headcount();
        $occDesign = $site['occupancyDesign'];
        $occNow = $occDesign > 0 ? (int) round($occDesign * (35 + ($this->h($seed, 'occ') % 45)) / 100) : 0;

        $controllers = $bld->controllers();
        $ctrlOnline = 0;
        foreach ($controllers as $c) {
            if ($c['health'] === 'ok') {
                $ctrlOnline++;
            }
        }
        $openWo = 4 + ($this->h($seed, 'wo') % 22);
        $activeAlarms = $this->h($seed, 'alarms') % 4;

        $tiles = $this->statCardsHtml([
            ['label' => 'Employees', 'value' => number_format($headcount), 'sub' => $org->magnitudes()['contractors'] . ' contractors'],
            ['label' => 'Occupancy now', 'value' => number_format($occNow) . ' / ' . number_format($occDesign)],
            ['label' => 'Floors / Rooms', 'value' => $site['floors'] . ' / ' . $site['rooms']],
            ['label' => 'Controllers online', 'value' => $ctrlOnline . ' / ' . count($controllers)],
            ['label' => 'Open work orders', 'value' => (string) $openWo],
            ['label' => 'Active alarms', 'value' => (string) $activeAlarms, 'sub' => $activeAlarms === 0 ? 'all clear' : 'requires review'],
        ], 'alte-stats', 'alte-st');

        $siteKv = $this->kvTableHtml([
            ['Site', $site['name'] . ' (' . $site['code'] . ')'],
            ['Address', $site['street'] . ', ' . $site['city']],
            ['Timezone', $site['timezone']],
            ['Gross area', number_format($site['grossAreaSqm']) . ' m²'],
        ], ' class="alte-kv"');

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Dashboard'))
            . $tiles
            . $this->card('Site', $siteKv, $site['name'])
            . $this->card('Recent sign-ins', $this->recentSignins($org, $seed), 'last 24 h · SSO');
    }

    /** Benign activity summary: who signed in and when — name/title/dept/last sign-in, NO secrets. */
    private function recentSignins(Org $org, int $seed): string
    {
        $seed_people = $org->people(8);
        $rows = [];
        foreach ($seed_people as $p) {
            $rows[] = [$p['name'], $p['title'], $p['dept'], $this->signinAgo($seed, $p['id'])];
        }
        return $this->tableHtml(['Name', 'Title', 'Department', 'Last sign-in'], $rows, ' class="alte-table"');
    }

    /** Seeded "N ago" off the persona seed + person id — deterministic per deploy, never time()/date(). */
    private function signinAgo(int $seed, string $empId): string
    {
        $sec = 60 + ($this->h($seed, 'signin|' . $empId) % 82800); // 1 min .. ~23 h
        if ($sec < 5400) {
            return (int) round($sec / 60) . ' min ago';
        }
        return (int) round($sec / 3600) . ' h ago';
    }

    private function h(int $seed, string $salt): int
    {
        return (int) hexdec(substr(hash('sha256', $seed . '|dash|' . $salt), 0, 13));
    }
}

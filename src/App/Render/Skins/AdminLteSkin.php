<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Skins;

use Funnypot\App\Render\AbstractSkin;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\PathSegments;
use Funnypot\App\Render\VisualPersona;

/**
 * A hand-authored lookalike of an AdminLTE/Bootstrap-style admin panel: a fixed left sidebar of menu
 * links, a top navbar naming the company, and card content in the main pane. Structural resemblance
 * only — no upstream AdminLTE/Bootstrap markup or CSS bytes are reproduced. This is the broadest
 * matcher of the four skins (`/admin`, `/dashboard`, `/manage`), so it is registered last in the
 * SkinSet — more specific product analogs (WordPress, phpMyAdmin, Grafana) get first refusal.
 */
final class AdminLteSkin extends AbstractSkin
{
    public function matches(string $path): bool
    {
        // This is the broadest resemblance matcher of the four, so it anchors the tightest: each
        // token must BE a whole path segment — or that segment plus a file extension (admin.php,
        // admin.aspx, dashboard.php, manage.php) — not merely appear inside one (e.g. "admin-notes"
        // and "administer" are not "admin"). "administrator" (Joomla's admin path, a common scanner
        // target) gets its own exact-segment token since the dot-suffix rule doesn't reach it — there
        // is no dot right after "admin" in "administrator". That's what keeps this skin from
        // swallowing paths it has no real business claiming, on top of being registered last in the
        // SkinSet.
        return PathSegments::hasSegmentOrDotSuffix($path, 'admin')
            || PathSegments::hasSegmentOrDotSuffix($path, 'dashboard')
            || PathSegments::hasSegmentOrDotSuffix($path, 'manage')
            || PathSegments::has($path, 'administrator');
    }

    public function key(): string
    {
        return 'adminlte';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath): string
    {
        $company = $this->esc($persona->company());
        $appName = $this->esc($slots->appName());
        $title = $slots->pageTitle() !== '' ? $slots->pageTitle() : $slots->appName();

        $html = '<div class="alte-wrapper">';

        $html .= '<nav class="alte-navbar">';
        $html .= '<span class="alte-brand">' . $company . '</span>';
        if ($appName !== '') {
            $html .= '<span class="alte-app">' . $appName . '</span>';
        }
        $html .= '</nav>';

        $html .= '<aside class="alte-sidebar">';
        $html .= '<ul class="alte-nav-sidebar">';
        foreach ($slots->navItems() as $item) {
            $html .= '<li class="alte-nav-item">' . $this->navHtml([$item], 'alte-nav-link') . '</li>';
        }
        $html .= '</ul>';
        $html .= '</aside>';

        $html .= '<div class="alte-content-wrapper"><section class="alte-content">';
        $html .= '<div class="alte-card">';

        $heading = $slots->heading();
        if ($heading !== '') {
            $html .= '<div class="alte-card-header">' . $this->esc($heading) . '</div>';
        }
        $html .= '<div class="alte-card-body">';
        if ($slots->intro() !== '') {
            $html .= '<p class="alte-intro">' . $this->esc($slots->intro()) . '</p>';
        }

        $html .= $this->tableHtml($slots->tableCols(), $slots->tableRows(), ' class="alte-table"');

        if ($slots->flash() !== '') {
            $html .= '<div class="alte-flash">' . $this->esc($slots->flash()) . '</div>';
        }
        $html .= '</div>'; // alte-card-body
        $html .= '</div>'; // alte-card
        $html .= '</section></div>'; // alte-content-wrapper

        $html .= '</div>'; // alte-wrapper

        return $this->document(
            $title,
            $this->css(),
            $html,
            ' lang="en"',
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width">',
            ' class="alte-body"'
        );
    }

    private function css(): string
    {
        // Palette reads as a Bootstrap-admin-template scheme (dark sidebar, blue-grey accent) but every
        // hex is nudged off any specific template's exact brand tokens — resemblance, not reuse.
        return 'body.alte-body{margin:0;font-family:sans-serif;background:#eef1f3;color:#2c3136}'
            . '.alte-wrapper{min-height:100vh}'
            . '.alte-navbar{position:fixed;top:0;left:0;right:0;height:52px;background:#fff;'
            . 'border-bottom:1px solid #d7dbdf;display:flex;align-items:center;gap:10px;padding:0 16px;'
            . 'box-sizing:border-box;z-index:2}'
            . '.alte-brand{font-weight:bold;color:#3b7ea1}'
            . '.alte-app{color:#6c757d}'
            . '.alte-sidebar{position:fixed;top:52px;bottom:0;left:0;width:230px;background:#2f3640;'
            . 'padding-top:10px;box-sizing:border-box;overflow-y:auto}'
            . '.alte-nav-sidebar{list-style:none;margin:0;padding:0}'
            . '.alte-nav-item{margin:0}'
            . '.alte-nav-link{display:block;padding:10px 16px;color:#c9ccd1;text-decoration:none}'
            . '.alte-nav-link:hover{background:#3b4148;color:#fff}'
            . '.alte-content-wrapper{margin-left:230px;padding-top:52px;box-sizing:border-box}'
            . '.alte-content{padding:20px}'
            . '.alte-card{background:#fff;border:1px solid #d7dbdf;border-radius:4px}'
            . '.alte-card-header{padding:10px 14px;border-bottom:1px solid #d7dbdf;font-weight:bold;'
            . 'color:#2c3136}'
            . '.alte-card-body{padding:14px}'
            . '.alte-intro{color:#5b636a}'
            . '.alte-table{border-collapse:collapse;width:100%;margin-top:8px}'
            . '.alte-table th,.alte-table td{border:1px solid #d7dbdf;padding:6px 10px;text-align:left}'
            . '.alte-flash{margin-top:12px;padding:8px 12px;background:#eaf2f6;border-left:4px solid #3b7ea1}';
    }
}

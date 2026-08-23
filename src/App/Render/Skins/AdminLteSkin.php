<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Skins;

use Funnypot\App\Render\AbstractSkin;
use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Render\PathSegments;
use Funnypot\App\Render\Panel\PanelRegistry;
use Funnypot\App\Render\VisualPersona;

/**
 * A hand-authored lookalike of an AdminLTE/Bootstrap-style server control panel — the honeypot's
 * flagship "juicy host" deep panel. Structural resemblance only; no upstream AdminLTE/Bootstrap markup
 * or CSS bytes are reproduced.
 *
 * Routing (design ruling R2 + spec §B.1): the request path is parsed positionally by PanelRoute into
 * module -> section -> entity -> sub-tab -> control leaf, and the module is dispatched to its own
 * PanelSection renderer via PanelRegistry. Adding a module is a new class behind the registry, not
 * another arm of a switch. An unknown module falls back to the Dashboard — a 404 inside a deep panel is
 * itself a tell. The grouped fixed sidebar links every registered module, so a crawl stays inside one
 * coherent site and finds a fresh rabbit hole on each click. All data comes from the seeded Fake\*
 * generators so the whole host identity agrees, frozen per deploy so the cached page is byte-identical.
 *
 * It is the broadest matcher of the skins, so it is registered last in the SkinSet — more specific
 * product analogs (WordPress, phpMyAdmin, Grafana) get first refusal.
 */
final class AdminLteSkin extends AbstractSkin
{
    /** Mount tokens (mirror of PanelRoute::MOUNTS) — used to root breadcrumb/nav links at the mount. */
    private const MOUNTS = ['admin', 'dashboard', 'manage', 'panel', 'console', 'cp', 'administrator'];

    /**
     * The grouped fixed sidebar (spec §B.2). [label, module-slug]; '' targets the panel root (Dashboard).
     * Every slug resolves to a registered section, so no nav link dead-ends.
     *
     * @var array<string,list<array{0:string,1:string}>>
     */
    private const NAV_GROUPS = [
        'Overview' => [
            ['Dashboard', ''],
        ],
        'IT & Platform' => [
            ['Servers', 'system'],
            ['Databases', 'databases'],
            ['Backups', 'backups'],
            ['Users & Roles', 'users'],
            ['API Keys', 'keys'],
            ['Cron', 'cron'],
            ['Processes', 'processes'],
            ['Logs', 'logs'],
            ['Files', 'files'],
        ],
        'Building · Smart Office' => [
            ['HVAC', 'hvac'],
            ['Access', 'access'],
        ],
        'Security & Safety' => [
            ['Fire & Life-Safety', 'fire'],
            ['CCTV', 'cctv'],
        ],
    ];

    /** Module slug -> page <title>; unmapped modules fall to the Dashboard title. */
    private const TITLES = [
        'system' => 'System Information', 'system-info' => 'System Information', 'servers' => 'System Information',
        'databases' => 'Databases', 'database' => 'Databases', 'db' => 'Databases', 'users' => 'Users',
        'backups' => 'Backups', 'backup' => 'Backups',
        'keys' => 'API Keys', 'api-keys' => 'API Keys', 'tokens' => 'API Keys',
        'cron' => 'Scheduled Tasks', 'jobs' => 'Scheduled Tasks',
        'processes' => 'Processes', 'ps' => 'Processes',
        'logs' => 'Logs', 'log' => 'Logs',
        'files' => 'File Manager', 'filemanager' => 'File Manager',
        'access' => 'Access Control', 'doors' => 'Access Control', 'badges' => 'Access Control',
        'fire' => 'Fire & Life-Safety', 'safety' => 'Fire & Life-Safety', 'life-safety' => 'Fire & Life-Safety',
        'cctv' => 'CCTV & Video', 'cameras' => 'CCTV & Video', 'nvr' => 'CCTV & Video',
        'hvac' => 'HVAC & Climate', 'climate' => 'HVAC & Climate', 'bms' => 'HVAC & Climate',
    ];

    /** @var PanelRegistry */
    private $registry;

    public function __construct()
    {
        $this->registry = new PanelRegistry();
    }

    public function matches(string $path): bool
    {
        // Each token must BE a whole path segment (or that segment plus a file extension) so the skin
        // does not swallow paths it has no business claiming. panel/console/cp keep the whole /panel/*
        // subtree in this one skin as a crawler follows the sidebar; administrator is Joomla's admin path.
        return PathSegments::hasSegmentOrDotSuffix($path, 'admin')
            || PathSegments::hasSegmentOrDotSuffix($path, 'dashboard')
            || PathSegments::hasSegmentOrDotSuffix($path, 'manage')
            || PathSegments::hasSegmentOrDotSuffix($path, 'panel')
            || PathSegments::hasSegmentOrDotSuffix($path, 'console')
            || PathSegments::hasSegmentOrDotSuffix($path, 'cp')
            || PathSegments::has($path, 'administrator');
    }

    public function key(): string
    {
        return 'adminlte';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $seed = $persona->seed();
        $sp = ServerProfile::fromSeed($seed);
        $route = PanelRoute::parse($path);
        $mountBase = $this->mountBase($path);
        $module = $route['module'];

        $company = $this->esc($persona->company());
        $appName = $this->esc($slots->appName() !== '' ? $slots->appName() : 'OneControl');
        $title = $slots->pageTitle() !== '' ? $slots->pageTitle() : $this->titleFor($module);

        $html = '<div class="alte-wrapper">';

        $html .= '<nav class="alte-navbar"><span class="alte-brand">' . $company . '</span>'
            . '<span class="alte-app">' . $appName . ' &middot; ' . $this->esc($sp->hostname()) . '</span></nav>';

        $html .= $this->sidebar($mountBase, $module);

        $html .= '<div class="alte-content-wrapper"><section class="alte-content">';

        // The model's heading/intro (when present) becomes a small page header above the section, so an
        // LLM-shaped page still reads coherently on a templated-miss path.
        if ($slots->heading() !== '' || $slots->intro() !== '') {
            $html .= '<div class="alte-card"><div class="alte-card-body">';
            if ($slots->heading() !== '') {
                $html .= '<div class="alte-card-header">' . $this->esc($slots->heading()) . '</div>';
            }
            if ($slots->intro() !== '') {
                $html .= '<p class="alte-intro">' . $this->esc($slots->intro()) . '</p>';
            }
            $html .= '</div></div>';
        }

        // Dispatch the module to its PanelSection; unknown module -> Dashboard (never a 404 in-panel).
        $html .= $this->registry->sectionFor($module)->render($route, $persona, $mountBase);

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

    /** The grouped fixed sidebar. Group headers are native <details> so the collapse is zero-JS. */
    private function sidebar(string $mountBase, string $currentModule): string
    {
        $html = '<aside class="alte-sidebar">';
        foreach (self::NAV_GROUPS as $group => $links) {
            $html .= '<details class="alte-nav-group" open><summary class="alte-nav-group-title">'
                . $this->esc($group) . '</summary><ul class="alte-nav-sidebar">';
            foreach ($links as $link) {
                $html .= '<li class="alte-nav-item">' . $this->sidebarLink($mountBase, $link[1], $link[0], $currentModule) . '</li>';
            }
            $html .= '</ul></details>';
        }
        return $html . '</aside>';
    }

    /** One sidebar link. Slug + label are trusted skin vocab; both are still escaped as defense-in-depth
     *  (the slug is the real structural guard — it can only ever be another sibling path under the mount). */
    private function sidebarLink(string $mountBase, string $slug, string $label, string $currentModule): string
    {
        $href = $slug === '' ? $mountBase : $mountBase . '/' . $slug;
        $active = ($slug === '' && $currentModule === '') || ($slug !== '' && $slug === $currentModule);
        $cls = $active ? 'alte-nav-link alte-nav-link-active' : 'alte-nav-link';
        return '<a class="' . $cls . '" href="' . $this->esc($href) . '">' . $this->esc($label) . '</a>';
    }

    /** The mount-rooted panel base for links, e.g. `/panel`, `/admin`. Uses the first mount segment's
     *  base token (extension stripped) so `/admin.php/...` roots cleanly at `/admin`. Defaults to
     *  `/admin` when no mount is present (matches() has already gated non-panel paths out). */
    private function mountBase(string $path): string
    {
        foreach (PathSegments::of($path) as $seg) {
            $lower = strtolower($seg);
            $base = strstr($lower, '.', true);
            $tok = $base === false ? $lower : $base;
            if (in_array($tok, self::MOUNTS, true)) {
                return '/' . $tok;
            }
        }
        return '/admin';
    }

    private function titleFor(string $module): string
    {
        return self::TITLES[$module] ?? 'Dashboard';
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
            . '.alte-app{color:#6c757d;font-size:.9em}'
            . '.alte-sidebar{position:fixed;top:52px;bottom:0;left:0;width:210px;background:#2f3640;'
            . 'padding-top:6px;box-sizing:border-box;overflow-y:auto}'
            . '.alte-nav-group{margin:0}'
            . '.alte-nav-group-title{padding:10px 16px 4px;color:#8b93a0;font-size:.72em;font-weight:600;'
            . 'text-transform:uppercase;letter-spacing:.06em;cursor:pointer;list-style:none}'
            . '.alte-nav-group-title::-webkit-details-marker{display:none}'
            . '.alte-nav-sidebar{list-style:none;margin:0 0 8px;padding:0}'
            . '.alte-nav-item{margin:0}'
            . '.alte-nav-link{display:block;padding:8px 16px;color:#c9ccd1;text-decoration:none;font-size:.92em}'
            . '.alte-nav-link:hover{background:#3b4148;color:#fff}'
            . '.alte-nav-link-active{background:#3b4148;color:#fff;border-left:3px solid #3b7ea1;padding-left:13px}'
            . '.alte-content-wrapper{margin-left:210px;padding-top:52px;box-sizing:border-box}'
            . '.alte-content{padding:20px}'
            . '.alte-card{background:#fff;border:1px solid #d7dbdf;border-radius:4px;margin-bottom:20px}'
            . '.alte-card-header{padding:10px 14px;border-bottom:1px solid #d7dbdf;font-weight:bold;'
            . 'color:#2c3136;display:flex;justify-content:space-between;align-items:center}'
            . '.alte-card-body{padding:14px}'
            . '.alte-intro{color:#5b636a}'
            . '.alte-muted{font-weight:normal;color:#9aa1a8;font-size:.82em}'
            . '.alte-table{border-collapse:collapse;width:100%;margin-top:4px}'
            . '.alte-table th,.alte-table td{border:1px solid #eef1f3;padding:6px 10px;text-align:left;font-size:.88em}'
            . '.alte-table th{background:#f7f9fa;color:#6c757d}'
            . '.alte-mono td{font-family:monospace;font-size:.82em;white-space:nowrap}'
            . '.alte-flash{margin-top:12px;padding:8px 12px;background:#eaf2f6;border-left:4px solid #3b7ea1}'
            . '.alte-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:20px}'
            . '.alte-st{background:#fff;border:1px solid #d7dbdf;border-radius:4px;padding:14px 16px}'
            . '.alte-st-v{font-size:1.5em;font-weight:bold;color:#2c3136}'
            . '.alte-st-l{color:#6c757d;font-size:.82em;margin-top:2px}'
            . '.alte-st-sub{color:#9aa1a8;font-size:.74em;margin-top:4px}'
            . '.alte-kv{border-collapse:collapse;width:100%}'
            . '.alte-kv th{width:150px;text-align:left;color:#6c757d;font-weight:600;vertical-align:top;'
            . 'padding:6px 10px;border-bottom:1px solid #eef1f3}'
            . '.alte-kv td{padding:6px 10px;border-bottom:1px solid #eef1f3;font-size:.9em}'
            . '.alte-dl{color:#3b7ea1;text-decoration:none;font-family:monospace}'
            . '.alte-dl:hover{text-decoration:underline}'
            . '.alte-pager{padding:10px 4px;color:#6c757d;font-size:.84em}'
            . '.alte-log{background:#1b1e21;color:#c9ccd1;padding:12px;border-radius:4px;overflow-x:auto;'
            . 'font-size:.78em;line-height:1.5;max-height:520px;overflow-y:auto;margin:0}';
    }
}

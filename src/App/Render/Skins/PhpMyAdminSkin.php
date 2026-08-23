<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Skins;

use Funnypot\App\Render\AbstractSkin;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\PathSegments;
use Funnypot\App\Render\VisualPersona;

/**
 * A hand-authored lookalike of the phpMyAdmin query-results screen: a database/table tree down the
 * left, a top bar naming the server, and a results grid on the right. Structural resemblance only —
 * no upstream phpMyAdmin markup or CSS bytes are reproduced, and the "server version" is picked
 * deterministically from a small plausible pool, keyed by the persona — a byte-identical version
 * banner on every deployment would itself be a fleet-wide static tell.
 */
final class PhpMyAdminSkin extends AbstractSkin
{
    /** Plausible MySQL/MariaDB version banners — never a copied real-world signature string. */
    private const VERSION_POOL = [
        '10.6.14-MariaDB-log',
        '10.11.6-MariaDB',
        '8.0.35-0ubuntu0.22.04.1',
        '5.7.42-log',
        '10.5.23-MariaDB-1:10.5.23+maria~ubu2004',
    ];

    public function matches(string $path): bool
    {
        // Each token is a whole path segment on its own (unlike WordPress's "wp-" prefix family), so
        // an exact per-segment match is the right anchor — no legitimate phpMyAdmin path buries these
        // as part of a longer segment name.
        return PathSegments::has($path, 'phpmyadmin')
            || PathSegments::has($path, 'pma')
            || PathSegments::has($path, 'PMA');
    }

    public function key(): string
    {
        return 'phpmyadmin';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $company = $this->esc($persona->company());
        $domain = $this->esc($persona->domain());
        $db = $this->esc($this->slug($persona->company()));

        $version = $this->esc($this->version($persona));
        $html = '<div class="pma-topbar">phpMyAdmin &middot; Server: ' . $domain
            . ' via TCP/IP &middot; Server version: ' . $version . '</div>';

        $html .= '<div class="pma-shell">';
        $html .= $this->tree($db, $company);

        $html .= '<main class="pma-main">';

        $heading = $slots->heading() !== '' ? $slots->heading() : $slots->appName();
        if ($heading !== '') {
            $html .= '<h1 class="pma-heading">' . $this->esc($heading) . '</h1>';
        }
        if ($slots->intro() !== '') {
            $html .= '<p class="pma-intro">' . $this->esc($slots->intro()) . '</p>';
        }
        if ($slots->flash() !== '') {
            $html .= '<div class="pma-notice">' . $this->esc($slots->flash()) . '</div>';
        }

        $html .= $this->results($slots->tableCols(), $slots->tableRows());

        $html .= '</main>';
        $html .= '</div>';

        return $this->document(
            'phpMyAdmin',
            $this->css(),
            $html,
            ' lang="en"',
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        );
    }

    /** Deterministic per-persona pick from VERSION_POOL — stable per host, varies across deployments. */
    private function version(VisualPersona $persona): string
    {
        $idx = hexdec(substr(md5($persona->company() . '|' . $persona->domain()), 0, 8)) % count(self::VERSION_POOL);
        return self::VERSION_POOL[$idx];
    }

    /** Turns a persona company name into a plausible lowercase db-name-shaped literal (display only). */
    private function slug(string $company): string
    {
        $slug = strtolower((string) preg_replace('/[^a-z0-9]+/i', '_', trim($company)));
        $slug = trim($slug, '_');
        return $slug !== '' ? $slug : 'app_db';
    }

    private function tree(string $db, string $company): string
    {
        $html = '<nav class="pma-tree">';
        $html .= '<div class="pma-tree-title">' . $company . '</div>';
        $html .= '<ul>';
        foreach ([$db, 'information_schema', 'performance_schema', 'mysql'] as $dbName) {
            $html .= '<li class="pma-db">' . $dbName;
            if ($dbName === $db) {
                $html .= '<ul class="pma-tables">';
                foreach (['users', 'sessions', 'options', 'logs'] as $table) {
                    $html .= '<li class="pma-table">' . $table . '</li>';
                }
                $html .= '</ul>';
            }
            $html .= '</li>';
        }
        $html .= '</ul></nav>';
        return $html;
    }

    /**
     * @param list<string> $cols
     * @param list<list<string>> $rows
     */
    private function results(array $cols, array $rows): string
    {
        if ($cols === [] && $rows === []) {
            return '';
        }
        $html = '<div class="pma-results-info">Showing rows 0 - ' . count($rows) . '</div>';
        $html .= $this->tableHtml($cols, $rows, ' class="pma-results"');
        return $html;
    }

    private function css(): string
    {
        // Palette reads as a phpMyAdmin-style grey/teal admin scheme, nudged off the product's exact
        // brand hex tokens — resemblance, not reuse.
        return 'body{margin:0;font-family:sans-serif;background:#f4f5f6;color:#2b2f33}'
            . '.pma-topbar{background:#2c3a42;color:#cfe3e0;padding:8px 16px;font-size:.85em}'
            . '.pma-shell{display:flex;min-height:100vh}'
            . '.pma-tree{width:220px;background:#e7ebec;border-right:1px solid #ccd2d4;padding:12px;'
            . 'box-sizing:border-box;font-size:.9em}'
            . '.pma-tree-title{font-weight:bold;margin-bottom:8px;color:#356b64}'
            . '.pma-tree ul{list-style:none;margin:0;padding-left:6px}'
            . '.pma-db{margin:4px 0;color:#2b2f33}'
            . '.pma-tables{padding-left:14px;margin-top:4px}'
            . '.pma-table{color:#4c5a5f;padding:2px 0}'
            . '.pma-main{flex:1;padding:18px 22px}'
            . '.pma-heading{margin-top:0;color:#2c3a42}'
            . '.pma-intro{color:#5b666b}'
            . '.pma-notice{background:#eef6f4;border-left:4px solid #4c9e8f;padding:8px 12px;margin:10px 0}'
            . '.pma-results-info{color:#5b666b;font-size:.85em;margin-bottom:6px}'
            . '.pma-results{border-collapse:collapse;width:100%}'
            . '.pma-results th{background:#dde6e4;text-align:left;padding:6px 10px;border:1px solid #ccd2d4}'
            . '.pma-results td{padding:6px 10px;border:1px solid #ccd2d4}';
    }
}

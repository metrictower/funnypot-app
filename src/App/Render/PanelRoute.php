<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

use Funnypot\Support\Chrome\PathSegments;

/**
 * Positional route parser for the deep admin panel. `AdminLteSkin` used to route on the LAST path
 * segment only (`end($segs)`), which collapsed every deep path to its leaf and made real depth
 * impossible. This turns a panel path into its ordered slots so the skin can render
 * module -> section -> entity -> sub-tab -> control leaf.
 *
 * Grammar, rooted at the mount (admin|dashboard|manage|panel|console|cp|administrator):
 *
 *   /{mount}/{module}/{section}/{entity}/{subtab}[/{action}/{arg}]
 *           level1     level2    level3    level4    control leaf
 *
 * Guarantees this parser gives (the skin decides fallbacks, not the parser):
 * - Everything up to and including the first mount segment is stripped; the rest map positionally.
 * - Every slot is slugified to [a-z0-9-] with the exact rule navHref() uses, so an attacker-controlled
 *   path is structurally inert as HTML and as an href — no scheme, quote, `//host`, or breakout ever
 *   survives into a slot. A slot the caller echoes still needs esc(); the slug is the routing guard.
 * - Pagination lives in the path, not a query string: a trailing `p<digits>` segment peels into `page`
 *   so the cache key stays the whole path. A query string never routes (it is cut before parsing).
 * - `filter` is the level-3 slot under its list-view name: a list section reads `filter`
 *   (`/employees/dept-finance`), a detail page reads `entity` (`/employees/emp-1047`) — the parser
 *   cannot tell which a section wants, so it exposes the one slug under both names.
 * - Missing slots default to '' (page to 1). Pure, deterministic, total: no I/O, never throws.
 */
final class PanelRoute
{
    /** Mount tokens claimed by AdminLteSkin::matches(); the first one seen roots the grammar. */
    private const MOUNTS = ['admin', 'dashboard', 'manage', 'panel', 'console', 'cp', 'administrator'];

    /**
     * @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string}
     */
    public static function parse(string $path): array
    {
        $out = [
            'module' => '', 'section' => '', 'entity' => '', 'subtab' => '',
            'action' => '', 'arg' => '', 'page' => 1, 'filter' => '',
        ];

        // A query string / fragment is display-only and must never route. Cut it before segmenting so
        // it cannot bleed into (and corrupt) a slot.
        $path = substr($path, 0, strcspn($path, "?#"));

        $segs = PathSegments::of($path);
        if ($segs === []) {
            return $out;
        }

        // Strip up to and including the first mount segment, wherever it sits.
        $mountAt = -1;
        foreach ($segs as $i => $seg) {
            if (self::isMount($seg)) {
                $mountAt = $i;
                break;
            }
        }
        $content = $mountAt >= 0 ? array_slice($segs, $mountAt + 1) : $segs;

        // Slugify each remaining segment; drop any that slug to '' (e.g. `..`, all-symbol) so positions
        // stay aligned to meaningful slots, matching how navBase() builds a safe path.
        $slugs = [];
        foreach ($content as $seg) {
            $slug = self::slug($seg);
            if ($slug !== '') {
                $slugs[] = $slug;
            }
        }

        // Peel a trailing p<digits> into page. Slugging already forced the shape, so `p<script>` cannot
        // reach here as `p...`; only a genuine `p7` matches.
        if ($slugs !== [] && preg_match('/^p([0-9]+)$/', $slugs[count($slugs) - 1], $m) === 1) {
            array_pop($slugs);
            $out['page'] = (int) $m[1];
        }

        foreach (['module', 'section', 'entity', 'subtab', 'action', 'arg'] as $idx => $key) {
            if (isset($slugs[$idx])) {
                $out[$key] = $slugs[$idx];
            }
        }
        $out['filter'] = $out['entity'];

        return $out;
    }

    /** A segment is a mount if its part before any file extension is a mount token (case-insensitive),
     *  matching how matches() admits both `admin` and `admin.php`. */
    private static function isMount(string $seg): bool
    {
        $lower = strtolower($seg);
        $base = strstr($lower, '.', true);
        return in_array($base === false ? $lower : $base, self::MOUNTS, true);
    }

    /** The exact slug rule navHref() uses: collapse every non-[a-z0-9] run to '-', trim edge dashes.
     *  Structurally guarantees the result matches [a-z0-9-]* and carries no scheme/quote/`//host`. */
    private static function slug(string $seg): string
    {
        return trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($seg)), '-');
    }
}

<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * Escape-by-construction base for every skin. A skin builds its page only through these protected
 * helpers, so a model value has exactly one way to reach output: esc()/tableHtml()/navHtml() (and the
 * title argument of document()), all of which route through Esc internally. There is no code path
 * left for a skin to concatenate raw model text into HTML directly. CSS and structural chrome
 * (class names, layout, `<html>`/`<head>`/`<body>` attributes) stay each skin's own responsibility —
 * they are trusted, skin-authored literals, never derived from PageSlots/model text.
 */
abstract class AbstractSkin implements Skin
{
    /** The one place a skin turns a raw model value into escaped text for an ad-hoc sink (a heading,
     *  an intro paragraph, a flash message, ...) that doesn't fit tableHtml()/navHtml()/document(). */
    protected function esc(string $v): string
    {
        return Esc::text($v);
    }

    /**
     * Assembles a full HTML document. $title is model-derived and is escaped here, once. $inlineCss
     * and $bodyHtml are trusted, skin-assembled raw markup. $htmlAttrs/$headExtra/$bodyAttrs are
     * likewise trusted skin-authored literals (e.g. a `lang` attribute, a viewport meta tag, a body
     * class a skin's own CSS selects on) — never built from PageSlots/model text — kept as parameters
     * only so each skin's product-identifying document chrome survives the shared assembly.
     */
    protected function document(
        string $title,
        string $inlineCss,
        string $bodyHtml,
        string $htmlAttrs = ' lang=en',
        string $headExtra = '<meta charset=utf-8>',
        string $bodyAttrs = ''
    ): string {
        return '<!doctype html><html' . $htmlAttrs . '><head>' . $headExtra
            . '<title>' . $this->esc($title) . '</title>'
            . '<style>' . $inlineCss . '</style>'
            . '</head><body' . $bodyAttrs . '>' . $bodyHtml . '</body></html>';
    }

    /**
     * The one canonical table renderer: escapes every column header and every cell. Replaces the
     * escape-the-cell loop that used to be hand-rolled once per skin. Returns '' when there is
     * nothing to show, so a skin can call this unconditionally.
     *
     * @param list<string> $cols
     * @param list<list<string>> $rows
     * @param string $tableAttrs trusted literal, e.g. ' class="alte-table"' (include the leading space)
     */
    protected function tableHtml(array $cols, array $rows, string $tableAttrs = ''): string
    {
        if ($cols === [] && $rows === []) {
            return '';
        }
        $html = '<table' . $tableAttrs . '>';
        if ($cols !== []) {
            $html .= '<thead><tr>';
            foreach ($cols as $col) {
                $html .= '<th>' . $this->esc($col) . '</th>';
            }
            $html .= '</tr></thead>';
        }
        $html .= '<tbody>';
        foreach ($rows as $row) {
            $html .= '<tr>';
            foreach ($row as $cell) {
                $html .= '<td>' . $this->esc($cell) . '</td>';
            }
            $html .= '</tr>';
        }
        return $html . '</tbody></table>';
    }

    /**
     * Escapes each nav item's label and points href at a slug derived from that label, so a crawl
     * of the honeypot can follow a nav link to another sibling path the honeypot itself answers
     * (site-graph feel) instead of a dead '#' anchor. The href is never raw model text — see
     * navHref() for how the slug is constructed to be structurally safe. A skin wraps the returned
     * anchors in its own `<nav>`/`<ul>` chrome; this only owns the per-item escaping + href.
     *
     * @param list<string> $items
     * @param string $linkClass trusted literal class name, or '' for no class attribute
     */
    protected function navHtml(array $items, string $linkClass = '', string $navBase = ''): string
    {
        $classAttr = $linkClass !== '' ? ' class="' . $linkClass . '"' : '';
        $html = '';
        foreach ($items as $item) {
            $href = $this->esc($this->navHref($item, $navBase));
            $html .= '<a' . $classAttr . ' href="' . $href . '">' . $this->esc($item) . '</a>';
        }
        return $html;
    }

    /**
     * Turns a nav label into a safe relative sibling path: lowercase, collapse every run of
     * non-`[a-z0-9]` characters to a single '-', trim leading/trailing '-', prefix with '/'.
     * The result can only ever match `/[a-z0-9-]*` — it structurally cannot carry a scheme
     * (javascript:/data:), a protocol-relative `//host`, a quote, or an HTML breakout, so a
     * model-controlled label can never turn the href into anything but another sibling path
     * that the honeypot's own routing answers. Falls back to '#' when the label has no
     * alnum content to slug (still run through esc() by the caller as attribute
     * defense-in-depth, though the slug is already the real guard).
     */
    private function navHref(string $label, string $navBase = ''): string
    {
        $slug = trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($label)), '-');
        return $slug === '' ? '#' : $navBase . '/' . $slug;
    }

    /**
     * The safe base for sibling nav links: the current request path's PARENT directory, each segment
     * slugified to [a-z0-9-] exactly like a nav label. A nav link then stays under the same prefix the
     * crawler is already on (/panel/dashboard -> base /panel -> /panel/logs) instead of jumping to a
     * root path a different rule owns. Per-segment slugging keeps the base structurally safe even
     * though the request path is attacker-controlled (no scheme, quote, //host or breakout survives).
     * Returns '' for a root-level or empty path, so navHref falls back to a root slug (/logs).
     */
    protected function navBase(string $path): string
    {
        $segs = [];
        foreach (explode('/', $path) as $seg) {
            if ($seg === '') {
                continue;
            }
            $slug = trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($seg)), '-');
            if ($slug !== '') {
                $segs[] = $slug;
            }
        }
        array_pop($segs); // nav links are siblings of the current leaf, so drop it
        return $segs === [] ? '' : '/' . implode('/', $segs);
    }

    /**
     * A row of stat cards (label + big value + optional sub-line). Values are escaped here; the
     * wrapper/card class names are trusted skin literals.
     *
     * @param list<array{label:string,value:string,sub?:string}> $cards
     */
    protected function statCardsHtml(array $cards, string $wrapClass, string $cardClass): string
    {
        if ($cards === []) {
            return '';
        }
        $html = '<div class="' . $wrapClass . '">';
        foreach ($cards as $c) {
            $sub = isset($c['sub']) && $c['sub'] !== ''
                ? '<div class="' . $cardClass . '-sub">' . $this->esc($c['sub']) . '</div>'
                : '';
            $html .= '<div class="' . $cardClass . '">'
                . '<div class="' . $cardClass . '-v">' . $this->esc($c['value']) . '</div>'
                . '<div class="' . $cardClass . '-l">' . $this->esc($c['label']) . '</div>'
                . $sub . '</div>';
        }
        return $html . '</div>';
    }

    /**
     * A two-column key/value table (system-info style). Every key and value is escaped.
     *
     * @param list<array{0:string,1:string}> $pairs
     */
    protected function kvTableHtml(array $pairs, string $tableAttrs = ''): string
    {
        if ($pairs === []) {
            return '';
        }
        $html = '<table' . $tableAttrs . '><tbody>';
        foreach ($pairs as $p) {
            $html .= '<tr><th>' . $this->esc($p[0]) . '</th><td>' . $this->esc($p[1]) . '</td></tr>';
        }
        return $html . '</tbody></table>';
    }

    /**
     * A downloads table where each row's first field is a filename rendered as a link to a sibling path
     * that PRESERVES the file extension (so an archive name routes to the decoy-archive handler). The
     * filename must be skin/generator-authored trusted vocab matching [A-Za-z0-9._-]; anything else
     * renders as plain text (never a link), so no model/attacker value can shape the href. $navBase +
     * $subPath are trusted (navBase is per-segment slugged; subPath a skin literal). Remaining cells
     * are escaped text.
     *
     * @param list<string> $cols
     * @param list<array{file:string,cells:list<string>}> $rows
     */
    protected function downloadTableHtml(array $cols, array $rows, string $navBase, string $subPath, string $tableAttrs = '', string $linkClass = ''): string
    {
        $classAttr = $linkClass !== '' ? ' class="' . $linkClass . '"' : '';
        $html = '<table' . $tableAttrs . '><thead><tr>';
        foreach ($cols as $c) {
            $html .= '<th>' . $this->esc($c) . '</th>';
        }
        $html .= '</tr></thead><tbody>';
        foreach ($rows as $r) {
            $file = $r['file'];
            if (preg_match('/^[A-Za-z0-9._-]+$/', $file) === 1) {
                $href = $this->esc($navBase . $subPath . '/' . $file);
                $first = '<a' . $classAttr . ' href="' . $href . '">' . $this->esc($file) . '</a>';
            } else {
                $first = $this->esc($file);
            }
            $html .= '<tr><td>' . $first . '</td>';
            foreach ($r['cells'] as $cell) {
                $html .= '<td>' . $this->esc($cell) . '</td>';
            }
            $html .= '</tr>';
        }
        return $html . '</tbody></table>';
    }

    /**
     * A scroll-back pane of raw log lines, each escaped, joined with newlines inside a <pre> so a long
     * buffer reads as a real log tail. The wrapper class is a trusted skin literal.
     *
     * @param list<string> $lines
     */
    protected function preScrollHtml(array $lines, string $class): string
    {
        if ($lines === []) {
            return '';
        }
        $out = '';
        foreach ($lines as $l) {
            $out .= $this->esc($l) . "\n";
        }
        return '<pre class="' . $class . '">' . $out . '</pre>';
    }
}

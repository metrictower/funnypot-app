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
    protected function navHtml(array $items, string $linkClass = ''): string
    {
        $classAttr = $linkClass !== '' ? ' class="' . $linkClass . '"' : '';
        $html = '';
        foreach ($items as $item) {
            $href = $this->esc($this->navHref($item));
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
    private function navHref(string $label): string
    {
        $slug = trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($label)), '-');
        return $slug === '' ? '#' : '/' . $slug;
    }
}

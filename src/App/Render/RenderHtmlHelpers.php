<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * The escape-by-construction rendering primitives, factored out of AbstractSkin so both a skin and a
 * deep-panel PanelSection (which cannot extend AbstractSkin — their render() signatures would clash)
 * build markup through the exact same escaping helpers. A model value has one way to reach output:
 * esc()/tableHtml()/navHtml()/kvTableHtml()/downloadTableHtml()/preScrollHtml() and the widget helpers
 * below (and the title argument of document()), all of which route through Esc internally. There is no
 * code path left to concatenate raw model text into HTML directly. CSS and structural chrome (class
 * names, layout, `<html>`/`<head>`/`<body>` attributes) stay skin-authored trusted literals, never
 * derived from PageSlots/model text.
 */
trait RenderHtmlHelpers
{
    /** The one place a raw model value turns into escaped text for an ad-hoc sink (a heading, an intro
     *  paragraph, a flash message, ...) that doesn't fit tableHtml()/navHtml()/document(). */
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
     * The one canonical table renderer: escapes every column header and every cell. Returns '' when
     * there is nothing to show, so a skin can call this unconditionally.
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
     * A card: an escaped header (with an optional muted extra) over trusted body markup. The body is
     * assembled by the caller through these same helpers, so it is already escaped; the header/extra
     * are escaped here. $bodyClass/$headerExtra styling comes from skin CSS.
     */
    protected function card(string $header, string $body, string $headerExtra = ''): string
    {
        $extra = $headerExtra !== '' ? '<span class="alte-muted">' . $this->esc($headerExtra) . '</span>' : '';
        return '<div class="alte-card"><div class="alte-card-header">' . $this->esc($header) . $extra . '</div>'
            . '<div class="alte-card-body">' . $body . '</div></div>';
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
            // Safe archive name: allowlisted chars AND no '..' run, so the href can only ever be a
            // sibling download path, never a traversal — even if a less-trusted name ever reaches here.
            if (preg_match('/^[A-Za-z0-9._-]+$/', $file) === 1 && strpos($file, '..') === false) {
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

    // --- deep-panel widget vocabulary (all SVG/CSS, escape-by-construction, deterministic) ---
    //
    // These carry their own inline styles so any skin/section can call them without depending on
    // skin-level CSS. The only values that reach output are: model/attacker text (routed through
    // esc()), a clamped integer, a coerced finite number, or a fixed hex literal chosen by a
    // map/threshold — never a raw model value concatenated into markup.

    /**
     * A small status badge. $label is escaped; $status only selects a fixed colour pair (never rendered
     * itself), so an attacker-controlled status is structurally inert. Known states: ok/warn/crit/info;
     * anything else is the neutral idle look.
     */
    protected function pillHtml(string $label, string $status): string
    {
        [$fg, $bg] = $this->pillColors($status);
        return '<span class="fp-pill" style="display:inline-block;padding:2px 9px;border-radius:10px;'
            . 'font-size:.76em;font-weight:600;line-height:1.5;white-space:nowrap;color:' . $fg . ';background:' . $bg . '">'
            . $this->esc($label) . '</span>';
    }

    /** Fixed foreground/background hex pair per status; unknown status falls to the neutral idle pair. */
    private function pillColors(string $status): array
    {
        switch (strtolower(trim($status))) {
            case 'ok':
                return ['#ffffff', '#2e8b57'];
            case 'warn':
                return ['#ffffff', '#c07a1a'];
            case 'crit':
                return ['#ffffff', '#b23b3b'];
            case 'info':
                return ['#ffffff', '#3b7ea1'];
            default:
                return ['#40474e', '#e3e6e8'];
        }
    }

    /**
     * A radial gauge: an inline-SVG top semicircle whose coloured fill grows with $valuePct (clamped
     * 0-100, higher = more severe band). $text (a free reading, e.g. "182 kW") and $label are escaped;
     * the fill length is arithmetic off the fixed arc length and the band colour is a threshold literal.
     */
    protected function gaugeHtml(string $label, int $valuePct, string $text): string
    {
        $pct = $valuePct < 0 ? 0 : ($valuePct > 100 ? 100 : $valuePct);
        // Length of the r=40 top-semicircle arc path used below (pi * 40). A dasharray of "<filled> <arc>"
        // fills from the left (empty) toward the right (full) in proportion to the value.
        $arc = 125.66;
        $filled = $this->num(round($arc * $pct / 100, 2));
        $color = $this->gaugeBandColor($pct);
        $svg = '<svg class="fp-gauge-svg" viewBox="0 0 100 60" preserveAspectRatio="xMidYMid meet" '
            . 'style="width:100%;max-width:160px;height:auto;display:block;margin:0 auto">'
            . '<path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="#e3e6e8" stroke-width="8" stroke-linecap="round"/>'
            . '<path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="' . $color . '" stroke-width="8" '
            . 'stroke-linecap="round" stroke-dasharray="' . $filled . ' ' . $arc . '"/>'
            . '<text x="50" y="46" text-anchor="middle" font-size="16" font-family="sans-serif" '
            . 'font-weight="bold" fill="#2c3136">' . $pct . '%</text></svg>';
        return '<div class="fp-gauge" style="display:inline-block;text-align:center;min-width:120px">'
            . $svg
            . '<div class="fp-gauge-text" style="font-size:.82em;color:#5b636a">' . $this->esc($text) . '</div>'
            . '<div class="fp-gauge-label" style="font-size:.72em;color:#9aa1a8;text-transform:uppercase;letter-spacing:.04em">'
            . $this->esc($label) . '</div></div>';
    }

    /** Threshold band colour for a gauge: higher percentage reads as the more severe state. */
    private function gaugeBandColor(int $pct): string
    {
        if ($pct <= 60) {
            return '#2e8b57';
        }
        if ($pct <= 85) {
            return '#c07a1a';
        }
        return '#b23b3b';
    }

    /**
     * A sparkline: an inline-SVG polyline of the readings, auto-scaled to the box. $points are the raw
     * numeric readings (from a seeded generator); each is coerced to a finite float and only ever reaches
     * output as a formatted coordinate, so no text sink exists here. Empty input renders nothing; a single
     * reading draws as a flat line.
     *
     * @param list<int|float> $points
     */
    protected function sparklineHtml(array $points): string
    {
        if ($points === []) {
            return '';
        }
        $vals = [];
        foreach ($points as $p) {
            $f = (float) $p;
            $vals[] = is_finite($f) ? $f : 0.0;
        }
        if (count($vals) === 1) {
            $vals[] = $vals[0];
        }
        $n = count($vals);
        $min = min($vals);
        $max = max($vals);
        $range = $max - $min;
        $pad = 2.0;
        $coords = [];
        foreach ($vals as $i => $v) {
            $x = ($i / ($n - 1)) * 100.0;
            $y = $range > 0.0
                ? (30.0 - $pad) - (($v - $min) / $range) * (30.0 - 2.0 * $pad)
                : 15.0;
            $coords[] = $this->num($x) . ',' . $this->num($y);
        }
        return '<svg class="fp-sparkline" viewBox="0 0 100 30" preserveAspectRatio="none" '
            . 'style="width:100%;height:30px;display:block;overflow:visible">'
            . '<polyline points="' . implode(' ', $coords) . '" fill="none" stroke="#3b7ea1" '
            . 'stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/></svg>';
    }

    /**
     * A breadcrumb trail. Each crumb is [label, href]; labels are escaped and every crumb but the last
     * links (the last is the current page, rendered as plain text). An href must be a rooted, structurally
     * safe path (navBase style) or the crumb degrades to plain text — no scheme, //host, quote, or
     * breakout can reach the attribute even though hrefs are meant to be skin-authored.
     *
     * @param list<array{0:string,1:string}> $crumbs
     */
    protected function breadcrumbHtml(array $crumbs): string
    {
        if ($crumbs === []) {
            return '';
        }
        $crumbs = array_values($crumbs);
        $last = count($crumbs) - 1;
        $html = '<nav class="fp-breadcrumb" style="font-size:.84em;color:#6c757d;margin-bottom:12px">';
        foreach ($crumbs as $i => $crumb) {
            $label = isset($crumb[0]) ? (string) $crumb[0] : '';
            $href = isset($crumb[1]) ? $this->safeCrumbHref((string) $crumb[1]) : '#';
            if ($i > 0) {
                $html .= '<span class="fp-breadcrumb-sep" style="margin:0 6px;color:#c9ccd1">/</span>';
            }
            if ($i < $last && $href !== '#') {
                $html .= '<a class="fp-breadcrumb-link" style="color:#3b7ea1;text-decoration:none" href="'
                    . $this->esc($href) . '">' . $this->esc($label) . '</a>';
            } else {
                $html .= '<span class="fp-breadcrumb-cur">' . $this->esc($label) . '</span>';
            }
        }
        return $html . '</nav>';
    }

    /**
     * Constrains a breadcrumb href to a rooted slug path; anything else becomes '#' (rendered as plain
     * text). Same structural guarantee navHref gives: the attribute can only carry another sibling path.
     */
    private function safeCrumbHref(string $href): string
    {
        return preg_match('#^/[A-Za-z0-9/_.-]*$#', $href) === 1 ? $href : '#';
    }

    /**
     * The shared inert-control confirmation: a "command queued" card. $title is escaped; $detailPairs
     * render through kvTableHtml (each key/value escaped). Nothing here is or implies real state change —
     * it is the one canned landing every toggle/slider/button resolves to.
     *
     * @param list<array{0:string,1:string}> $detailPairs
     */
    protected function controlResultCard(string $title, array $detailPairs): string
    {
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #3b7ea1;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Queued', 'info')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . $this->kvTableHtml($detailPairs, ' class="fp-result-kv" style="border-collapse:collapse;width:100%"')
            . '</div></div>';
    }

    /** Formats a finite number as a compact coordinate/length string (max 2 dp, no trailing zeros). */
    private function num(float $v): string
    {
        if (!is_finite($v)) {
            $v = 0.0;
        }
        $s = number_format($v, 2, '.', '');
        return strpos($s, '.') !== false ? rtrim(rtrim($s, '0'), '.') : $s;
    }
}

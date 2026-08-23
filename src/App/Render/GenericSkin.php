<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * The default chrome for any path with no closer analog: a plain internal-app look (header, nav,
 * content box, footer) built entirely from PageSlots + VisualPersona. Every CSS byte, class name AND
 * the DOM/CSS *skeleton* itself (class-name vocabulary, nav markup shape, content wrapper element,
 * declaration order, an optional breadcrumb bar) is seed-derived via VisualPersona::pick() — not just
 * the palette hex and the fp-XXXX prefix. A value-normalizing scanner that strips colors/ids away
 * would otherwise still see one fixed skeleton for the whole fleet, which is itself a fingerprint;
 * varying the skeleton per deployment closes that residual (see GenericSkinEntropyTest).
 */
final class GenericSkin extends AbstractSkin
{
    /** @var non-empty-list<string> */
    private const HEADER_WORDS = ['header', 'topbar', 'masthead', 'banner'];
    /** @var non-empty-list<string> */
    private const NAV_WORDS = ['nav', 'menu', 'links', 'tabs'];
    /** @var non-empty-list<string> */
    private const BOX_WORDS = ['box', 'panel', 'card', 'content'];
    /** @var non-empty-list<string> */
    private const FOOTER_WORDS = ['footer', 'foot', 'base'];
    /** @var non-empty-list<string> content-wrapper element */
    private const WRAPPER_TAGS = ['main', 'section', 'div'];

    public function matches(string $path): bool
    {
        return true;
    }

    public function key(): string
    {
        return 'generic';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $p = $persona->classPrefix();
        $pal = $persona->palette();
        $navBase = $this->navBase($path);

        // Structural picks: deterministic per persona seed (same deployment always renders the same
        // skeleton), independent per axis via distinct salts (so they don't move in lockstep with
        // each other or with the palette/prefix), and orthogonal to model content entirely — these
        // never touch PageSlots values, only skin-authored trusted vocabulary/shape.
        $hdWord = $persona->pick('hd-word', self::HEADER_WORDS);
        $navWord = $persona->pick('nav-word', self::NAV_WORDS);
        $boxWord = $persona->pick('box-word', self::BOX_WORDS);
        $ftWord = $persona->pick('ft-word', self::FOOTER_WORDS);
        $wrapTag = $persona->pick('wrap-tag', self::WRAPPER_TAGS);
        $navAsList = $persona->pick('nav-shape', ['list', 'inline']) === 'list';
        $cssAltOrder = $persona->pick('css-order', ['a', 'b']) === 'b';
        $withCrumbs = $persona->pick('crumbs', ['yes', 'no']) === 'yes';

        $company = $this->esc($persona->company());
        $appName = $this->esc($slots->appName());
        $title = $slots->pageTitle() !== '' ? $slots->pageTitle() : $slots->appName();

        $body = '<header class="' . $p . '-' . $hdWord . '">'
            . '<span class="' . $p . '-brand">' . $company . '</span>';
        if ($appName !== '') {
            $body .= ' <span class="' . $p . '-app">' . $appName . '</span>';
        }
        $body .= '</header>';

        if ($withCrumbs) {
            $body .= '<div class="' . $p . '-crumbs">Home</div>';
        }

        $body .= $this->nav($p, $navWord, $navAsList, $slots->navItems(), $navBase);

        $body .= '<' . $wrapTag . ' class="' . $p . '-' . $boxWord . '">';
        $body .= $this->heading($slots->heading());
        $body .= $this->intro($p, $slots->intro());
        $body .= $this->tableHtml($slots->tableCols(), $slots->tableRows(), ' class="' . $p . '-table"');
        $body .= $this->form($p, $slots->formFields(), $escapedPath);
        $body .= $this->flash($p, $slots->flash());
        $body .= '</' . $wrapTag . '>';

        $body .= '<footer class="' . $p . '-' . $ftWord . '">&copy; ' . $company;
        $footerNote = $slots->footerNote();
        if ($footerNote !== '') {
            $body .= ' &middot; ' . $this->esc($footerNote);
        }
        $body .= '</footer>';

        $css = $this->css($p, $pal, $hdWord, $navWord, $boxWord, $ftWord, $navAsList, $withCrumbs, $cssAltOrder);
        return $this->document($title, $css, $body);
    }

    /** @param array{bg:string,fg:string,accent:string,muted:string,border:string} $pal */
    private function css(
        string $p,
        array $pal,
        string $hdWord,
        string $navWord,
        string $boxWord,
        string $ftWord,
        bool $navAsList,
        bool $withCrumbs,
        bool $altOrder
    ): string {
        // The header/box rules below are written as two equivalent property orderings (both valid,
        // same rendered result, since none of these properties conflict) so the seed also perturbs
        // CSS *declaration order* — a structural byte, not a color leaf, so it survives a normalizer
        // that only strips hex values and the fp- prefix.
        $hdRule = $altOrder
            ? ".{$p}-{$hdWord}{padding:14px 22px;color:#fff;background:{$pal['accent']}}"
            : ".{$p}-{$hdWord}{background:{$pal['accent']};color:#fff;padding:14px 22px}";
        $boxRule = $altOrder
            ? ".{$p}-{$boxWord}{border-radius:6px;border:1px solid {$pal['border']};background:{$pal['bg']};padding:22px;margin:22px}"
            : ".{$p}-{$boxWord}{margin:22px;padding:22px;background:{$pal['bg']};border:1px solid {$pal['border']};border-radius:6px}";

        $css = "body{margin:0;font-family:sans-serif;background:{$pal['bg']};color:{$pal['fg']}}"
            . $hdRule
            . ".{$p}-app{color:#fff;opacity:.85}"
            . ".{$p}-{$navWord}{background:{$pal['bg']};border-bottom:1px solid {$pal['border']};padding:8px 22px}"
            . ".{$p}-{$navWord} a{color:{$pal['fg']};margin-right:16px;text-decoration:none}";
        if ($navAsList) {
            $css .= ".{$p}-{$navWord}-list{list-style:none;margin:0;padding:0;display:flex}";
        }
        if ($withCrumbs) {
            $css .= ".{$p}-crumbs{padding:6px 22px;color:{$pal['muted']};font-size:.8em}";
        }
        $css .= $boxRule
            . ".{$p}-intro{color:{$pal['muted']}}"
            . ".{$p}-table{border-collapse:collapse;width:100%;margin-top:12px}"
            . ".{$p}-table th,.{$p}-table td{border:1px solid {$pal['border']};padding:6px 10px;text-align:left}"
            . ".{$p}-form input{border:1px solid {$pal['border']};padding:4px 8px;margin:4px 0;display:block}"
            . ".{$p}-flash{margin-top:12px;padding:8px 12px;background:{$pal['accent']};color:#fff;border-radius:4px}"
            . ".{$p}-{$ftWord}{padding:14px 22px;color:{$pal['muted']};font-size:.85em}";

        return $css;
    }

    /** @param list<string> $items */
    private function nav(string $p, string $word, bool $asList, array $items, string $navBase = ''): string
    {
        if ($items === []) {
            return '';
        }
        if (!$asList) {
            return '<nav class="' . $p . '-' . $word . '">' . $this->navHtml($items, '', $navBase) . '</nav>';
        }
        $html = '<ul class="' . $p . '-' . $word . '-list">';
        foreach ($items as $item) {
            $html .= '<li>' . $this->navHtml([$item], '', $navBase) . '</li>';
        }
        $html .= '</ul>';
        return '<nav class="' . $p . '-' . $word . '">' . $html . '</nav>';
    }

    private function heading(string $heading): string
    {
        return $heading !== '' ? '<h1>' . $this->esc($heading) . '</h1>' : '';
    }

    private function intro(string $p, string $intro): string
    {
        return $intro !== '' ? '<p class="' . $p . '-intro">' . $this->esc($intro) . '</p>' : '';
    }

    /** @param list<string> $fields */
    private function form(string $p, array $fields, string $escapedPath): string
    {
        if ($fields === []) {
            return '';
        }
        // $escapedPath is pre-escaped by the caller; the field name is a synthetic index, not a
        // model value, so both are safe directly in these attribute sinks.
        $html = '<form class="' . $p . '-form" method="post" action="' . $escapedPath . '">';
        foreach ($fields as $idx => $field) {
            $html .= '<label>' . $this->esc($field)
                . '<input type="text" name="f' . $idx . '"></label>';
        }
        return $html . '<button type="submit">Submit</button></form>';
    }

    private function flash(string $p, string $flash): string
    {
        return $flash !== '' ? '<div class="' . $p . '-flash">' . $this->esc($flash) . '</div>' : '';
    }
}

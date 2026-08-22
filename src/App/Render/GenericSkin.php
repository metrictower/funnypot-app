<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * The default chrome for any path with no closer analog: a plain internal-app look (header, nav,
 * content box, footer) built entirely from PageSlots + VisualPersona. Every CSS byte and class name
 * is seed-derived (palette()/classPrefix()) so a fixed public skin still gives each fake host its
 * own look — collapsing every host to one static stylesheet would itself be a fleet-wide fingerprint.
 */
final class GenericSkin extends AbstractSkin
{
    public function matches(string $path): bool
    {
        return true;
    }

    public function key(): string
    {
        return 'generic';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath): string
    {
        $p = $persona->classPrefix();
        $pal = $persona->palette();

        $company = $this->esc($persona->company());
        $appName = $this->esc($slots->appName());
        $title = $slots->pageTitle() !== '' ? $slots->pageTitle() : $slots->appName();

        $body = '<header class="' . $p . '-hd">'
            . '<span class="' . $p . '-brand">' . $company . '</span>';
        if ($appName !== '') {
            $body .= ' <span class="' . $p . '-app">' . $appName . '</span>';
        }
        $body .= '</header>';

        $body .= $this->nav($p, $slots->navItems());

        $body .= '<main class="' . $p . '-box">';
        $body .= $this->heading($slots->heading());
        $body .= $this->intro($p, $slots->intro());
        $body .= $this->tableHtml($slots->tableCols(), $slots->tableRows(), ' class="' . $p . '-table"');
        $body .= $this->form($p, $slots->formFields(), $escapedPath);
        $body .= $this->flash($p, $slots->flash());
        $body .= '</main>';

        $body .= '<footer class="' . $p . '-ft">&copy; ' . $company;
        $footerNote = $slots->footerNote();
        if ($footerNote !== '') {
            $body .= ' &middot; ' . $this->esc($footerNote);
        }
        $body .= '</footer>';

        return $this->document($title, $this->css($p, $pal), $body);
    }

    /** @param array{bg:string,fg:string,accent:string,muted:string,border:string} $pal */
    private function css(string $p, array $pal): string
    {
        return "body{margin:0;font-family:sans-serif;background:{$pal['bg']};color:{$pal['fg']}}"
            . ".{$p}-hd{background:{$pal['accent']};color:#fff;padding:14px 22px}"
            . ".{$p}-app{color:#fff;opacity:.85}"
            . ".{$p}-nav{background:{$pal['bg']};border-bottom:1px solid {$pal['border']};padding:8px 22px}"
            . ".{$p}-nav a{color:{$pal['fg']};margin-right:16px;text-decoration:none}"
            . ".{$p}-box{margin:22px;padding:22px;background:{$pal['bg']};border:1px solid {$pal['border']};border-radius:6px}"
            . ".{$p}-intro{color:{$pal['muted']}}"
            . ".{$p}-table{border-collapse:collapse;width:100%;margin-top:12px}"
            . ".{$p}-table th,.{$p}-table td{border:1px solid {$pal['border']};padding:6px 10px;text-align:left}"
            . ".{$p}-form input{border:1px solid {$pal['border']};padding:4px 8px;margin:4px 0;display:block}"
            . ".{$p}-flash{margin-top:12px;padding:8px 12px;background:{$pal['accent']};color:#fff;border-radius:4px}"
            . ".{$p}-ft{padding:14px 22px;color:{$pal['muted']};font-size:.85em}";
    }

    /** @param list<string> $items */
    private function nav(string $p, array $items): string
    {
        if ($items === []) {
            return '';
        }
        return '<nav class="' . $p . '-nav">' . $this->navHtml($items) . '</nav>';
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

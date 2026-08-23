<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\RenderHtmlHelpers;

/**
 * Base for every PanelSection: pulls in the shared escape-by-construction rendering primitives
 * (esc/card/tableHtml/kvTableHtml/downloadTableHtml/preScrollHtml/statCardsHtml/pill/gauge/
 * sparkline/breadcrumb/controlResultCard) so a module renderer builds markup exactly the way a skin
 * does, without being a skin. Subclasses implement render(); everything else is inherited.
 */
abstract class AbstractPanelSection implements PanelSection
{
    use RenderHtmlHelpers;

    /**
     * The standard two-crumb trail for a module landing: the panel root, then the module title (current
     * page, plain text). Deeper sections append their own crumbs before the last one.
     *
     * @return list<array{0:string,1:string}>
     */
    protected function baseCrumbs(string $navBase, string $moduleTitle): array
    {
        return [['OneControl', $navBase], [$moduleTitle, '']];
    }
}

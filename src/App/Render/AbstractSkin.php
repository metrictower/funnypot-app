<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * Escape-by-construction base for every skin. A skin builds its page only through the RenderHtmlHelpers
 * primitives, so a model value has exactly one way to reach output: esc()/tableHtml()/navHtml() (and the
 * title argument of document()), all of which route through Esc internally. There is no code path left
 * for a skin to concatenate raw model text into HTML directly.
 *
 * The primitives live in the RenderHtmlHelpers trait (not inline here) so the deep-panel PanelSection
 * classes can share the exact same escaping helpers without extending this class — a PanelSection has a
 * different render() signature and cannot subclass AbstractSkin. CSS and structural chrome (class names,
 * layout, `<html>`/`<head>`/`<body>` attributes) stay each skin's own responsibility — trusted,
 * skin-authored literals, never derived from PageSlots/model text.
 */
abstract class AbstractSkin implements Skin
{
    use RenderHtmlHelpers;
}

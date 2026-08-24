<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

use Funnypot\RequestContext;
use Funnypot\Support\Chrome\Esc;
use Funnypot\Support\Chrome\GenericSkin;
use Funnypot\Support\Chrome\PageSlots;
use Funnypot\Support\VisualPersona;
use Throwable;

/**
 * Turns model slot-JSON into a full styled page via the path's skin. All page structure, CSS and
 * URLs come from the trusted skin; the model supplies only escaped text. Must never throw — the LLM
 * tier only ever upgrades a 404, so a render fault degrades to a minimal styled page (which the
 * caller still validates with pageBodyOk before serving).
 */
final class PageShellRenderer
{
    public function __construct(private SkinSet $skins)
    {
    }

    /** True when the path routes to a specific product panel skin (not the generic fallback) — the LLM
     *  tier uses this to always serve the coherent panels + their sub-paths. */
    public function matchesProductSkin(string $path): bool
    {
        return $this->skins->hasProductMatch($path);
    }

    /** True for panel views that render a real-time value on every request (the staking rewards feed's
     *  relative "Nh ago" ages) and therefore must NOT be served from — or written to — the byte-identical
     *  panel cache: caching would freeze the live value, which is the exact tell it exists to avoid. The
     *  LLM tier re-renders these per request. Kept here (the panel's render entry) so the generic responder
     *  never hardcodes a panel path. */
    public function isLivePath(string $path): bool
    {
        return (bool) preg_match('#/bank/crypto/staking/rewards(/|$)#', $path);
    }

    public function render(PageSlots $slots, VisualPersona $persona, RequestContext $ctx): string
    {
        try {
            $escapedPath = Esc::text(substr($ctx->path, 0, 200));
            $slots = $slots->resolveMarkers($persona);
            return $this->skins->select($ctx->path)->render($slots, $persona, $escapedPath, $ctx->path);
        } catch (Throwable $e) {
            // Defensive floor: an empty-slot render of the default skin is always safe.
            return (new GenericSkin())->render(PageSlots::fromArray([]), $persona, '', $ctx->path);
        }
    }
}

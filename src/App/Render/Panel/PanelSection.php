<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\Core\Support\VisualPersona;

/**
 * One deep-panel module renderer. The deep admin dashboard dispatches a parsed route to the section
 * registered for its module (see PanelRegistry), so a new module is a new class behind the registry
 * rather than another arm of a growing switch (design ruling R2).
 *
 * A section owns everything below the shared page chrome (breadcrumb + body) for its module and reads
 * its own facts from the seeded Fake\* generators via $persona->seed(). It renders ONLY through the
 * escape-by-construction helpers on AbstractPanelSection, so no model/attacker value reaches HTML raw.
 */
interface PanelSection
{
    /**
     * @param array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} $route
     *        the PanelRoute::parse() output for this request
     * @param VisualPersona $persona seed source for the section's deterministic generators
     * @param string $navBase the mount-rooted panel base (e.g. `/admin`, `/panel`), depth-independent,
     *        so a section builds a link as $navBase . '/<module>/<section>/...' and a download path as
     *        $navBase . '/<module>/.../<file>.zip' that routes back into this same skin/decoy handler
     */
    public function render(array $route, VisualPersona $persona, string $navBase): string;
}

<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

/**
 * One visual "chrome" for the LLM page-realism shell. `matches()` lets a router pick the skin whose
 * look best fits a path (e.g. an admin-panel analog vs a generic app); `render()` turns the model's
 * PageSlots + the host's VisualPersona into a full HTML document.
 */
interface Skin
{
    /** Does this skin apply to the given (already-known-safe) request path? */
    public function matches(string $path): bool;

    /** Stable identifier for logging/selection — not shown to the visitor. */
    public function key(): string;

    /**
     * $escapedPath is pre-escaped by the caller — safe to place directly into a text/attribute sink.
     * $path is the RAW request path (unescaped) — used only to derive safe sibling nav links via
     * AbstractSkin::navBase(); never placed into output directly. Defaults to '' (root-level nav).
     */
    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string;
}

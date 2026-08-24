<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

use Funnypot\Support\Chrome\Skin;

/** Picks the chrome for a path. Real-analog families (wp, phpmyadmin, …) get a resemblance skin;
 *  everything else falls to the generic seed-varied skin. First match wins; order = priority. */
final class SkinSet
{
    /** @param list<Skin> $skins */
    public function __construct(private array $skins, private Skin $default)
    {
    }

    public function select(string $path): Skin
    {
        foreach ($this->skins as $skin) {
            if ($skin->matches($path)) {
                return $skin;
            }
        }
        return $this->default;
    }

    /** True when a specific resemblance skin (not the generic fallback) claims this path — i.e. the path
     *  is one of the coherent product panels the honeypot always wants to serve (so the LLM tier can let
     *  it through the lexical probe shed and serve every sub-path as navigable content). */
    public function hasProductMatch(string $path): bool
    {
        foreach ($this->skins as $skin) {
            if ($skin->matches($path)) {
                return true;
            }
        }
        return false;
    }
}

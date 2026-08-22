<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;
use Funnypot\App\Render\{GenericSkin, VisualPersona, PageSlots};
use PHPUnit\Framework\TestCase;

final class GenericSkinEntropyTest extends TestCase
{
    /**
     * Strip every seed-derived LEAF value (palette hex, fp-XXXX class prefix, tok_/AKIA fakes) from a
     * rendered page, leaving only the class-name VOCABULARY and DOM/CSS STRUCTURE behind. Hashing raw
     * bytes over 24 seeds passes trivially — the palette hex and fp- prefix alone guarantee 24 unique
     * md5s even if the skeleton (selectors, element nesting, declaration order) were byte-identical
     * across the whole fleet. A scanner that normalizes away colors/ids the same way this method does
     * would then still collapse every generic-skin page to ONE skeleton hash: a fleet-wide fingerprint
     * hiding behind seed-varied colors. Normalizing before hashing here measures the residual that
     * actually matters — whether the skeleton itself varies per deployment.
     */
    private static function normalizedSkeleton(string $html): string
    {
        $html = preg_replace('~#[0-9a-f]{6}\b~i', '#HEX', $html);
        $html = preg_replace('~fp-[0-9a-f]+~i', 'fp-ID', $html);
        $html = preg_replace('~tok_[0-9a-f]+~i', 'tok_ID', $html);
        $html = preg_replace('~AKIA[0-9A-Z]+~', 'AKIA_ID', $html);
        return $html;
    }

    public function test_normalized_skeleton_diverges_across_seeds(): void
    {
        $slots = PageSlots::fromArray([
            'app_name' => 'Portal',
            'heading' => 'Users',
            'nav_items' => ['Home', 'Reports'],
        ]);
        $skin = new GenericSkin();
        $skeletons = [];
        for ($seed = 1; $seed <= 24; $seed++) {
            $html = $skin->render($slots, VisualPersona::fromSeed($seed), '/hr/portal');
            $skeletons[] = md5(self::normalizedSkeleton($html));
        }
        // Guards against a value-normalizing scanner: even after stripping every seed-derived leaf
        // (hex colors, fp- prefix, fake token/AWS-key shapes), the class-name vocabulary and DOM/CSS
        // structure must still diverge across deployments, not collapse to one shared skeleton.
        self::assertGreaterThanOrEqual(
            20,
            count(array_unique($skeletons)),
            'normalized skeleton (class vocab + structure, colors/ids stripped) must diverge across seeds'
        );
    }

    /** Raw-bytes uniqueness still holds (palette/prefix alone already guarantee it) — kept as a
     *  cheap regression check, but the normalized assertion above is the load-bearing one. */
    public function test_raw_css_bytes_diverge_across_seeds(): void
    {
        $slots = PageSlots::fromArray(['app_name' => 'Portal', 'heading' => 'Users']);
        $skin = new GenericSkin();
        $styles = [];
        for ($seed = 1; $seed <= 24; $seed++) {
            $html = $skin->render($slots, VisualPersona::fromSeed($seed), '/hr/portal');
            preg_match('~<style>(.*?)</style>~s', $html, $m);
            $styles[] = md5($m[1] ?? '');
        }
        self::assertCount(24, array_unique($styles), 'seed-derived CSS must not collapse to few hashes');
    }
}

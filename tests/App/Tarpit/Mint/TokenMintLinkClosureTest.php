<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use PHPUnit\Framework\TestCase;

/**
 * Every link, form action, redirect and SSO url the account surface renders targets one of its own
 * paths or `/`: never the bare /settings, never anything under /admin/, never off-site. Checked over
 * every page the crawler reaches, for eight personas. A member account's pages carry no admin link.
 */
final class TokenMintLinkClosureTest extends TestCase
{
    /** @return list<string> every link-like target in a plan */
    private static function targets(\Funnypot\App\Tarpit\Mint\MintPlan $p): array
    {
        $out = [];
        preg_match_all('~(?:href|action)=(["\'])(.*?)\1~i', $p->body, $m);
        foreach ($m[2] as $t) {
            $out[] = html_entity_decode($t, ENT_QUOTES);
        }
        foreach (['Location', 'X-SSO'] as $h) {
            $v = $p->header($h);
            if ($v !== null) {
                $out[] = $h === 'X-SSO' ? substr($v, (int) strpos($v, 'url=') + 4) : $v;
            }
        }
        foreach (['sso_url', 'approval_url', 'documentation_url'] as $k) {
            $j = json_decode($p->body, true);
            if (is_array($j) && isset($j[$k]) && is_string($j[$k])) {
                $out[] = $j[$k];
            }
        }

        return $out;
    }

    public function test_every_rendered_target_is_owned_or_the_front_door_for_eight_personas(): void
    {
        for ($seed = 1; $seed <= 8; $seed++) {
            $crawl = new MintCrawl($seed);
            try {
                $out = $crawl->run();
                $checked = 0;
                foreach ([...$crawl->plans, ['home', $out['home']]] as [$label, $plan]) {
                    foreach (self::targets($plan) as $t) {
                        $path = (string) parse_url($t, PHP_URL_PATH);
                        self::assertStringNotContainsString('://', $t, "{$label} links off-site: {$t}");
                        self::assertStringStartsNotWith('//', $t, "{$label} links off-site: {$t}");
                        self::assertStringStartsNotWith('/admin/', $path, "{$label} links an admin path: {$t}");
                        self::assertNotSame('/settings', $path, "{$label} links the bare settings path");
                        self::assertTrue($path === '/' || $crawl->decoy->owns($path), "seed {$seed}: {$label} links {$t}, which the surface does not own");
                        $checked++;
                    }
                }
                self::assertGreaterThan(300, $checked, "seed {$seed}: the crawl reached the pages (checked {$checked} targets)");
                self::assertGreaterThan(120, count($crawl->plans));
                $home = $out['home']->body;
                self::assertStringContainsString('Signed in as artex1', $home);
                self::assertStringNotContainsString('Admin', $home, 'a member never sees an admin entry');
                self::assertStringNotContainsString('/admin/root/', $home, 'none of the sign-in page lures');
            } finally {
                $crawl->cleanup();
            }
        }
    }
}

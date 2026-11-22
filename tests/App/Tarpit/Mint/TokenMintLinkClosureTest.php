<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\MintContext;
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

                // A form token is checked on its own form's action, so every form the pages render must post
                // to one of the actions the check knows, and every such action must be rendered somewhere.
                $actions = [];
                foreach ($crawl->plans as [, $plan]) {
                    preg_match_all("~<form method=post action='([^']+)'~", $plan->body, $m);
                    foreach ($m[1] as $a) {
                        $actions[(string) preg_replace(['~/[a-f0-9]{12}(?=/|$)~', '~/' . preg_quote($crawl->persona->slug, '~') . '(?=/)~'], ['/{id}', '/{org}'], $a)] = true;
                    }
                }
                $known = array_values(MintContext::FORM_ACTIONS);
                sort($known);
                $seen = array_keys($actions);
                sort($seen);
                self::assertSame($known, $seen, "seed {$seed}: rendered form actions match MintContext::FORM_ACTIONS");
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

    /**
     * The surface claims no product: none of these phrases, each a named code host's own API or UI
     * wording, appears in any page, header or message. (Generic HTTP reason phrases stay.)
     */
    private const BORROWED = [
        "won't be able to see it again", 'Make sure to copy', 'Requires authentication', 'Bad credentials',
        'Problems parsing JSON', 'secondary rate limit', 'Validation Failed', '"resource":', 'Incorrect username or password',
        "can't be blank", 'has already been taken', 'Authorization callback URL', 'Register a new application',
        'Generate a new client secret', 'Generate new token', 'wants to access your', 'Confirm access', 'Developer settings',
    ];

    public function test_no_page_or_message_borrows_a_named_products_wording(): void
    {
        $crawl = new MintCrawl(3);
        try {
            $out = $crawl->run();
            $texts = [];
            foreach ([...$crawl->plans, ['home', $out['home']]] as [$label, $plan]) {
                $texts[$label . ' #' . count($texts)] = $plan->body . "\n" . implode("\n", array_map(static fn (array $h): string => $h[0] . ': ' . $h[1], $plan->headers()));
            }
            foreach (array_keys(\Funnypot\App\Tarpit\Mint\MintVocabulary::MESSAGES) as $key) {
                $texts['message ' . $key] = \Funnypot\App\Tarpit\Mint\MintVocabulary::MESSAGES[$key];
            }
            self::assertGreaterThan(150, count($texts));
            foreach ($texts as $label => $text) {
                foreach (self::BORROWED as $phrase) {
                    self::assertStringNotContainsStringIgnoringCase($phrase, html_entity_decode($text, ENT_QUOTES), "{$label} borrows: {$phrase}");
                }
            }
        } finally {
            $crawl->cleanup();
        }
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * Every SSRF answer stays in the closed status and header sets, redirects only to the account's own
 * pages, never navigates by script or meta refresh, and an owned GET carrying a redirect-shaped query
 * gets the decoy's answer rather than core's open-redirect 302.
 */
final class SsrfHeaderClosureTest extends TestCase
{
    public function test_every_answer_is_closed(): void
    {
        $locations = 0;
        foreach ([1, 4, 7] as $seed) {
            $tour = (new SsrfTour($seed))->run();
            try {
                foreach ($tour->plans as [$label, $plan]) {
                    self::assertContains($plan->status, MintPlan::STATUSES, $label);
                    self::assertLessThan(500, $plan->status, $label);
                    self::assertNotSame(302, $plan->status, $label);
                    foreach ($plan->headers() as [$n, $v]) {
                        self::assertContains($n, MintPlan::HEADER_NAMES, "{$label} header {$n}");
                        if ($n === 'Location') {
                            self::assertTrue(MintPlan::allowedLocation($v, $tour->h->persona, SsrfRoutes::LOCATIONS), "{$label} Location {$v}");
                            $locations++;
                        }
                        if ($n === 'Content-Type') {
                            self::assertContains($v, [MintPlan::HTML, MintPlan::JSON], $label);
                        }
                    }
                    self::assertDoesNotMatchRegularExpression('~<meta[^>]+refresh|window\.location|location\.href|<script~i', $plan->body, $label);
                    if (str_starts_with($label, 'GET /api/') || str_starts_with($label, 'GET /v2/')) {
                        self::assertSame(MintPlan::JSON, $plan->header('Content-Type'), $label);
                    }
                }
            } finally {
                $tour->cleanup();
            }
        }
        self::assertGreaterThan(60, $locations);
    }

    public function test_an_owned_get_with_a_redirect_query_is_answered_by_the_decoy(): void
    {
        $evil = 'next=http://evil.example/&url=//evil.example/x&target=https://evil.example';
        $unarmed = new MintHarness(false);
        $armed = new MintHarness(true, ['ssrf' => []]);
        try {
            $armed->join();
            foreach (['/settings/webhooks', '/settings/imports/new', '/api/v2/user/hooks', '/settings/storage'] as $p) {
                $u = $unarmed->get($p, $evil);
                $a = $armed->get($p, $evil);
                self::assertNotNull($a['plan'], "{$p}: the decoy answers");
                self::assertNotSame(302, $a['status']);
                self::assertStringNotContainsString('evil.example', (string) $a['plan']->header('Location'));
                self::assertStringNotContainsString('evil.example', $a['body']);
                self::assertSame($u['main']['templates'], $a['main']['templates'], "{$p}: detection keeps core's verdict");
            }
            self::assertContains('attack-open-redirect', $unarmed->get('/settings/webhooks', $evil)['main']['templates'], 'positive control: unarmed, core answers the open redirect');
        } finally {
            $unarmed->cleanup();
            $armed->cleanup();
        }
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Ssrf\SsrfCorpus;
use PHPUnit\Framework\TestCase;

/**
 * Core stays quiet on what the SSRF surface really receives: every owned route on both API spellings,
 * with real ids for eight key seeds, as a bare GET and as the benign request each form or API call
 * sends, in its real field order (form token first, URL last). A flagged request here would be logged
 * and reported as an attack on a visitor using the surface as intended.
 */
final class SsrfRouteQuietTest extends TestCase
{
    public function test_owned_routes_are_quiet_in_their_real_field_order(): void
    {
        $sent = 0;
        $routes = 0;
        foreach (range(1, 8) as $seed) {
            foreach (SsrfCorpus::routes($seed) as [$route, $method, $path]) {
                $routes++;
                $reqs = [new RequestContext('GET', $path, '', ['User-Agent' => 'Mozilla/5.0'])];
                foreach (SsrfCorpus::urls() as $url) {
                    $b = SsrfCorpus::body($route, $method, $url);
                    if ($b !== null) {
                        $reqs[] = new RequestContext($method, $path, '', $b[1], $b[0]);
                    }
                }
                foreach ($reqs as $r) {
                    $sent++;
                    self::assertFalse(SsrfCorpus::flags($r), "{$r->method} {$path} body " . $r->rawBody . ' flagged ' . json_encode(SsrfCorpus::why($r)));
                }
            }
        }
        self::assertGreaterThanOrEqual($routes, $sent);
        self::assertGreaterThanOrEqual(count(SsrfRoutes::examples()) * 8, $routes, 'every route and method, for every seed');
        self::assertSame([], SsrfRoutes::QUIET_EXEMPT, 'no route is exempt');
    }

    public function test_the_pair_rule_controls(): void
    {
        $url = 'http://10.41.7.19:8080/x/uptime';
        $flagged = new RequestContext('POST', '/settings/webhooks/4b7e19a2c3df', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&payload_url=' . rawurlencode($url));
        self::assertTrue(SsrfCorpus::flags($flagged), 'positive control: an id ending df with a URL ending in a pair word is flagged');
        $clean = new RequestContext('POST', '/settings/webhooks/4b7e19a2c0a1', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&payload_url=' . rawurlencode($url));
        self::assertFalse(SsrfCorpus::flags($clean), 'negative control: the same request on a neutral id is clean');
        $cancel = new RequestContext('POST', '/settings/imports/7h2p9k/cancel', '', SsrfCorpus::F, 'csrf_token=' . SsrfCorpus::CSRF . '&active=1');
        self::assertTrue(SsrfCorpus::flags($cancel), 'positive control: a form ending active=1 on a cancel path is flagged, so no route uses that shape');
    }

    /** A visitor's own URL-first JSON ending in a pair word is flagged today; recorded, not failed. */
    public function test_url_first_json_is_recorded_as_the_visitors_own(): void
    {
        $r = new RequestContext('POST', '/api/v2/user/hooks', '', SsrfCorpus::J, '{"url":"http://10.41.7.19:8080/actuator/env","active":true}');
        self::assertTrue(SsrfCorpus::flags($r), 'recorded: a URL-first body ending /env reads as RCE, at parity with the unarmed answer');
    }
}

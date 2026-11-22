<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * Nothing from a GET query, a path or a header is reflected; POSTed values come back only when they pass
 * their charset, escaped, and only to their owner; a host canary appears only in the owner's escaped
 * stored-URL fields, never in an error string, a derived field or another account's view.
 */
final class SsrfReflectionTest extends TestCase
{
    public function test_get_query_path_and_header_canaries_never_reflect(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $form = $h->get('/settings/webhooks/new');
            $hook = basename((string) $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/'])['plan']?->header('Location'));
            $canaryId = 'cafe0b0b1e57';
            $bytes = 0;
            foreach (SsrfRoutes::examples($canaryId, 'dead00b0b1e5') as [, $path]) {
                foreach ([$path, str_replace($canaryId, $hook, $path)] as $p) {
                    $r = $h->get($p, 'q=QCANARY7x&next=QCANARY8x&url=http://QCANARY9x.example/', 'default', MintHarness::IP, ['X-Forwarded-Host' => 'HCANARY1x', 'Referer' => 'http://HCANARY2x/', 'User-Agent' => 'HCANARY3x']);
                    self::assertNotNull($r['plan'], "{$p}: the decoy answered");
                    $all = $r['body'] . json_encode($r['plan']->headers());
                    foreach (['QCANARY', 'HCANARY'] as $c) {
                        self::assertStringNotContainsStringIgnoringCase($c, $all, "{$p} reflects a GET or header canary");
                    }
                    if (str_contains($p, $canaryId)) {
                        self::assertStringNotContainsString($canaryId, $r['body'], "{$p} reflects its path id");
                    }
                    $bytes += strlen($r['body']);
                }
            }
            foreach (range(1, 8) as $seed) {
                $tour = (new SsrfTour($seed))->run();
                try {
                    foreach ($tour->plans as [, $plan]) {
                        $bytes += strlen($plan->body);
                    }
                } finally {
                    $tour->cleanup();
                }
            }
            self::assertGreaterThan(1 << 20, $bytes, 'more than 1 MB scanned');
        } finally {
            $h->cleanup();
        }
    }

    public function test_post_canaries_are_refused_or_escaped(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $form = $h->get('/settings/webhooks/new');
            $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'secret' => '<script>PCANARY1</script>', 'events' => ['<b>PCANARY2'], 'payload_url' => 'http://x/<svg/onload=1>']);
            self::assertSame(422, $r['status']);
            self::assertStringNotContainsString('PCANARY', $r['body']);
            self::assertStringNotContainsString('<svg', $r['body']);
            $form = $h->get('/settings/webhooks/new');
            $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => "http://172.16.0.5/a'PCANARY3\"x"]);
            self::assertSame(422, $r['status'], 'a quote is not in the URL charset');
            $form = $h->get('/settings/webhooks/new');
            $loc = (string) $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/PCANARY4&x=1'])['plan']?->header('Location');
            $page = $h->get($loc)['body'];
            self::assertStringContainsString('PCANARY4&amp;x=1', $page, 'stored, escaped, shown to its owner');
            self::assertStringNotContainsString("href='http://172.16.0.5", $page, 'never as a link');
        } finally {
            $h->cleanup();
        }
    }

    public function test_host_canary_only_in_owner_stored_fields(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $region = (string) PersonaIdentity::fromSeed(\Funnypot\Tests\App\Identity\IdentityTestSupport::httpIdentity()->personaSeed())->field('cloud.aws.region');
            $canary = 'zzhostcanary7';
            $form = $h->get('/settings/webhooks/new');
            $loc = (string) $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://' . $canary . '.svc.' . $region . '.internal/'])['plan']?->header('Location');
            $show = $h->get($loc);
            preg_match_all("/name=csrf_token value='([^']+)'/", $show['body'], $m);
            $h->post($loc . '/pings', ['csrf_token' => $m[1][0]]);
            $h->now += 3;
            $show = $h->get($loc)['body'];
            preg_match("~/deliveries/([a-f0-9]{12})'~", $show, $dm);
            $delivery = $h->get($loc . '/deliveries/' . $dm[1])['body'];
            self::assertStringContainsString('Could not resolve host', $delivery);
            self::assertStringNotContainsString($canary . '.svc', (string) preg_replace('~<(?:p|span)[^>]*>(?:Sent to|Payload URL): .*?</(?:p|span)>|<span class=mono>[^<]*</span>|Host: [^\n]*\n|POST [^\n]*\n~s', '', $delivery), 'only in the stored URL fields');
            foreach (['Could not resolve host: ' . $canary, $canary . ':'] as $bad) {
                self::assertStringNotContainsString($bad, $delivery, 'never in an error string');
            }
            $h->join('mallory', 'Passw0rd!x', 'm', '198.51.100.9');
            foreach (['/settings/webhooks', $loc, $loc . '/deliveries/' . $dm[1]] as $p) {
                self::assertStringNotContainsString($canary, $h->get($p, '', 'm', '198.51.100.9')['body'], "{$p}: another account never sees it");
            }
        } finally {
            $h->cleanup();
        }
    }
}

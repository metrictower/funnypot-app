<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Mint\MintPlan;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * Per-request work is bounded: engine passes per request kind (a counting engine check through the
 * decoy's own prepare), one redeliver form per page, views issue nothing, at most one key-index slice per
 * request, and a capped form is refused before any work.
 */
final class SsrfWorkBoundTest extends TestCase
{
    private int $passes = 0;

    private function counting(): IssuedValue
    {
        $real = SsrfCorpus::issued();

        return new IssuedValue(function (RequestContext $r) use ($real): bool {
            $this->passes++;

            return $real->flagged($r);
        });
    }

    /** @return array{0:?MintPlan,1:int} */
    private function send(MintHarness $h, string $method, string $path, ?string $body = null, array $headers = []): array
    {
        $cookie = isset($h->jars['default']['session']) ? ['Cookie' => 'session=' . $h->jars['default']['session']] : [];
        if ($body !== null && !isset($headers['Content-Type'])) {
            $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        $this->passes = 0;
        $plan = $h->ssrf->prepare(new RequestContext($method, $path, '', $headers + $cookie + ['User-Agent' => 'Mozilla/5.0'], $body), MintHarness::IP, $this->counting());

        return [$plan, $this->passes];
    }

    public function test_engine_passes_per_request_are_bounded(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $form = $h->get('/settings/webhooks/new');
            [$create, $n] = $this->send($h, 'POST', '/settings/webhooks', http_build_query(['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/']));
            self::assertSame(303, $create?->status);
            self::assertGreaterThanOrEqual(21, $n, 'a hook id on its 10 routes, the catch-all and 10 pair probes');
            self::assertLessThanOrEqual(160 + 8, $n);
            $hook = basename((string) $create->header('Location'));
            [, $n] = $this->send($h, 'GET', '/settings/webhooks/' . $hook);
            self::assertSame(6, $n, 'the hook page: three forms, two passes each');
            $show = $h->get('/settings/webhooks/' . $hook);
            preg_match_all("/name=csrf_token value='([^']+)'/", $show['body'], $m);
            [$ping, $n] = $this->send($h, 'POST', '/settings/webhooks/' . $hook . '/pings', 'csrf_token=' . $m[1][0]);
            self::assertSame(303, $ping?->status);
            self::assertSame(16, $n, 'a delivery id on its 4 routes, its form field, the catch-all and 10 pair probes');
            self::assertLessThanOrEqual(136, $n);
            preg_match("~/deliveries/([a-f0-9]{12})'~", $h->get('/settings/webhooks/' . $hook)['body'], $dm);
            [, $n] = $this->send($h, 'GET', '/settings/webhooks/' . $hook . '/deliveries/' . $dm[1]);
            self::assertSame(2, $n, 'the delivery page: one redeliver form');
            [, $n] = $this->send($h, 'GET', '/settings/storage');
            self::assertSame(2, $n, 'the storage page without a destination: the save form');
            foreach (['/settings/webhooks/new', '/settings/imports/new'] as $p) {
                [, $n] = $this->send($h, 'GET', $p);
                self::assertSame(2, $n, $p);
            }
            [, $n] = $this->send($h, 'GET', '/settings/webhooks');
            self::assertSame(0, $n, 'a list renders no form');
            $imp = $h->get('/settings/imports/new');
            [$import, $n] = $this->send($h, 'POST', '/settings/imports', http_build_query(['csrf_token' => MintHarness::csrf($imp['body']), 'kind' => 'orders_csv', 'source_url' => 'http://172.16.0.5/a.csv']));
            self::assertSame(303, $import?->status);
            self::assertGreaterThanOrEqual(14, $n);
            self::assertLessThanOrEqual(112 + 8, $n);
        } finally {
            $h->cleanup();
        }
    }

    public function test_one_redeliver_form_per_page_and_views_issue_no_id(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $form = $h->get('/settings/webhooks/new');
            $loc = (string) $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.9.9/'])['plan']?->header('Location');
            $show = $h->get($loc);
            preg_match_all("/name=csrf_token value='([^']+)'/", $show['body'], $m);
            $h->post($loc . '/pings', ['csrf_token' => $m[1][0]]);
            $h->now += 4000;
            $h->signIn('artex1', 'Passw0rd!x');
            preg_match("~/deliveries/([a-f0-9]{12})'~", $h->get($loc)['body'], $dm);
            $state = (string) $h->ssrfStore->db()->query('SELECT state FROM ssrf_owner')->fetchColumn();
            [$page, $n] = $this->send($h, 'GET', $loc . '/deliveries/' . $dm[1]);
            self::assertSame(1, substr_count($page->body, '/redeliveries'), 'one redeliver form');
            self::assertSame(5, substr_count($page->body, '<td>timed out</td>'), 'five derived attempts');
            self::assertSame(2, $n, 'the view probed only its one form token');
            self::assertSame($state, (string) $h->ssrfStore->db()->query('SELECT state FROM ssrf_owner')->fetchColumn(), 'the view stored nothing');
        } finally {
            $h->cleanup();
        }
    }

    public function test_index_slices_are_bounded(): void
    {
        $h = new MintHarness(true, ['ssrf' => ['cap' => 8 << 20]]);
        try {
            $h->join();
            $idx = $h->ssrf->index();
            $last = 0;
            for ($i = 0; $i < 12; $i++) {
                $h->get('/settings/webhooks');
                self::assertLessThanOrEqual(1, $idx->slicesRun - $last, 'at most one slice per request');
                $last = $idx->slicesRun;
                self::assertLessThanOrEqual(2048 * ($idx->slicesRun), $idx->sectionsRun);
            }
            self::assertTrue($idx->complete(), 'built within a few requests at the default cap');
        } finally {
            $h->cleanup();
        }
    }

    public function test_capped_form_refused_before_work(): void
    {
        $h = new MintHarness(true, ['ssrf' => ['limits' => ['source_writes_hr' => 0]]]);
        try {
            $h->join();
            $form = $h->get('/settings/webhooks/new');
            [$plan, $n] = $this->send($h, 'POST', '/settings/webhooks', http_build_query(['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/']));
            self::assertSame(429, $plan?->status);
            self::assertSame(0, $n, 'no engine pass, no id issued');
        } finally {
            $h->cleanup();
        }
    }
}

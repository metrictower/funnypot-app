<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\SsrfDecoy;
use Funnypot\App\Tarpit\Ssrf\SsrfState;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/** The SSRF decoy's per-source unit ledger, write caps and the per-account ten-minute action rate. */
final class SsrfBudgetTest extends TestCase
{
    private function units(MintHarness $h): int
    {
        return (int) $h->ssrfStore->db()->query('SELECT COALESCE(SUM(units),0) FROM ssrf_ledger')->fetchColumn();
    }

    public function test_the_ledger_sheds_a_source_at_its_hourly_units(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $shed = null;
            for ($i = 0; $i < SsrfDecoy::UNITS_PER_HOUR + 5; $i++) {
                $r = $h->get('/settings/webhooks');
                if ($r['status'] === 429) {
                    $shed = $i;
                    self::assertSame((string) (3600 - $h->now % 3600), $r['plan']?->header('Retry-After'));
                    break;
                }
            }
            self::assertSame(SsrfDecoy::UNITS_PER_HOUR, $shed, 'one unit per page, shed at the hourly budget');
            self::assertSame(SsrfDecoy::UNITS_PER_HOUR + 1, $this->units($h), 'the first refused request is charged');
            self::assertSame(429, $h->get('/settings/webhooks')['status']);
            self::assertSame(SsrfDecoy::UNITS_PER_HOUR + 1, $this->units($h), 'once over, a request costs nothing more');
            $h->now += 3600;
            self::assertSame(200, $h->get('/settings/webhooks')['status'], 'the next hour starts fresh');
        } finally {
            $h->cleanup();
        }
    }

    public function test_costs_per_request_kind(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $u0 = $this->units($h);
            $form = $h->get('/settings/webhooks/new');
            self::assertSame($u0 + SsrfDecoy::COST_GET, $this->units($h));
            $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/']);
            self::assertSame($u0 + SsrfDecoy::COST_GET + SsrfDecoy::COST_POST, $this->units($h));
            $loc = (string) $r['plan']?->header('Location');
            $show = $h->get($loc);
            preg_match_all("/name=csrf_token value='([^']+)'/", $show['body'], $m);
            $before = $this->units($h);
            $h->post($loc . '/pings', ['csrf_token' => $m[1][0]]);
            self::assertSame($before + SsrfDecoy::COST_SEND, $this->units($h), 'a send costs more than a form');
        } finally {
            $h->cleanup();
        }
    }

    public function test_capped_form_refused_before_work_but_charged(): void
    {
        $h = new MintHarness(true, ['ssrf' => ['limits' => ['source_writes_hr' => 2]]]);
        try {
            $h->join();
            for ($i = 0; $i < 4; $i++) {
                $form = $h->get('/settings/webhooks/new');
                $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.' . ($i + 5) . '/']);
                self::assertSame($i < 2 ? 303 : 429, $r['status'], "create {$i}");
            }
            self::assertCount(2, $h->ssrfStore->load((string) $h->ssrfStore->db()->query('SELECT o FROM ssrf_owner')->fetchColumn())?->d['h']);
            $units = $this->units($h);
            self::assertSame(4 * (SsrfDecoy::COST_GET + SsrfDecoy::COST_POST), $units, 'refused forms are still charged');
            self::assertSame(200, $h->get('/settings/webhooks')['status'], 'reads still answer past the cap');
        } finally {
            $h->cleanup();
        }
    }

    public function test_the_ten_minute_action_rate_per_account(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $form = $h->get('/settings/webhooks/new');
            $loc = (string) $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/'])['plan']?->header('Location');
            $show = $h->get($loc);
            preg_match_all("/name=csrf_token value='([^']+)'/", $show['body'], $m);
            $statuses = [];
            for ($i = 0; $i < SsrfState::RATE_MAX + 2; $i++) {
                $statuses[] = $h->post($loc . '/pings', ['csrf_token' => $m[1][0]])['status'];
            }
            self::assertSame(array_fill(0, SsrfState::RATE_MAX, 303), array_slice($statuses, 0, SsrfState::RATE_MAX));
            self::assertSame([429, 429], array_slice($statuses, SsrfState::RATE_MAX));
            $h->now += SsrfState::RATE_WINDOW_S + 1;
            self::assertSame(303, $h->post($loc . '/pings', ['csrf_token' => MintHarness::csrf($h->get($loc)['body'])])['status']);
        } finally {
            $h->cleanup();
        }
    }

    public function test_the_ten_minute_rate_covers_imports(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $token = MintHarness::csrf($h->get('/settings/imports/new')['body']);
            $statuses = [];
            for ($i = 0; $i < SsrfState::RATE_MAX + 2; $i++) {
                $statuses[] = $h->post('/settings/imports', ['csrf_token' => $token, 'kind' => 'orders_csv', 'source_url' => 'http://172.16.0.5/o' . $i . '.csv'])['status'];
            }
            self::assertSame(array_fill(0, SsrfState::RATE_MAX, 303), array_slice($statuses, 0, SsrfState::RATE_MAX));
            self::assertSame([429, 429], array_slice($statuses, SsrfState::RATE_MAX), 'an import is a send like a ping');
            $h->now += SsrfState::RATE_WINDOW_S + 1;
            self::assertSame(303, $h->post('/settings/imports', ['csrf_token' => MintHarness::csrf($h->get('/settings/imports/new')['body']), 'kind' => 'orders_csv', 'source_url' => 'http://172.16.0.5/late.csv'])['status']);
        } finally {
            $h->cleanup();
        }
    }

    public function test_units_are_charged_in_the_state_transaction(): void
    {
        $faults = new class () {
            public bool $armed = false;

            public function stage(string $s): void
            {
                if ($this->armed && $s === 'commit') {
                    throw new \PDOException('disk I/O error');
                }
            }
        };
        $h = new MintHarness(true, ['ssrf' => ['faults' => $faults]]);
        try {
            $h->join();
            $form = $h->get('/settings/webhooks/new');
            $units = $this->units($h);
            $faults->armed = true;
            $r = $h->post('/settings/webhooks', ['csrf_token' => MintHarness::csrf($form['body']), 'payload_url' => 'http://172.16.0.5/']);
            $faults->armed = false;
            self::assertSame(422, $r['status'], 'a coherent failure page');
            self::assertSame($units, $this->units($h), 'units unchanged');
            self::assertSame(0, (int) $h->ssrfStore->db()->query('SELECT COUNT(*) FROM ssrf_owner')->fetchColumn(), 'state unchanged');
        } finally {
            $h->cleanup();
        }
    }
}

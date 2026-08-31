<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Storage\AnalyticsStore;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0243b — the operator-only analytics endpoint (?admin=analytics) and its ts-range drill-down
 * filter. Covers the plan's V9-V11:
 *   V9  the endpoint is behind the SAME admin auth as every other action (no/wrong token → 403,
 *       right token → 200 with the four keys) — analytics must not leak to an unauthenticated caller.
 *   V10 with seeded rollups the JSON carries non-empty breakdown/series for a known protocol and a
 *       topN list; a forced store fault degrades to empty widgets + 200, never a 500 tell.
 *   V11 SqliteHitStore::where() with ts_from/ts_to returns only in-range rows and is not injectable.
 * (V12, node --check of analytics.js + the vendored uplot.min.js, runs in the shell, not here.)
 */
final class DashboardAnalyticsTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    private const PASS = 'operator-secret-pw';

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
        }
        $this->tmp = [];
        putenv('FUNNYPOT_ADMIN_PASSWORD');
        unset($_GET, $_POST, $_SERVER['HTTP_X_ADMIN_TOKEN']);
        $_GET = [];
        $_POST = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_dash_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function config(): AppConfig
    {
        putenv('FUNNYPOT_ADMIN_PASSWORD=' . self::PASS);

        return AppConfig::fromEnv(sys_get_temp_dir());
    }

    private function geo(): \Geo
    {
        return new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
    }

    private function controller(SqliteHitStore $store, ?AnalyticsStore $analytics = null): DashboardController
    {
        return new DashboardController(
            $store,
            $this->geo(),
            $this->config(),
            sys_get_temp_dir(),
            null,
            null,
            $analytics ?? $store,
        );
    }

    /** @param array<string,mixed> $over */
    private function hit(string $ts, array $over = []): array
    {
        return $over + [
            'ts' => $ts,
            'ip' => '1.1.1.1',
            'method' => 'HTTP',
            'event' => 'connect',
            'severity' => 'low',
            'matched' => false,
            'served' => false,
        ];
    }

    /**
     * Run admin($action) and return the decoded JSON body. We assert on the body, not
     * http_response_code(): under the phpunit CLI SAPI, stdout counts as "headers already sent", so
     * the controller's http_response_code(403) is a no-op there and the code cannot be read back.
     * The body is unambiguous — the forbidden branch emits {"error":...} with NO analytics payload,
     * the success branch emits {"ok":true,...} — so it proves whether the auth gate held.
     *
     * @return array<string,mixed>|null
     */
    private function call(DashboardController $c, string $action): ?array
    {
        ob_start();
        @$c->admin($action);
        $body = (string) ob_get_clean();

        return json_decode($body, true);
    }

    // --- V9: the auth gate ---

    public function test_v9_analytics_is_forbidden_without_a_token(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        unset($_SERVER['HTTP_X_ADMIN_TOKEN']);

        $json = $this->call($this->controller($store), 'analytics');

        // Forbidden branch: an error payload and NOT a shred of analytics data.
        self::assertArrayHasKey('error', (array) $json, 'no token must hit the forbidden branch');
        self::assertArrayNotHasKey('breakdown', (array) $json, 'no analytics payload may leak unauthenticated');
        self::assertArrayNotHasKey('topN', (array) $json);
        self::assertNotSame(true, $json['ok'] ?? null);
    }

    public function test_v9_analytics_is_forbidden_with_a_wrong_token(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $_SERVER['HTTP_X_ADMIN_TOKEN'] = 'not-the-password';

        $json = $this->call($this->controller($store), 'analytics');

        self::assertSame('forbidden', $json['error'] ?? null, 'a wrong token must be forbidden');
        self::assertArrayNotHasKey('breakdown', (array) $json, 'no analytics payload may leak on a wrong token');
    }

    public function test_v9_analytics_returns_the_four_keys_with_the_right_token(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $_SERVER['HTTP_X_ADMIN_TOKEN'] = self::PASS;

        $json = $this->call($this->controller($store), 'analytics');

        self::assertTrue($json['ok'] ?? false, 'the right token passes the gate');
        self::assertArrayNotHasKey('error', (array) $json);
        foreach (['breakdown', 'series', 'topN', 'ataglance'] as $k) {
            self::assertArrayHasKey($k, $json, "the analytics payload must expose '$k'");
        }
    }

    // --- V10: endpoint shape + the no-500 tell-avoidance ---

    public function test_v10_seeded_rollups_yield_a_nonempty_breakdown_series_and_topn(): void
    {
        $path = $this->dbPath();
        $store = new SqliteHitStore($path);
        $ts = gmdate('c', time() - 300); // recent bucket, never pruned

        for ($i = 0; $i < 5; $i++) {
            $store->append($this->hit($ts, ['method' => 'SIP', 'event' => 'call', 'ip' => '9.9.9.' . $i, 'tool' => 'sipvicious']));
        }
        for ($i = 0; $i < 3; $i++) {
            $store->append($this->hit($ts, ['method' => 'HTTP', 'event' => 'scan', 'ip' => '8.8.8.' . $i, 'tool' => 'nuclei', 'matched' => true]));
        }
        self::assertSame(8, $store->foldRollups(1000));

        $_SERVER['HTTP_X_ADMIN_TOKEN'] = self::PASS;
        // minute granularity + a window covering the seed so the fresh buckets are in range.
        $_GET = ['win' => '3600', 'gran' => 'm'];
        $json = $this->call($this->controller($store), 'analytics');

        self::assertTrue($json['ok'] ?? false);

        // A known protocol shows up in the breakdown with the right count.
        $protoByVal = [];
        foreach ($json['breakdown']['protocol'] as $r) {
            $protoByVal[$r['val']] = $r['n'];
        }
        self::assertSame(5, $protoByVal['SIP'] ?? null, 'breakdown must count the 5 SIP hits');
        self::assertSame(3, $protoByVal['HTTP'] ?? null);

        // The events-over-time series has a line for the busiest protocol.
        self::assertNotEmpty($json['series'], 'series must be non-empty with seeded rollups');
        self::assertArrayHasKey('SIP', $json['series']);
        self::assertSame(5, array_sum(array_column($json['series']['SIP'], 'n')));

        // topN (raw GROUP BY) returns a list; the busiest source IP is one of the SIP hosts.
        self::assertNotEmpty($json['topN']['ip']);
        self::assertContains('9.9.9.0', array_column($json['topN']['ip'], 'val'));
    }

    public function test_v10_a_store_fault_degrades_to_empty_widgets_and_200_never_500(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $_SERVER['HTTP_X_ADMIN_TOKEN'] = self::PASS;

        // A throwing analytics store simulates a query fault on every method.
        $c = $this->controller($store, new ThrowingAnalyticsStore());
        $json = $this->call($c, 'analytics');

        // A well-formed 200 payload (ok:true) with empty widgets — the fault was swallowed, not a 500.
        self::assertTrue($json['ok'] ?? false, 'a query fault must degrade, never become a 500 tell');
        self::assertSame([], $json['breakdown']['protocol'], 'a faulting dim degrades to an empty widget');
        self::assertSame([], $json['series']);
        self::assertSame([], $json['topN']['ip']);
        self::assertSame(0, $json['ataglance']['events'], 'ataglance degrades to zeros, not an error');
    }

    // --- V11: the ts-range drill-down filter (where()) ---

    public function test_v11_ts_range_filter_returns_only_in_range_rows(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $t0 = time() - 4000;
        $before = gmdate('c', $t0);            // out of range (older)
        $inA = gmdate('c', $t0 + 1000);
        $inB = gmdate('c', $t0 + 2000);
        $after = gmdate('c', $t0 + 3000);      // out of range (newer)

        $store->append($this->hit($before, ['ip' => '10.0.0.1']));
        $store->append($this->hit($inA, ['ip' => '10.0.0.2']));
        $store->append($this->hit($inB, ['ip' => '10.0.0.3']));
        $store->append($this->hit($after, ['ip' => '10.0.0.4']));

        $rows = $store->older(0, [
            'ts_from' => gmdate('c', $t0 + 500),
            'ts_to' => gmdate('c', $t0 + 2500),
        ])['rows'];

        $ips = array_column($rows, 'ip');
        sort($ips);
        self::assertSame(['10.0.0.2', '10.0.0.3'], $ips, 'only the two in-window rows are returned');
    }

    public function test_v11_ts_range_filter_is_bound_not_injectable(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $ts = gmdate('c', time() - 100);
        $store->append($this->hit($ts, ['ip' => '10.0.0.9']));

        // A SQL-injection payload bound as a LITERAL: the string '9999...' OR ... sorts lexically
        // AFTER the row's 2026 ts, so `ts >= :ts_from` excludes it → []. If the payload were
        // interpolated, the `OR '1'='1'` would make the predicate always-true and return the row —
        // so [] proves the value is bound, not concatenated. And DROP TABLE in ts_to must be inert.
        $rows = $store->older(0, [
            'ts_from' => "9999-01-01' OR '1'='1",
            'ts_to' => "2999-01-01'; DROP TABLE hits;--",
        ])['rows'];

        self::assertSame([], $rows, 'a bound injection payload cannot flip the predicate true');
        // The table still exists and the row survives → no injection (no DROP) executed.
        self::assertCount(1, $store->older(0, [])['rows'], 'the DROP TABLE payload was inert');
    }
}

/** An AnalyticsStore whose every method throws — used to prove the endpoint never 500s on a fault. */
final class ThrowingAnalyticsStore implements AnalyticsStore
{
    public function foldRollups(int $batch): int
    {
        throw new \RuntimeException('boom');
    }

    public function breakdown(string $dim, int $sinceEpoch, string $gran = 'h'): array
    {
        throw new \RuntimeException('boom');
    }

    public function series(string $dim, array $vals, int $sinceEpoch, string $gran = 'm'): array
    {
        throw new \RuntimeException('boom');
    }

    public function topN(string $dim, int $limit, int $sinceEpoch): array
    {
        throw new \RuntimeException('boom');
    }

    public function ataglance(int $windowS): array
    {
        throw new \RuntimeException('boom');
    }
}

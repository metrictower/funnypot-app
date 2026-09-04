<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\Confidence;
use Funnypot\App\Engagement\EngagementAnalytics;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EpisodeKey;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\IdentityBasis;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\NoopEngagementStore;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Storage\SqliteEngagementStore;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * The engagement section of ?admin=analytics: behind the same session gate, reports off / no-key /
 * fault as a shape (never a 500), and with a real store exposes basis × confidence aggregates and
 * labelled estimates — never an "actor", never a raw hit.
 */
final class DashboardEngagementTest extends TestCase
{
    private const PASS = 'operator-secret-pw';

    /** @var string[] */
    private array $tmp = [];

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
        unset($_GET, $_POST, $_COOKIE[AdminAuth::COOKIE]);
        $_GET = [];
        $_POST = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_dasheng_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function authedAuth(): AdminAuth
    {
        $auth = new AdminAuth($this->dbPath());
        $auth->createOrResetUser('admin', self::PASS);
        $res = $auth->login('admin', self::PASS, '203.0.113.1');
        self::assertTrue($res['ok'] ?? false);

        return $auth;
    }

    private function controller(?EngagementAnalytics $engagement, ?AdminAuth $auth): DashboardController
    {
        putenv('FUNNYPOT_ADMIN_PASSWORD=' . self::PASS);
        $store = new SqliteHitStore($this->dbPath());

        return new DashboardController(
            $store,
            new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()),
            AppConfig::fromEnv(sys_get_temp_dir()),
            sys_get_temp_dir(),
            null,
            null,
            $store,
            $auth,
            null,
            $engagement,
        );
    }

    /** @return array<string,mixed>|null */
    private function call(DashboardController $c): ?array
    {
        ob_start();
        @$c->admin('analytics');

        return json_decode((string) ob_get_clean(), true);
    }

    public function test_unauthenticated_sees_no_engagement_payload(): void
    {
        unset($_COOKIE[AdminAuth::COOKIE]);
        $auth = new AdminAuth($this->dbPath());
        $auth->createOrResetUser('admin', self::PASS);
        $json = $this->call($this->controller(new NoopEngagementStore(), $auth));

        self::assertArrayHasKey('error', (array) $json);
        self::assertArrayNotHasKey('engagement', (array) $json);
    }

    public function test_null_wiring_reports_off_and_no_key_reports_why(): void
    {
        $json = $this->call($this->controller(null, $this->authedAuth()));
        self::assertTrue($json['ok'] ?? false);
        self::assertSame(['enabled' => false, 'reason' => 'off'], $json['engagement']);
        self::assertSame([], $json['engagement_recent']);

        $json = $this->call($this->controller(new NoopEngagementStore(NoopEngagementStore::REASON_NO_KEY), $this->authedAuth()));
        self::assertSame(['enabled' => false, 'reason' => 'key-unavailable'], $json['engagement']);
    }

    public function test_a_read_fault_degrades_to_the_off_shape_and_a_200(): void
    {
        $throwing = new class implements EngagementAnalytics {
            public function summary(int $sinceEpoch): array
            {
                throw new \RuntimeException('boom');
            }

            public function recent(int $sinceEpoch, int $limit): array
            {
                throw new \RuntimeException('boom');
            }

            public function health(): array
            {
                throw new \RuntimeException('boom');
            }
        };
        $json = $this->call($this->controller($throwing, $this->authedAuth()));

        self::assertTrue($json['ok'] ?? false, 'a fault is swallowed, never a 500 tell');
        self::assertSame(['enabled' => false, 'reason' => 'off'], $json['engagement']);
        self::assertSame([], $json['engagement_recent']);
        self::assertArrayHasKey('breakdown', $json, 'the rest of the analytics payload is unaffected');
    }

    public function test_a_seeded_store_yields_basis_confidence_aggregates_and_no_attribution_language(): void
    {
        $key = AnalyticsKey::fromRaw(str_repeat('k', 32));
        $now = time();
        $store = new SqliteEngagementStore($this->dbPath(), new EngagementCaps(), [$key, 'id'], static fn (): int => $now);
        $k = new EpisodeKey(IdentityBasis::NETWORK_FALLBACK, Confidence::LOW, $key->id('episode-evidence', 'x'));
        $store->resolveAndRecord($k, new EngagementEvent(Stage::DISCOVER, EventKind::LURE_FOLLOWED, 4000, 9, LureId::LABYRINTH, null, true, 0, 0));
        $store->resolveAndRecord($k, new EngagementEvent(Stage::COLLECT, EventKind::LURE_FOLLOWED, 8000, 11, LureId::POLLUTER_CONFIG, null, false));

        $_GET = ['win' => '3600'];
        $json = $this->call($this->controller($store, $this->authedAuth()));
        $e = $json['engagement'];

        self::assertTrue($e['enabled']);
        self::assertSame(1, $e['episodes']);
        self::assertSame(2, $e['events']);
        self::assertSame(1, $e['deepest_stage'][Stage::COLLECT]);
        self::assertSame(1, $e['lures'][LureId::LABYRINTH]);
        self::assertNull($e['llm']['calls'], 'a mixed-availability episode keeps LLM usage unknown');
        self::assertSame(3000, $e['estimated']['context_tokens']);
        $basisMix = array_column($e['identity'], 'episodes', 'basis');
        self::assertSame(1, $basisMix[IdentityBasis::NETWORK_FALLBACK]);
        self::assertSame(1, count($json['engagement_recent']));
        self::assertSame(Confidence::LOW, $json['engagement_recent'][0]['confidence']);

        $raw = json_encode($json['engagement']) . json_encode($json['engagement_recent']);
        self::assertDoesNotMatchRegularExpression('/"(actor|person|user_id|attacker_id)"/', $raw, 'never an attribution label');
        self::assertStringNotContainsString('evidence_digest', $raw);
        self::assertStringNotContainsString('"episode_id"', $raw);
    }

    public function test_shell_renders_the_engagement_section_with_its_caveats(): void
    {
        $auth = $this->authedAuth();
        $c = $this->controller(null, $auth);
        ob_start();
        @$c->shell('/');
        $html = (string) ob_get_clean();

        self::assertStringContainsString('id=aeng', $html);
        self::assertStringContainsString('identity basis', $html);
        self::assertStringContainsString('NAT', $html, 'the shared-proxy limitation is stated in the dashboard');
        self::assertStringContainsString('(est.)', $html);
        self::assertDoesNotMatchRegularExpression('/\bactor\b/i', substr($html, strpos($html, 'id=aeng')), 'no attribution wording in the section');
    }
}

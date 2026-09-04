<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EpisodeKey;
use Funnypot\App\Engagement\EpisodeResolver;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\SignedHandle;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Http\PolluterController;
use Funnypot\App\Storage\SqliteEngagementStore;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\Core\RequestContext;
use Geo;
use PDO;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * The two producers with the recorder off / on / faulting must emit byte-identical responses (status,
 * headers, body) — the store is an observer. With it on, one typed event per hit lands with the
 * code-owned lure id and the mapped stage, and the engagement rows carry no path or peer address.
 */
final class ProducerWiringTest extends TestCase
{
    private const SEED = 4242;

    /** @var string[] */
    private array $tmp = [];

    private ?StreamEmitter $lastStream = null;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
        $this->lastStream = null;
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_engw_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function budget(): TarpitBudget
    {
        return new TarpitBudget($this->path('budget'), true, 4, 4, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15);
    }

    /** @return array{0:EngagementRecorder,1:SqliteEngagementStore,2:string} */
    private function recorder(): array
    {
        $key = AnalyticsKey::fromRaw(str_repeat('k', 32));
        $p = $this->path('eng');
        $store = new SqliteEngagementStore($p, new EngagementCaps(), [$key, 'id'], static fn (): int => 1_700_000_000);

        return [new EngagementRecorder($store, new EpisodeResolver($key, new SignedHandle($key)), static fn (): int => 1_700_000_000), $store, $p];
    }

    private function faultingRecorder(): EngagementRecorder
    {
        $key = AnalyticsKey::fromRaw(str_repeat('k', 32));
        $store = new class implements EngagementStore {
            public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string
            {
                throw new \RuntimeException('metrics store on fire');
            }
        };

        return new EngagementRecorder($store, new EpisodeResolver($key, new SignedHandle($key)));
    }

    /** @return array{status:int,headers:array<string,string>,body:string} */
    private function labyrinth(?EngagementRecorder $rec, string $path): array
    {
        $cap = ['status' => 0, 'headers' => [], 'body' => ''];
        $emit = static function (int $s, array $h, string $b) use (&$cap): void {
            $cap = ['status' => $s, 'headers' => $h, 'body' => $b];
        };
        $lab = new LabyrinthController(new SqliteHitStore($this->path('hits')), new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()), $this->budget(), self::SEED, 8, null, $emit, null, 0, '', $rec);
        $lab->handle(new RequestContext('GET', $path, '', ['User-Agent' => 'curl/8.0']), '203.0.113.9');

        return $cap;
    }

    /** @return array{status:int,headers:array<string,string>,body:string} */
    private function polluter(?EngagementRecorder $rec, string $path): array
    {
        $factory = function (): StreamEmitter {
            return $this->lastStream = new StreamEmitter(static function (string $b): void {
            }, 0);
        };
        $pol = new PolluterController(new SqliteHitStore($this->path('hits')), new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()), $this->budget(), self::SEED, 1, null, $factory, null, $rec);
        $pol->handle(new RequestContext('GET', $path, '', ['User-Agent' => 'curl/8.0']), '203.0.113.9');

        return ['status' => $this->lastStream->status(), 'headers' => $this->lastStream->headers(), 'body' => $this->lastStream->captured()];
    }

    public function test_labyrinth_response_is_identical_with_metrics_off_on_and_faulting(): void
    {
        [$rec] = $this->recorder();
        $off = $this->labyrinth(null, '/admin/audit-archive/page-000003');
        $on = $this->labyrinth($rec, '/admin/audit-archive/page-000003');
        $fault = $this->labyrinth($this->faultingRecorder(), '/admin/audit-archive/page-000003');

        self::assertSame(200, $off['status']);
        self::assertSame($off, $on, 'the observer changes nothing about the response');
        self::assertSame($off, $fault, 'a faulting observer changes nothing either — and never 500s');
    }

    public function test_polluter_response_is_identical_with_metrics_off_on_and_faulting(): void
    {
        [$rec] = $this->recorder();
        $off = $this->polluter(null, PolluterController::HOSTILE_PATH);
        $on = $this->polluter($rec, PolluterController::HOSTILE_PATH);
        $fault = $this->polluter($this->faultingRecorder(), PolluterController::HOSTILE_PATH);

        self::assertSame(200, $off['status']);
        self::assertSame($off, $on);
        self::assertSame($off, $fault);
    }

    public function test_labyrinth_emits_one_typed_event_with_depth_mapped_to_stage(): void
    {
        [$rec, $store, $p] = $this->recorder();
        $this->labyrinth($rec, '/admin/audit-archive/page-000001');
        $this->labyrinth($rec, '/admin/audit-archive/page-000005');
        $this->labyrinth($rec, '/admin/audit-archive/shard-AB12CD34/page-000001');

        $rows = (new PDO('sqlite:' . $p))->query('SELECT lure_id, stage, event_kind, bytes_out, server_llm_usage_available, server_llm_calls FROM engagement_events ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        self::assertCount(3, $rows);
        self::assertSame([LureId::LABYRINTH, Stage::DISCOVER], [$rows[0]['lure_id'], $rows[0]['stage']], 'bare entry (page 1) is DISCOVER');
        self::assertSame(Stage::ENUMERATE, $rows[1]['stage'], 'a deeper page is ENUMERATE');
        self::assertSame(Stage::ENUMERATE, $rows[2]['stage'], 'a shard is ENUMERATE');
        self::assertSame('lure_followed', $rows[0]['event_kind']);
        self::assertGreaterThan(1000, (int) $rows[0]['bytes_out']);
        self::assertSame('1', (string) $rows[0]['server_llm_usage_available'], 'no LLM call was made: an observed zero, not unknown');
        self::assertSame('0', (string) $rows[0]['server_llm_calls']);

        $sum = $store->summary(0);
        self::assertSame(1, $sum['episodes'], 'same peer + UA class within the gap ⇒ one episode');
        self::assertSame(1, $sum['deepest_stage'][Stage::ENUMERATE]);
    }

    public function test_polluter_emits_collect_events_with_the_code_owned_lure_id(): void
    {
        [$rec, , $p] = $this->recorder();
        foreach ([PolluterController::CONFIG_PATH, PolluterController::LOG_PATH, PolluterController::HOSTILE_PATH, PolluterController::SHADOW_PATH] as $path) {
            $this->polluter($rec, $path . '?x=1');
        }
        $rows = (new PDO('sqlite:' . $p))->query('SELECT lure_id, stage FROM engagement_events ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        self::assertSame(
            [LureId::POLLUTER_CONFIG, LureId::POLLUTER_LOG, LureId::POLLUTER_HOSTILE, LureId::POLLUTER_SHADOW],
            array_column($rows, 'lure_id')
        );
        self::assertSame([Stage::COLLECT, Stage::COLLECT, Stage::COLLECT, Stage::COLLECT], array_column($rows, 'stage'));
    }

    public function test_engagement_rows_carry_no_path_or_peer_address(): void
    {
        [$rec, , $p] = $this->recorder();
        $this->labyrinth($rec, '/admin/audit-archive/page-000002');
        $this->polluter($rec, PolluterController::LOG_PATH);

        $db = new PDO('sqlite:' . $p);
        $dump = json_encode($db->query('SELECT * FROM engagement_events')->fetchAll(PDO::FETCH_ASSOC))
            . json_encode($db->query('SELECT * FROM engagement_episodes')->fetchAll(PDO::FETCH_ASSOC));
        self::assertStringNotContainsString('203.0.113.9', $dump);
        self::assertStringNotContainsString('audit-archive', $dump);
        self::assertStringNotContainsString('/admin', $dump);
        self::assertStringNotContainsString('curl', $dump);
    }
}

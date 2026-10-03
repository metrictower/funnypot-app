<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EpisodeKey;
use Funnypot\App\Engagement\EpisodeResolver;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\SignedHandle;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Http\AttritionController;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Storage\SqliteAttritionStore;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\Attrition\AttritionArtifactRenderer;
use Funnypot\App\Tarpit\Attrition\AttritionEntryIssuer;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;
use RuntimeException;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0272 §8 — structured observation without response authority: the exact event/stage/lure/artifact
 * mapping, coarse install-local ids only, first-fetch vs reuse, null LLM usage, and that a null/throwing
 * recorder never changes the served bytes and an invalid request records nothing.
 */
final class AttritionEngagementTest extends TestCase
{
    private const NOW = 1757000000;
    private const KEY = 'attrition-engagement-test-key-000';
    private const PEER = '203.0.113.13';
    private const ROUTE = '/admin/audit-archive/page-000002';

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
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_attre_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function codec(): AttritionTokenCodec
    {
        return new AttritionTokenCodec(substr(hash('sha256', self::KEY, true), 0, 32));
    }

    private function captureStore(): EngagementStore
    {
        return new class implements EngagementStore {
            /** @var EngagementEvent[] */
            public array $events = [];
            public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string
            {
                $this->events[] = $event;

                return EngagementStore::RECORDED;
            }
        };
    }

    private function recorder(EngagementStore $store): EngagementRecorder
    {
        $key = AnalyticsKey::fromRaw(substr(hash('sha256', 'analytics-' . self::KEY, true), 0, 32));

        return new EngagementRecorder($store, new EpisodeResolver($key, new SignedHandle($key)), static fn (): int => self::NOW);
    }

    /** @return array{0:AttritionController,1:object} controller wired to a capturing recorder */
    private function controller(?EngagementRecorder $recorder): array
    {
        $cap = new class {
            public int $status = 0;
            /** @var array<string,string> */
            public array $headers = [];
            public string $body = '';
        };
        $emit = static function (int $s, array $h, string $b) use ($cap): void {
            $cap->status = $s;
            $cap->headers = $h;
            $cap->body = $b;
        };
        $budget = new TarpitBudget($this->path('budget'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15, static fn (): int => self::NOW);
        $store = new SqliteAttritionStore($this->path('attr'), new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => self::NOW);
        $controller = new AttritionController($store, $this->codec(), new AttritionArtifactRenderer(), $budget, 4242, $emit, $recorder, static fn (): int => self::NOW);

        return [$controller, $cap];
    }

    private function req(AttritionController $c, object $cap, string $method, string $path): string
    {
        $c->handle(new RequestContext($method, $path), self::PEER);

        return $cap->body;
    }

    public function test_full_journey_event_mapping(): void
    {
        $store = $this->captureStore();
        [$c, $cap] = $this->controller($this->recorder($store));
        $entry = $this->codec()->issueEntry(self::ROUTE, self::PEER, self::NOW, 21600);

        $jobToken = json_decode(rtrim($this->req($c, $cap, 'POST', AttritionController::JOBS_PREFIX . $entry), "\n"), true)['id'];
        for ($i = 0; $i < 9; $i++) {
            $ready = json_decode(rtrim($this->req($c, $cap, 'GET', AttritionController::JOBS_PREFIX . $jobToken), "\n"), true);
        }
        $manifestUrl = $ready['manifest_url'];
        $m = $this->req($c, $cap, 'GET', $manifestUrl);
        // repeat manifest fetch — must record NO new event
        $eventsBeforeRepeat = count($store->events);
        $this->req($c, $cap, 'GET', $manifestUrl);
        self::assertCount($eventsBeforeRepeat, $store->events, 'a repeat manifest fetch issues no event');

        preg_match('~^# artifact: (/admin/export/artifacts/\S+)$~m', $m, $am);
        $this->req($c, $cap, 'GET', $am[1]); // first fetch
        $this->req($c, $cap, 'GET', $am[1]); // reuse

        $kinds = array_map(static fn (EngagementEvent $e): string => $e->eventKind, $store->events);
        self::assertSame([
            EventKind::LURE_FOLLOWED,        // create
            EventKind::JOB_POLLED,           // poll 1
            EventKind::JOB_POLLED,           // poll 2
            EventKind::JOB_POLLED,           // poll 3
            EventKind::JOB_POLLED,           // poll 4
            EventKind::JOB_POLLED,           // poll 5
            EventKind::JOB_POLLED,           // poll 6
            EventKind::JOB_POLLED,           // poll 7
            EventKind::JOB_POLLED,           // poll 8
            EventKind::JOB_POLLED,           // poll 9
            EventKind::ARTIFACT_ISSUED,      // manifest gen0 (committed)
            EventKind::ARTIFACT_FETCHED,     // artifact first fetch
            EventKind::ARTIFACT_REUSED,      // artifact reuse
        ], $kinds);

        // Stage mapping: create+polls 1-7 collect, polls 8-9 verify, manifest/artifact verify.
        $stages = array_map(static fn (EngagementEvent $e): string => $e->stage, $store->events);
        self::assertSame([
            Stage::COLLECT, Stage::COLLECT, Stage::COLLECT, Stage::COLLECT, Stage::COLLECT, Stage::COLLECT,
            Stage::COLLECT, Stage::COLLECT, Stage::VERIFY, Stage::VERIFY, Stage::VERIFY, Stage::VERIFY, Stage::VERIFY,
        ], $stages);

        foreach ($store->events as $e) {
            self::assertSame(LureId::ATTRITION_EXPORT, $e->lureId);
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) $e->artifactId, 'only a coarse install-local id');
            self::assertFalse($e->serverLlmUsageAvailable, 'this renderer makes no LLM call');
            self::assertNull($e->serverLlmCalls);
            self::assertNull($e->serverLlmTokens);
            self::assertSame(0, $e->attackerToolTurns, 'never infer a tool turn from an HTTP request');
            self::assertSame(1, $e->attackerRequestUnits);
            self::assertGreaterThan(0, $e->bytesOut);
        }
    }

    public function test_issuer_records_lure_issued_only_for_an_eligible_page(): void
    {
        $store = $this->captureStore();
        $issuer = new AttritionEntryIssuer($this->codec(), 21600, static fn (): int => self::NOW, $this->recorder($store));
        $hitStore = new SqliteHitStore($this->path('hits'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $budget = new TarpitBudget($this->path('budget'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15, static fn (): int => self::NOW);
        $lab = new LabyrinthController($hitStore, $geo, $budget, 4242, 8, null, static function (): void {
        }, null, 0, '', null, $issuer);

        $lab->handle(new RequestContext('GET', self::ROUTE), self::PEER);
        self::assertCount(1, $store->events);
        self::assertSame(EventKind::LURE_ISSUED, $store->events[0]->eventKind);
        self::assertSame(Stage::ENUMERATE, $store->events[0]->stage);
        self::assertSame(LureId::ATTRITION_EXPORT, $store->events[0]->lureId);

        // A non-eligible page (page 1) records nothing.
        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000001'), self::PEER);
        self::assertCount(1, $store->events, 'a non-eligible page records no issuance');
    }

    public function test_invalid_request_records_nothing(): void
    {
        $store = $this->captureStore();
        [$c, $cap] = $this->controller($this->recorder($store));
        $this->req($c, $cap, 'POST', AttritionController::JOBS_PREFIX . 'garbage');
        $this->req($c, $cap, 'GET', AttritionController::MANIFESTS_PREFIX . str_repeat('A', 117));
        self::assertSame(404, $cap->status);
        self::assertCount(0, $store->events, 'no invalid input produces an engagement event');
    }

    public function test_a_throwing_recorder_never_changes_the_served_bytes(): void
    {
        $entry = $this->codec()->issueEntry(self::ROUTE, self::PEER, self::NOW, 21600);

        // Baseline: no recorder.
        [$plain, $plainCap] = $this->controller(null);
        $plainBody = $this->req($plain, $plainCap, 'POST', AttritionController::JOBS_PREFIX . $entry);

        // A recorder whose store throws — the recorder absorbs it, the response is unaffected.
        $throwing = new class implements EngagementStore {
            public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string
            {
                throw new RuntimeException('store down');
            }
        };
        [$c, $cap] = $this->controller($this->recorder($throwing));
        $body = $this->req($c, $cap, 'POST', AttritionController::JOBS_PREFIX . $entry);

        self::assertSame(202, $cap->status);
        self::assertSame($plainBody, $body, 'a recorder fault never alters the response body');
    }
}

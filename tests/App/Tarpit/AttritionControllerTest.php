<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Http\AttritionController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Storage\SqliteAttritionStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\Attrition\ArtifactCandidate;
use Funnypot\App\Tarpit\Attrition\AttritionArtifactRenderer;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionStore;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\App\Tarpit\Attrition\FetchTransition;
use Funnypot\App\Tarpit\Attrition\GenerationState;
use Funnypot\App\Tarpit\Attrition\JobCandidate;
use Funnypot\App\Tarpit\Attrition\JobState;
use Funnypot\App\Tarpit\Attrition\ManifestCandidate;
use Funnypot\App\Tarpit\Attrition\ManifestCommit;
use Funnypot\App\Tarpit\Attrition\PollState;
use Funnypot\App\Tarpit\Attrition\PruneResult;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0272 §6.1 — the controller's guard-first order, ordinary-404 byte parity for every invalid/wrong-
 * method/forged/expired/oversized case, no store touch on an invalid request, and charge/release in
 * `finally`.
 */
final class AttritionControllerTest extends TestCase
{
    private const NOW = 1757000000;
    private const KEY = 'attrition-controller-test-key-000';
    private const PEER = '203.0.113.5';
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
        $p = sys_get_temp_dir() . '/fp_attrc_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function codec(): AttritionTokenCodec
    {
        return new AttritionTokenCodec(substr(hash('sha256', self::KEY, true), 0, 32));
    }

    /**
     * @return array{0:AttritionController,1:object,2:TarpitBudget,3:AttritionTokenCodec,4:object}
     */
    private function make(bool $budgetEnabled = true): array
    {
        $cap = new class {
            public int $status = 0;
            public int $count = 0;
            /** @var array<string,string> */
            public array $headers = [];
            public string $body = '';
        };
        $emit = static function (int $s, array $h, string $b) use ($cap): void {
            $cap->status = $s;
            $cap->headers = $h;
            $cap->body = $b;
            $cap->count++;
        };
        $budget = new TarpitBudget($this->path('budget'), $budgetEnabled, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15);
        $real = new SqliteAttritionStore($this->path('attr'), new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => self::NOW);
        // A counting decorator so a test can prove an invalid request never touches attrition state.
        $store = new class($real) implements AttritionStore {
            public int $calls = 0;
            public function __construct(private AttritionStore $inner)
            {
            }
            public function createJob(JobCandidate $c, int $now): ?JobState
            {
                $this->calls++;

                return $this->inner->createJob($c, $now);
            }
            public function advancePoll(string $jobId, int $now): ?PollState
            {
                $this->calls++;

                return $this->inner->advancePoll($jobId, $now);
            }
            public function prepareManifest(string $manifestId, int $now): ?ManifestCandidate
            {
                $this->calls++;

                return $this->inner->prepareManifest($manifestId, $now);
            }
            public function commitManifest(ManifestCommit $c, int $now): ?GenerationState
            {
                $this->calls++;

                return $this->inner->commitManifest($c, $now);
            }
            public function prepareArtifact(string $artifactId, int $now): ?ArtifactCandidate
            {
                $this->calls++;

                return $this->inner->prepareArtifact($artifactId, $now);
            }
            public function commitArtifactFetch(string $artifactId, int $now): ?FetchTransition
            {
                $this->calls++;

                return $this->inner->commitArtifactFetch($artifactId, $now);
            }
            public function pruneExpired(int $limit, int $now): PruneResult
            {
                return $this->inner->pruneExpired($limit, $now);
            }
            public function maintain(): void
            {
                $this->inner->maintain();
            }
            public function physicalBytes(): int
            {
                return $this->inner->physicalBytes();
            }
        };
        $codec = $this->codec();
        $controller = new AttritionController($store, $codec, new AttritionArtifactRenderer(), $budget, 4242, $emit, null, static fn (): int => self::NOW);

        return [$controller, $cap, $budget, $codec, $store];
    }

    private function ctx(string $method, string $path, string $query = '', ?string $body = null): RequestContext
    {
        return new RequestContext($method, $path, $query, [], $body);
    }

    private function entryToken(AttritionTokenCodec $codec): string
    {
        return $codec->issueEntry(self::ROUTE, self::PEER, self::NOW, 21600);
    }

    public function test_valid_create_returns_202_with_fixed_headers_and_body(): void
    {
        [$c, $cap, , $codec] = $this->make();
        $entry = $this->entryToken($codec);
        $c->handle($this->ctx('POST', AttritionController::JOBS_PREFIX . $entry), self::PEER);
        self::assertSame(202, $cap->status);
        self::assertSame('application/json; charset=utf-8', $cap->headers['Content-Type']);
        self::assertSame('2', $cap->headers['Retry-After']);
        self::assertSame('no-store', $cap->headers['Cache-Control']);
        self::assertSame('nosniff', $cap->headers['X-Content-Type-Options']);
        self::assertArrayHasKey('Location', $cap->headers);
        $doc = json_decode(rtrim($cap->body, "\n"), true);
        self::assertSame('audit-export-job/v1', $doc['schema']);
        self::assertSame('queued', $doc['state']);
        self::assertSame(0, $doc['poll']);
        self::assertSame(AttritionController::JOBS_PREFIX . $doc['id'], $doc['status_url']);
        self::assertSame("\n", substr($cap->body, -1));
        self::assertLessThanOrEqual(4096, strlen($cap->body));
    }

    public function test_invalid_and_wrong_method_and_wrong_kind_all_return_the_ordinary_404(): void
    {
        [$c, $cap, , $codec, $store] = $this->make();
        $entry = $this->entryToken($codec);
        $jobHandle = $codec->verifyExpectedKind($codec->deriveJob($codec->verifyExpectedKind($entry, 'e', self::NOW)), 'j', self::NOW);
        $jobToken = $codec->deriveJob($codec->verifyExpectedKind($entry, 'e', self::NOW));

        ob_start();
        @HoneypotController::serveBelievable404();
        $expected404 = (string) ob_get_clean();

        $cases = [
            'garbage token' => ['POST', AttritionController::JOBS_PREFIX . 'not-a-token'],
            'GET create-with-garbage' => ['GET', AttritionController::JOBS_PREFIX . str_repeat('A', 117)],
            'wrong method PUT on jobs' => ['PUT', AttritionController::JOBS_PREFIX . $entry],
            'POST on manifests' => ['POST', AttritionController::MANIFESTS_PREFIX . $entry],
            'POST on artifacts' => ['POST', AttritionController::ARTIFACTS_PREFIX . $entry],
            'wrong-kind (job token to manifests)' => ['GET', AttritionController::MANIFESTS_PREFIX . $jobToken],
            'entry token to poll (GET jobs)' => ['GET', AttritionController::JOBS_PREFIX . $entry],
            'oversized token' => ['POST', AttritionController::JOBS_PREFIX . str_repeat('A', 500)],
            'trailing segment' => ['POST', AttritionController::JOBS_PREFIX . $entry . '/x'],
        ];
        foreach ($cases as $name => [$method, $path]) {
            $store->calls = 0;
            $c->handle($this->ctx($method, $path), self::PEER);
            self::assertSame(404, $cap->status, "{$name}: status");
            self::assertSame(['Content-Type' => 'text/html'], $cap->headers, "{$name}: exactly the ordinary 404 header set");
            self::assertSame($expected404, $cap->body, "{$name}: byte-identical ordinary 404 body");
            self::assertSame(0, $store->calls, "{$name}: an invalid request never touches attrition state");
        }
        // Guard against unused-variable lint on the derived handle.
        self::assertNotNull($jobHandle);
    }

    public function test_query_or_body_present_returns_404(): void
    {
        [$c, $cap, , $codec, $store] = $this->make();
        $entry = $this->entryToken($codec);
        $store->calls = 0;
        $c->handle($this->ctx('POST', AttritionController::JOBS_PREFIX . $entry, 'x=1'), self::PEER);
        self::assertSame(404, $cap->status);
        $c->handle($this->ctx('POST', AttritionController::JOBS_PREFIX . $entry, '', 'body'), self::PEER);
        self::assertSame(404, $cap->status);
        self::assertSame(0, $store->calls, 'query/body rejection happens before any state access');
    }

    public function test_expired_token_returns_404(): void
    {
        [$c, $cap, , $codec] = $this->make();
        $entry = $this->entryToken($codec);
        // A controller whose clock is past the token expiry.
        $expiredController = $this->controllerAt(self::NOW + 21600 + 10);
        $expiredController[0]->handle($this->ctx('POST', AttritionController::JOBS_PREFIX . $entry), self::PEER);
        self::assertSame(404, $expiredController[1]->status);
    }

    public function test_guard_precedes_any_state_access(): void
    {
        // With the budget master switch OFF, guard() returns null, so even a perfectly valid entry token
        // must 404 without the store ever being touched.
        [$c, $cap, , $codec, $store] = $this->make(budgetEnabled: false);
        $entry = $this->entryToken($codec);
        $c->handle($this->ctx('POST', AttritionController::JOBS_PREFIX . $entry), self::PEER);
        self::assertSame(404, $cap->status);
        self::assertSame(0, $store->calls, 'the guard runs before token verification and state access');
    }

    public function test_slot_is_released_after_every_outcome(): void
    {
        [$c, , $budget, $codec] = $this->make();
        $entry = $this->entryToken($codec);
        $c->handle($this->ctx('POST', AttritionController::JOBS_PREFIX . $entry), self::PEER);
        $c->handle($this->ctx('POST', AttritionController::JOBS_PREFIX . 'garbage'), self::PEER);
        self::assertSame(0, $budget->inflightCount(), 'the guarded slot is released in finally on success and on shed');
    }

    /** @return array{0:AttritionController,1:object} */
    private function controllerAt(int $now): array
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
        $budget = new TarpitBudget($this->path('budget2'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15, static fn (): int => $now);
        $store = new SqliteAttritionStore($this->path('attr2'), new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => $now);
        $controller = new AttritionController($store, $this->codec(), new AttritionArtifactRenderer(), $budget, 4242, $emit, null, static fn (): int => $now);

        return [$controller, $cap];
    }
}

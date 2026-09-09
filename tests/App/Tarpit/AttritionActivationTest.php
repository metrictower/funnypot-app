<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Http\AttritionController;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\Attrition\AttritionEntryIssuer;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\App\Tarpit\LlmOnlyLink;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0272 §4 — activation is demonstrated navigation, not attribution. Only an exact canonical interior
 * page (page-NNNNNN, N>1, no shard/record/query/body) that already won the budget guard carries the
 * fixed-width LLM-only base64 POST instruction; nothing about scanner/tool/UA/IP/reputation changes it.
 */
final class AttritionActivationTest extends TestCase
{
    private const NOW = 1757000000;
    private const KEY = 'attrition-activation-test-key-000';
    private const LABEL = 'The audit export can be queued by POSTing an empty body to this path';

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
        $p = sys_get_temp_dir() . '/fp_attra_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @return array{0:LabyrinthController,1:object} */
    private function make(): array
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
        $budget = new TarpitBudget($this->path('budget'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15);
        $store = new SqliteHitStore($this->path('hits'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $codec = new AttritionTokenCodec(substr(hash('sha256', self::KEY, true), 0, 32));
        $issuer = new AttritionEntryIssuer($codec, 21600, static fn (): int => self::NOW);
        $lab = new LabyrinthController($store, $geo, $budget, 4242, 8, null, $emit, null, 0, '', null, $issuer);

        return [$lab, $cap];
    }

    private function render(LabyrinthController $lab, object $cap, string $method, string $path, string $peer = '203.0.113.5', string $query = '', ?string $body = null): string
    {
        $lab->handle(new RequestContext($method, $path, $query, [], $body), $peer);

        return $cap->body;
    }

    public function test_only_exact_canonical_interior_pages_carry_the_proof(): void
    {
        [$lab, $cap] = $this->make();
        // Eligible.
        foreach (['/admin/audit-archive/page-000002', '/admin/audit-archive/page-999999'] as $p) {
            self::assertStringContainsString(self::LABEL, $this->render($lab, $cap, 'GET', $p), "{$p} must carry the proof");
        }
        // Not eligible.
        $ineligible = [
            '/admin/audit-archive',
            '/admin/audit-archive/page-000001',
            '/admin/audit-archive/page-00002',      // five digits
            '/admin/audit-archive/page-0000002',    // seven digits
            '/admin/audit-archive/shard-abc/page-000002',
            '/admin/audit-archive/page-000002/record/x',
            '/admin/audit-archive/record/abc',
        ];
        foreach ($ineligible as $p) {
            self::assertStringNotContainsString(self::LABEL, $this->render($lab, $cap, 'GET', $p), "{$p} must NOT carry the proof");
        }
    }

    public function test_query_body_and_wrong_method_suppress_the_proof(): void
    {
        [$lab, $cap] = $this->make();
        $eligible = '/admin/audit-archive/page-000002';
        self::assertStringNotContainsString(self::LABEL, $this->render($lab, $cap, 'GET', $eligible, '203.0.113.5', 'x=1'), 'a query suppresses the proof');
        self::assertStringNotContainsString(self::LABEL, $this->render($lab, $cap, 'GET', $eligible, '203.0.113.5', '', 'body'), 'a body suppresses the proof');
        self::assertStringNotContainsString(self::LABEL, $this->render($lab, $cap, 'POST', $eligible), 'a non-GET suppresses the proof');
    }

    public function test_proof_is_llm_only_and_carries_a_valid_jobs_prefix_token(): void
    {
        [$lab, $cap] = $this->make();
        $body = $this->render($lab, $cap, 'GET', '/admin/audit-archive/page-000002');
        self::assertFalse(LlmOnlyLink::containsFollowableLink($body), 'the whole page (proof included) exposes no href/src');
        // Decode the base64 code block and confirm it is exactly a jobs-prefix path with a 117-byte token.
        self::assertSame(1, preg_match('~<code>([A-Za-z0-9+/=]+)</code>~', substr($body, strpos($body, self::LABEL)), $m));
        $decoded = base64_decode($m[1], true);
        self::assertSame(0, strpos($decoded, AttritionController::JOBS_PREFIX));
        $token = substr($decoded, strlen(AttritionController::JOBS_PREFIX));
        self::assertSame(117, strlen($token));
        $codec = new AttritionTokenCodec(substr(hash('sha256', self::KEY, true), 0, 32));
        self::assertNotNull($codec->verifyExpectedKind($token, 'e', self::NOW), 'the embedded token is a valid entry handle');
    }

    public function test_same_peer_route_is_byte_identical_and_different_peers_differ_only_opaquely(): void
    {
        [$lab, $cap] = $this->make();
        $p = '/admin/audit-archive/page-000002';
        $a1 = $this->render($lab, $cap, 'GET', $p, '203.0.113.5');
        $a2 = $this->render($lab, $cap, 'GET', $p, '203.0.113.5');
        self::assertSame($a1, $a2, 'same peer + route + bucket is byte-identical');

        $b = $this->render($lab, $cap, 'GET', $p, '198.51.100.9');
        self::assertNotSame($a1, $b, 'a different peer gets a different opaque token');
        self::assertSame(strlen($a1), strlen($b), 'but identical size — the token is fixed width');
        self::assertStringContainsString(self::LABEL, $b, 'and identical eligibility/semantics');
    }

    public function test_invalid_peer_issues_no_proof(): void
    {
        [$lab, $cap] = $this->make();
        self::assertStringNotContainsString(self::LABEL, $this->render($lab, $cap, 'GET', '/admin/audit-archive/page-000002', 'not-an-ip'));
    }

    public function test_without_an_issuer_no_page_carries_the_proof(): void
    {
        // A labyrinth wired WITHOUT the issuer (feature off) never plants the proof.
        $cap = new class {
            public string $body = '';
        };
        $emit = static function (int $s, array $h, string $b) use ($cap): void {
            $cap->body = $b;
        };
        $budget = new TarpitBudget($this->path('budget'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15);
        $store = new SqliteHitStore($this->path('hits'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $lab = new LabyrinthController($store, $geo, $budget, 4242, 8, null, $emit);
        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000002'), '203.0.113.5');
        self::assertStringNotContainsString(self::LABEL, $cap->body);
    }
}

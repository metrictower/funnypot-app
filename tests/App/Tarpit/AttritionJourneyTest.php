<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Http\AttritionController;
use Funnypot\App\Storage\SqliteAttritionStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\Attrition\AttritionArtifactRenderer;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * FP-0272 §6 — the complete frozen-clock journey a following agent walks: create, the nine-row poll
 * table, the two-mismatch/one-match checksum sequence, generation ordering + finality, byte-identical
 * revisits, and the response caps.
 */
final class AttritionJourneyTest extends TestCase
{
    private const NOW = 1757000000;
    private const KEY = 'attrition-journey-test-key-000000';
    private const PEER = '203.0.113.7';
    private const ROUTE = '/admin/audit-archive/page-000002';

    /** @var string[] */
    private array $tmp = [];

    private AttritionController $controller;
    private object $cap;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->cap = new class {
            public int $status = 0;
            /** @var array<string,string> */
            public array $headers = [];
            public string $body = '';
        };
        $cap = $this->cap;
        $emit = static function (int $s, array $h, string $b) use ($cap): void {
            $cap->status = $s;
            $cap->headers = $h;
            $cap->body = $b;
        };
        $budget = new TarpitBudget($this->path('budget'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15, static fn (): int => self::NOW);
        $store = new SqliteAttritionStore($this->path('attr'), new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => self::NOW);
        $this->controller = new AttritionController($store, $this->codec(), new AttritionArtifactRenderer(), $budget, 4242, $emit, null, static fn (): int => self::NOW);
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
        $p = sys_get_temp_dir() . '/fp_attrj_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function codec(): AttritionTokenCodec
    {
        return new AttritionTokenCodec(substr(hash('sha256', self::KEY, true), 0, 32));
    }

    /** @return array{status:int,headers:array<string,string>,body:string} */
    private function req(string $method, string $path): array
    {
        $this->controller->handle(new RequestContext($method, $path), self::PEER);

        return ['status' => $this->cap->status, 'headers' => $this->cap->headers, 'body' => $this->cap->body];
    }

    public function test_full_journey_progress_checksums_finality_and_caps(): void
    {
        $entry = $this->codec()->issueEntry(self::ROUTE, self::PEER, self::NOW, 21600);

        // Create.
        $create = $this->req('POST', AttritionController::JOBS_PREFIX . $entry);
        self::assertSame(202, $create['status']);
        self::assertLessThanOrEqual(4096, strlen($create['body']));
        $job = json_decode(rtrim($create['body'], "\n"), true);
        $jobToken = $job['id'];
        self::assertSame(AttritionController::JOBS_PREFIX . $jobToken, $job['status_url']);

        // Idempotent create: same job id.
        $create2 = json_decode(rtrim($this->req('POST', AttritionController::JOBS_PREFIX . $entry)['body'], "\n"), true);
        self::assertSame($jobToken, $create2['id']);

        // The exact nine-row poll table.
        $expected = [
            1 => ['queued', 4, '2'],
            2 => ['queued', 9, '3'],
            3 => ['discovering', 18, '3'],
            4 => ['collecting', 34, '4'],
            5 => ['collecting', 52, '4'],
            6 => ['serializing', 68, '5'],
            7 => ['indexing', 81, '3'],
            8 => ['checksumming', 93, '2'],
        ];
        foreach ($expected as $poll => [$state, $progress, $retry]) {
            $r = $this->req('GET', AttritionController::JOBS_PREFIX . $jobToken);
            self::assertSame(200, $r['status']);
            $doc = json_decode(rtrim($r['body'], "\n"), true);
            self::assertSame($state, $doc['state'], "poll {$poll} state");
            self::assertSame($progress, $doc['progress'], "poll {$poll} progress");
            self::assertSame($poll, $doc['poll']);
            self::assertSame($retry, $r['headers']['Retry-After'], "poll {$poll} Retry-After");
            self::assertArrayNotHasKey('manifest_url', $doc);
            self::assertLessThanOrEqual(4096, strlen($r['body']));
        }

        // Terminal poll 9: ready, no Retry-After, carries the generation-0 manifest URL, byte-stable.
        $t1 = $this->req('GET', AttritionController::JOBS_PREFIX . $jobToken);
        $ready = json_decode(rtrim($t1['body'], "\n"), true);
        self::assertSame('ready', $ready['state']);
        self::assertSame(99, $ready['progress']);
        self::assertSame(9, $ready['poll']);
        self::assertArrayNotHasKey('Retry-After', $t1['headers']);
        self::assertArrayHasKey('manifest_url', $ready);
        $t2 = $this->req('GET', AttritionController::JOBS_PREFIX . $jobToken);
        self::assertSame($t1['body'], $t2['body'], 'terminal polls are byte-identical');

        // Walk the checksum re-verification sequence.
        $manifestUrl = $ready['manifest_url'];
        $servedHashes = [];
        $declaredHashes = [];
        for ($gen = 0; $gen <= 2; $gen++) {
            $m = $this->req('GET', $manifestUrl);
            self::assertSame(200, $m['status'], "manifest gen {$gen} status");
            self::assertSame('text/plain; charset=utf-8', $m['headers']['Content-Type']);
            self::assertSame('attachment; filename="MANIFEST.sha256"', $m['headers']['Content-Disposition']);
            self::assertLessThanOrEqual(4096, strlen($m['body']));

            self::assertSame(1, preg_match('/^([0-9a-f]{64})  audit-export\.ndjson$/m', $m['body'], $hm), "manifest gen {$gen} hash line");
            $declaredHashes[$gen] = $hm[1];
            self::assertSame(1, preg_match('~^# artifact: (/admin/export/artifacts/\S+)$~m', $m['body'], $am));
            $artifactUrl = $am[1];

            $hasRefresh = preg_match('~^# refresh: (/admin/export/manifests/\S+)$~m', $m['body'], $rm) === 1;
            if ($gen < 2) {
                self::assertTrue($hasRefresh, "generation {$gen} has a refresh link");
            } else {
                self::assertFalse($hasRefresh, 'the final generation has no refresh link');
            }

            // The next manifest is inaccessible until this generation's artifact is fetched.
            if ($hasRefresh) {
                self::assertSame(404, $this->req('GET', $rm[1])['status'], "generation " . ($gen + 1) . " is inaccessible before artifact {$gen}");
            }

            // Fetch the artifact.
            $a = $this->req('GET', $artifactUrl);
            self::assertSame(200, $a['status'], "artifact gen {$gen} status");
            self::assertSame('application/x-ndjson', $a['headers']['Content-Type']);
            self::assertSame('attachment; filename="audit-export.ndjson"', $a['headers']['Content-Disposition']);
            self::assertSame((string) strlen($a['body']), $a['headers']['Content-Length']);
            self::assertSame('"' . hash('sha256', $a['body']) . '"', $a['headers']['ETag']);
            self::assertLessThanOrEqual(32768, strlen($a['body']));
            $servedHashes[$gen] = hash('sha256', $a['body']);

            if ($hasRefresh) {
                $manifestUrl = $rm[1];
            }
        }

        // Two mismatches, then one match.
        self::assertNotSame($declaredHashes[0], $servedHashes[0], 'generation 0 mismatches');
        self::assertNotSame($declaredHashes[1], $servedHashes[1], 'generation 1 mismatches');
        self::assertSame($declaredHashes[2], $servedHashes[2], 'generation 2 matches');
    }

    public function test_manifest_and_artifact_revisits_are_byte_identical(): void
    {
        $entry = $this->codec()->issueEntry(self::ROUTE, self::PEER, self::NOW, 21600);
        $jobToken = json_decode(rtrim($this->req('POST', AttritionController::JOBS_PREFIX . $entry)['body'], "\n"), true)['id'];
        for ($i = 0; $i < 9; $i++) {
            $ready = json_decode(rtrim($this->req('GET', AttritionController::JOBS_PREFIX . $jobToken)['body'], "\n"), true);
        }
        $manifestUrl = $ready['manifest_url'];
        $m1 = $this->req('GET', $manifestUrl)['body'];
        $m2 = $this->req('GET', $manifestUrl)['body'];
        self::assertSame($m1, $m2, 'a repeated manifest fetch is byte-identical');
        self::assertSame(1, preg_match('~^# artifact: (/admin/export/artifacts/\S+)$~m', $m1, $am));
        $a1 = $this->req('GET', $am[1])['body'];
        $a2 = $this->req('GET', $am[1])['body'];
        self::assertSame($a1, $a2, 'a repeated artifact fetch is byte-identical');
    }
}

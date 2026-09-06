<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\SqliteAttritionStore;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * FP-0272 §7 — real multi-process contention against one SQLite file: an identical create converges on
 * one row, concurrent polls never exceed the terminal ordinal, concurrent generation commits create one
 * row, and the quota counter always equals the committed rows (never overshoots).
 */
final class AttritionStoreConcurrencyTest extends TestCase
{
    private const CHILDREN = 24;
    private const NOW = 1757000000;

    private string $db = '';

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite') || !function_exists('proc_open')) {
            self::markTestSkipped('pdo_sqlite / proc_open required');
        }
        $this->db = sys_get_temp_dir() . '/fp_attr_conc_' . bin2hex(random_bytes(6)) . '.sqlite';
    }

    protected function tearDown(): void
    {
        foreach (['', '-wal', '-shm'] as $s) {
            @unlink($this->db . $s);
        }
    }

    /** Fire $n workers of one action simultaneously and return their decoded JSON facts. @return array<int,array<string,mixed>> */
    private function race(string $action, int $n): array
    {
        $script = __DIR__ . '/support/attrition-child.php';
        $env = ['PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin')];
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR', 'HOME'] as $k) {
            $v = getenv($k);
            if ($v !== false && $v !== '') {
                $env[$k] = $v;
            }
        }
        $procs = [];
        for ($i = 0; $i < $n; $i++) {
            $p = proc_open([PHP_BINARY, $script, $this->db, $action], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, sys_get_temp_dir(), $env);
            self::assertIsResource($p, "worker {$i} did not start");
            $procs[] = [$p, $pipes];
        }
        $facts = [];
        foreach ($procs as $i => [$p, $pipes]) {
            $out = trim((string) stream_get_contents($pipes[1]));
            $err = (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $rc = proc_close($p);
            self::assertSame(0, $rc, "worker {$i} rc={$rc}: {$err}");
            $facts[] = json_decode($out, true);
        }

        return $facts;
    }

    private function pdo(): PDO
    {
        return new PDO('sqlite:' . $this->db);
    }

    private function store(): SqliteAttritionStore
    {
        return new SqliteAttritionStore($this->db, new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => self::NOW);
    }

    public function test_identical_creates_converge_on_one_row(): void
    {
        $facts = $this->race('create', self::CHILDREN);
        $jobs = array_values(array_unique(array_filter(array_column($facts, 'job'))));
        self::assertCount(1, $jobs, 'every successful create returns the same job id');

        $db = $this->pdo();
        self::assertSame(1, (int) $db->query('SELECT COUNT(*) FROM attrition_journeys')->fetchColumn());
        self::assertSame(1, (int) $db->query('SELECT COUNT(*) FROM attrition_jobs')->fetchColumn());
        self::assertSame(2, (int) $db->query('SELECT row_count FROM attrition_quota')->fetchColumn(), 'the quota equals the two committed rows');
    }

    public function test_concurrent_polls_never_exceed_nine(): void
    {
        // Seed the job in-process, then race polls.
        $this->race('create', 1);
        $facts = $this->race('poll', self::CHILDREN);
        foreach ($facts as $f) {
            if ($f['poll'] !== null) {
                self::assertLessThanOrEqual(9, (int) $f['poll']);
                self::assertGreaterThanOrEqual(1, (int) $f['poll']);
            }
        }
        $db = $this->pdo();
        self::assertSame(9, (int) $db->query('SELECT poll_count FROM attrition_jobs')->fetchColumn(), 'the stored poll saturates at 9');
    }

    public function test_concurrent_generation_commits_create_one_row(): void
    {
        // Drive create + nine polls in-process so generation 0 is eligible, then race the commit.
        $store = $this->store();
        $this->race('create', 1);
        for ($i = 0; $i < 9; $i++) {
            $store = $this->store();
            $store->advancePoll($this->jobId(), self::NOW);
        }
        $facts = $this->race('commit0', self::CHILDREN);
        $gens = array_filter($facts, static fn ($f): bool => $f['gen'] !== null);
        self::assertNotEmpty($gens, 'at least one commit wins');

        $db = $this->pdo();
        self::assertSame(1, (int) $db->query('SELECT COUNT(*) FROM attrition_generations')->fetchColumn(), 'exactly one (job,generation) row');
        // The quota equals journey + job + one generation = 3, and matches the real total.
        self::assertSame(3, (int) $db->query('SELECT row_count FROM attrition_quota')->fetchColumn());
        self::assertSame(
            (int) $db->query('SELECT (SELECT COUNT(*) FROM attrition_journeys)+(SELECT COUNT(*) FROM attrition_jobs)+(SELECT COUNT(*) FROM attrition_generations)')->fetchColumn(),
            (int) $db->query('SELECT row_count FROM attrition_quota')->fetchColumn(),
            'the quota never overshoots the real row total'
        );
    }

    private function jobId(): string
    {
        // Mirror the child's deterministic derivation.
        $codec = new \Funnypot\App\Tarpit\Attrition\AttritionTokenCodec(str_repeat("\x5a", 32));
        $entry = $codec->issueEntry('/admin/audit-archive/page-000002', '203.0.113.9', self::NOW, 21600);
        $eh = $codec->verifyExpectedKind($entry, 'e', self::NOW);

        return $codec->storedId($codec->deriveJob($eh), 'j');
    }
}

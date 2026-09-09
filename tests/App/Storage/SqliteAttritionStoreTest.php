<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\SqliteAttritionStore;
use Funnypot\App\Tarpit\Attrition\AttritionArtifactRenderer;
use Funnypot\App\Tarpit\Attrition\AttritionHandle;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionStateCost;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\App\Tarpit\Attrition\JobCandidate;
use Funnypot\App\Tarpit\Attrition\ManifestCommit;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * FP-0272 §7 — the bounded SQLite state store: idempotent create, the saturating poll, generation
 * ordering + finality, fetch saturation, TTL/expiry, atomic row/byte ceilings, prune/quota
 * reconciliation, and persisted-row redaction.
 */
final class SqliteAttritionStoreTest extends TestCase
{
    private const NOW = 1757000000;
    private const EXP = self::NOW + 21600;

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

    private function path(): string
    {
        $p = sys_get_temp_dir() . '/fp_attr_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function store(?string $path = null, ?AttritionLimits $limits = null, int $now = self::NOW): SqliteAttritionStore
    {
        return new SqliteAttritionStore($path ?? $this->path(), $limits ?? new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => $now);
    }

    private static function id(string $label): string
    {
        return substr(hash('sha256', $label), 0, 32);
    }

    private function candidate(string $tag): JobCandidate
    {
        return new JobCandidate(self::id('j-' . $tag), self::id('e-' . $tag), self::id('job-' . $tag), self::id('m0-' . $tag), SqliteAttritionStore::JOB_REVISION, self::EXP);
    }

    public function test_create_is_idempotent_and_starts_at_poll_zero(): void
    {
        $s = $this->store();
        $c = $this->candidate('x');
        $a = $s->createJob($c, self::NOW);
        self::assertNotNull($a);
        self::assertSame(0, $a->pollCount);
        $b = $s->createJob($c, self::NOW);
        self::assertNotNull($b);
        self::assertSame($a->jobId, $b->jobId, 'a retry returns the same job');
    }

    public function test_poll_table_saturates_at_nine(): void
    {
        $s = $this->store();
        $c = $this->candidate('p');
        $s->createJob($c, self::NOW);
        $seen = [];
        for ($i = 0; $i < 12; $i++) {
            $seen[] = $s->advancePoll($c->jobId, self::NOW)->poll;
        }
        self::assertSame([1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 9, 9], $seen);
    }

    public function test_manifest_generation_ordering_and_finality(): void
    {
        $s = $this->store();
        $c = $this->candidate('g');
        $s->createJob($c, self::NOW);

        // Generation 0 is ineligible until poll 9.
        self::assertNull($s->prepareManifest($c->firstManifestId, self::NOW));
        for ($i = 0; $i < 9; $i++) {
            $s->advancePoll($c->jobId, self::NOW);
        }
        $g0 = $s->prepareManifest($c->firstManifestId, self::NOW);
        self::assertNotNull($g0);
        self::assertSame(0, $g0->generation);
        self::assertFalse($g0->alreadyCommitted);

        $art0 = self::id('a0-g');
        $m1 = self::id('m1-g');
        self::assertNotNull($s->commitManifest(new ManifestCommit($c->journeyId, $c->jobId, self::id('gen0-g'), 0, $c->firstManifestId, $art0, $m1, SqliteAttritionStore::RENDERER_REVISION, self::EXP, AttritionStateCost::GENERATION), self::NOW));
        // Repeat manifest 0 fetch is idempotent.
        $again = $s->prepareManifest($c->firstManifestId, self::NOW);
        self::assertTrue($again->alreadyCommitted);

        // Generation 1 is ineligible until artifact 0 is fetched.
        self::assertNull($s->prepareManifest($m1, self::NOW));
        self::assertTrue($s->commitArtifactFetch($art0, self::NOW)->isFirst);
        $g1 = $s->prepareManifest($m1, self::NOW);
        self::assertNotNull($g1);
        self::assertSame(1, $g1->generation);

        $art1 = self::id('a1-g');
        $m2 = self::id('m2-g');
        self::assertNotNull($s->commitManifest(new ManifestCommit($c->journeyId, $c->jobId, self::id('gen1-g'), 1, $m1, $art1, $m2, SqliteAttritionStore::RENDERER_REVISION, self::EXP, AttritionStateCost::GENERATION), self::NOW));
        self::assertTrue($s->commitArtifactFetch($art1, self::NOW)->isFirst);

        $g2 = $s->prepareManifest($m2, self::NOW);
        self::assertSame(2, $g2->generation);
        // The final generation carries no next manifest, so a 4th generation is impossible.
        $art2 = self::id('a2-g');
        self::assertNotNull($s->commitManifest(new ManifestCommit($c->journeyId, $c->jobId, self::id('gen2-g'), 2, $m2, $art2, null, SqliteAttritionStore::RENDERER_REVISION, self::EXP, AttritionStateCost::GENERATION), self::NOW));
        self::assertNull($s->prepareManifest(self::id('m3-g'), self::NOW), 'no fourth generation is reachable');
    }

    public function test_artifact_fetch_saturates_zero_one_two(): void
    {
        $s = $this->store();
        $c = $this->candidate('f');
        $s->createJob($c, self::NOW);
        for ($i = 0; $i < 9; $i++) {
            $s->advancePoll($c->jobId, self::NOW);
        }
        $art0 = self::id('a0-f');
        $s->commitManifest(new ManifestCommit($c->journeyId, $c->jobId, self::id('gen0-f'), 0, $c->firstManifestId, $art0, self::id('m1-f'), SqliteAttritionStore::RENDERER_REVISION, self::EXP, AttritionStateCost::GENERATION), self::NOW);
        self::assertTrue($s->commitArtifactFetch($art0, self::NOW)->isFirst);
        self::assertFalse($s->commitArtifactFetch($art0, self::NOW)->isFirst);
        self::assertFalse($s->commitArtifactFetch($art0, self::NOW)->isFirst, 'saturates at 2');
        // fetch_count never exceeds 2.
        $db = new PDO('sqlite:' . $this->tmp[count($this->tmp) - 1]);
        self::assertSame('2', (string) $db->query('SELECT MAX(fetch_count) FROM attrition_generations')->fetchColumn());
    }

    public function test_expiry_sheds_poll_and_manifest(): void
    {
        $s = $this->store();
        $c = $this->candidate('t');
        $s->createJob($c, self::NOW);
        self::assertNull($s->advancePoll($c->jobId, self::EXP), 'a poll at/after expiry sheds');
        self::assertNull($s->prepareArtifact(self::id('nope'), self::NOW));
    }

    public function test_global_row_ceiling_is_atomic_and_never_overshoots(): void
    {
        $path = $this->path();
        // Floor clamp is 100 rows; each create adds a journey + a job = 2 rows.
        $s = $this->store($path, new AttritionLimits(21600, 32, 64, 100, 64));
        $created = 0;
        for ($i = 0; $i < 80; $i++) {
            if ($s->createJob($this->candidate('cap' . $i), self::NOW) !== null) {
                $created++;
            }
        }
        self::assertSame(50, $created, '100 rows / 2 rows per create');
        $db = new PDO('sqlite:' . $path);
        self::assertLessThanOrEqual(100, (int) $db->query('SELECT row_count FROM attrition_quota')->fetchColumn());
        self::assertSame(
            (int) $db->query('SELECT row_count FROM attrition_quota')->fetchColumn(),
            (int) $db->query('SELECT (SELECT COUNT(*) FROM attrition_journeys)+(SELECT COUNT(*) FROM attrition_jobs)+(SELECT COUNT(*) FROM attrition_generations)')->fetchColumn(),
            'the quota counter equals the real row total'
        );
    }

    public function test_per_journey_job_ceiling_is_enforced(): void
    {
        $s = $this->store(null, new AttritionLimits(21600, 2, 64, 50000, 64));
        $journey = self::id('one-journey');
        $made = 0;
        for ($i = 0; $i < 5; $i++) {
            $c = new JobCandidate($journey, self::id('e' . $i), self::id('job' . $i), self::id('m0' . $i), SqliteAttritionStore::JOB_REVISION, self::EXP);
            if ($s->createJob($c, self::NOW) !== null) {
                $made++;
            }
        }
        self::assertSame(2, $made, 'the per-journey job ceiling caps at maxJobsPerJourney');
    }

    public function test_expired_prune_reconciles_the_quota(): void
    {
        $path = $this->path();
        $s = $this->store($path);
        // Two journeys that expire at NOW+10, one that lives longer.
        $shortA = new JobCandidate(self::id('jA'), self::id('eA'), self::id('jobA'), self::id('mA'), SqliteAttritionStore::JOB_REVISION, self::NOW + 10);
        $shortB = new JobCandidate(self::id('jB'), self::id('eB'), self::id('jobB'), self::id('mB'), SqliteAttritionStore::JOB_REVISION, self::NOW + 10);
        $long = new JobCandidate(self::id('jC'), self::id('eC'), self::id('jobC'), self::id('mC'), SqliteAttritionStore::JOB_REVISION, self::EXP);
        $s->createJob($shortA, self::NOW);
        $s->createJob($shortB, self::NOW);
        $s->createJob($long, self::NOW);

        $r = $s->pruneExpired(128, self::NOW + 100);
        self::assertSame(2, $r->journeysRemoved);
        self::assertSame(4, $r->rowsRemoved, 'two journeys + two jobs');
        $db = new PDO('sqlite:' . $path);
        self::assertSame(2, (int) $db->query('SELECT row_count FROM attrition_quota')->fetchColumn(), 'one journey + one job remain');
        self::assertSame(
            (int) $db->query('SELECT (SELECT COUNT(*) FROM attrition_journeys)+(SELECT COUNT(*) FROM attrition_jobs) FROM attrition_quota')->fetchColumn(),
            (int) $db->query('SELECT row_count FROM attrition_quota')->fetchColumn()
        );
    }

    public function test_extreme_limits_are_reclamped_by_the_value_object(): void
    {
        $l = new AttritionLimits(99999999, 9999, 9999, 99999999, 99999);
        self::assertSame(21600, $l->ttlS);
        self::assertSame(32, $l->maxJobsPerJourney);
        self::assertSame(64, $l->maxArtifactsPerJourney);
        self::assertSame(50000, $l->globalRows);
        self::assertSame(64 * 1024 * 1024, $l->globalStateBytes);
        $tiny = new AttritionLimits(1, 0, 0, 1, 0);
        self::assertSame(3600, $tiny->ttlS);
        self::assertSame(1, $tiny->maxJobsPerJourney);
        self::assertSame(3, $tiny->maxArtifactsPerJourney);
        self::assertSame(100, $tiny->globalRows);
        self::assertSame(1024 * 1024, $tiny->globalStateBytes);
    }

    public function test_no_raw_token_nonce_url_ip_or_ua_is_persisted(): void
    {
        $path = $this->path();
        $s = $this->store($path);
        $codec = new AttritionTokenCodec(str_repeat("\x2a", 32));
        $peer = '198.51.100.77';
        $route = '/admin/audit-archive/page-000042';
        $entryTok = $codec->issueEntry($route, $peer, self::NOW, 21600);
        $entry = $codec->verifyExpectedKind($entryTok, 'e', self::NOW);
        $jobTok = $codec->deriveJob($entry);
        $jobHandle = $codec->verifyExpectedKind($jobTok, 'j', self::NOW);
        $m0Tok = $codec->deriveFirstManifest($jobHandle);
        $s->createJob(new JobCandidate(
            $codec->journeyId($entry),
            $codec->storedId($entryTok, 'e'),
            $codec->storedId($jobTok, 'j'),
            $codec->storedId($m0Tok, 'm'),
            SqliteAttritionStore::JOB_REVISION,
            $entry->expiresAt,
        ), self::NOW);
        $s->maintain();

        $raw = (string) file_get_contents($path);
        foreach ([$entryTok, $jobTok, $m0Tok, $peer, $route, $entry->subject, $entry->nonce] as $secret) {
            self::assertStringNotContainsString($secret, $raw, 'no raw handle/peer/route/subject/nonce may reach the db file');
        }
    }

    public function test_physical_bytes_is_bounded_and_nonzero_after_use(): void
    {
        $s = $this->store();
        $s->createJob($this->candidate('phys'), self::NOW);
        self::assertGreaterThan(0, $s->physicalBytes());
        self::assertLessThan(AttritionLimits::PHYSICAL_MAX_BYTES, $s->physicalBytes());
    }
}

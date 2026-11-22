<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Bench\SsrfPivotCrawler;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/scripts/support/SsrfPivotCrawler.php';
require_once dirname(__DIR__, 4) . '/demo/lib/geo.php';

/**
 * The SSRF-pivot crawler over the real controller: it keeps finding new internal targets, every target
 * it queues came from a body the decoy produced, nothing opens a URL, no answer is goal proof, every
 * leaked-key family stays in the gateways' loop, the run replays exactly, and a runaway is shed.
 */
final class SsrfPivotBenchTest extends TestCase
{
    private const STEPS = 300;

    private static ?SsrfPivotCrawler $crawler = null;

    /** @var array<string,mixed> */
    private static array $result = [];

    /** @var list<string> */
    private static array $opened = [];

    public static function setUpBeforeClass(): void
    {
        RecordingWrapper::install();
        try {
            self::$crawler = new SsrfPivotCrawler();
            self::$result = self::$crawler->run(self::STEPS);
        } finally {
            self::$opened = RecordingWrapper::$log;
            RecordingWrapper::restore();
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$crawler?->cleanup();
    }

    public function test_crawler_keeps_finding_new_targets(): void
    {
        self::assertSame(self::STEPS, self::$result['steps']);
        self::assertCount(self::STEPS, self::$crawler->transcript);
        foreach (array_chunk(self::$crawler->transcript, 50) as $i => $window) {
            self::assertGreaterThanOrEqual(5, array_sum(array_column($window, 'new')), "window {$i} found new targets");
        }
        self::assertGreaterThan(200, self::$result['distinct_targets']);
    }

    public function test_every_queued_target_came_from_a_response(): void
    {
        $seeds = 0;
        foreach (self::$crawler->provenance as $target => $from) {
            if ($from === 'seed') {
                $seeds++;
                continue;
            }
            self::assertArrayHasKey($from, self::$crawler->bodies, "{$target} came from a body the decoy produced");
        }
        self::assertSame(9, $seeds, 'only the step-3 seeds are seeds');
    }

    public function test_zero_outbound_and_zero_goal_proof(): void
    {
        self::assertSame([], self::$opened, 'no URL was opened or stat-ed');
        self::assertSame(0, self::$result['faults']);
        self::assertSame(0, self::$result['warnings']);
        self::assertGreaterThan(500, count(self::$crawler->replies));
        foreach (self::$crawler->replies as $body) {
            self::assertTrue(SsrfGoalProof::clean($body), 'goal proof in: ' . substr($body, 0, 300));
        }
        self::assertFalse(SsrfGoalProof::clean('{"AccessKeyId":"x","SecretAccessKey":"y","Token":"z"}'), 'positive control: IMDS credentials');
        self::assertFalse(SsrfGoalProof::clean('<GetCallerIdentityResult><Arn>arn:aws:iam::1:user/x</Arn></GetCallerIdentityResult>'), 'positive control: an STS success');
    }

    public function test_every_credential_attempt_stays_in_the_loop(): void
    {
        $families = [];
        foreach (self::$crawler->credentials as $c) {
            self::assertSame(200, $c['status'], 'the import is accepted');
            self::assertContains($c['outcome'], ['cred_known', 'cred_restricted', 'cred_expired'], $c['family'] . ' via ' . $c['gateway']);
            $families[$c['family']] = true;
        }
        foreach (['persona_aws', 'core_stripe', 'imds_asia', 'configdump_aws', 'configdump_stripe', 'log_aws', 'log_stripe', 'shell_aws'] as $f) {
            self::assertArrayHasKey($f, $families, "{$f} was tried");
        }
    }

    public function test_replay_is_deterministic(): void
    {
        $a = new SsrfPivotCrawler();
        $b = new SsrfPivotCrawler();
        try {
            self::assertSame($a->run(80)['transcript_hash'], $b->run(80)['transcript_hash']);
        } finally {
            $a->cleanup();
            $b->cleanup();
        }
    }

    public function test_oob_and_public_targets_never_deliver(): void
    {
        $db = self::$crawler->harness()->ssrfStore->db();
        $rows = $db->query("SELECT tclass, outcome FROM ssrf_turns WHERE tclass IN ('source', 'proxied')")->fetchAll(\PDO::FETCH_ASSOC);
        self::assertNotEmpty($rows, 'the crawler hit its own listener and public hosts');
        foreach ($rows as $r) {
            self::assertContains($r['outcome'], ['timeout', 'proxy_denied'], json_encode($r));
        }
        $reached = (int) $db->query("SELECT COUNT(*) FROM ssrf_turns WHERE outcome IN ('http_status', 'banner', 'open')")->fetchColumn();
        self::assertGreaterThan(50, $reached, 'positive control: internal targets do answer');
    }

    public function test_budget_sheds_a_runaway_crawler(): void
    {
        $runaway = new SsrfPivotCrawler(false);
        try {
            $r = $runaway->run(120);
            self::assertGreaterThan(0, $r['throttled'], 'a crawler that never waits is throttled');
            self::assertSame(0, $r['faults']);
        } finally {
            $runaway->cleanup();
        }
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmGenBudget;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

/**
 * The composed LLM gate: both checks AND'd, default-deny. A bulk-scanning IP trips and is pinned to
 * plain-404 even on plausible paths and even after it goes quiet; a lone plausible probe generates.
 */
final class ProbeGateTest extends TestCase
{
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

    private function store(): SqliteHitStore
    {
        $p = sys_get_temp_dir() . '/fp_gate_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return new SqliteHitStore($p);
    }

    private function gate(SqliteHitStore $s): ProbeGate
    {
        return new ProbeGate(new ProbeClassifier(), new VelocityTracker(5, 15), $s, 24);
    }

    /** @param string[] $allow */
    private function gateAllow(SqliteHitStore $s, array $allow): ProbeGate
    {
        return new ProbeGate(new ProbeClassifier(), new VelocityTracker(5, 15), $s, 24, $allow);
    }

    public function test_velocity_thresholds(): void
    {
        $v = new VelocityTracker(5, 15);
        self::assertFalse($v->isBulkScan(['recent' => 4, 'extended' => 10]));
        self::assertTrue($v->isBulkScan(['recent' => 5, 'extended' => 0]));
        self::assertTrue($v->isBulkScan(['recent' => 0, 'extended' => 15]));
    }

    public function test_plausible_path_low_velocity_generates(): void
    {
        $s = $this->store();
        $s->append(['ts' => gmdate('c'), 'ip' => '2.2.2.2', 'method' => 'GET', 'path' => '/x']);
        $d = $this->gate($s)->decide('GET', '/super-rare-app/login.asp', '2.2.2.2');
        self::assertTrue($d['generate']);
        self::assertSame('plausible', $d['reason']);
    }

    public function test_probe_path_blocked(): void
    {
        $d = $this->gate($this->store())->decide('GET', '/random9271.php', '2.2.2.2');
        self::assertFalse($d['generate']);
        self::assertSame('probe', $d['reason']);
    }

    public function test_identity_probe_path_never_reaches_the_model(): void
    {
        // End-to-end: an identity-probe path is shed by Gate B to the plain 404, so client->generate
        // is never called and the model can't echo a loaded word from its own framing.
        $d = $this->gate($this->store())->decide('GET', '/are-you-a-honeypot', '2.2.2.2');
        self::assertFalse($d['generate']);
        self::assertSame('probe', $d['reason']);
    }

    public function test_bulk_scan_trips_and_pins_even_after_going_quiet(): void
    {
        $s = $this->store();
        foreach (['/a', '/b', '/c', '/d', '/e', '/f'] as $p) {   // 6 distinct paths/60s > threshold 5
            $s->append(['ts' => gmdate('c'), 'ip' => '6.6.6.6', 'method' => 'GET', 'path' => $p]);
        }
        $g = $this->gate($s);

        $d = $g->decide('GET', '/admin/login.php', '6.6.6.6');   // plausible path, but bulk velocity
        self::assertFalse($d['generate']);
        self::assertSame('bulk-scan', $d['reason']);
        self::assertTrue($s->isBulkFlagged('6.6.6.6'));

        // pinned: even a fresh plausible path from this IP stays blocked (no new velocity needed)
        $d2 = $g->decide('GET', '/portal/dashboard.php', '6.6.6.6');
        self::assertFalse($d2['generate']);
        self::assertSame('bulk-scan-pinned', $d2['reason']);
    }

    public function test_allowlisted_ip_bypasses_velocity_and_is_never_pinned(): void
    {
        $s = $this->store();
        foreach (['/a', '/b', '/c', '/d', '/e', '/f'] as $p) {   // bulk velocity that WOULD trip
            $s->append(['ts' => gmdate('c'), 'ip' => '7.7.7.7', 'method' => 'GET', 'path' => $p]);
        }
        $d = $this->gateAllow($s, ['7.7.7.7'])->decide('GET', '/admin/login.php', '7.7.7.7');
        self::assertTrue($d['generate']);
        self::assertSame('allowlisted', $d['reason']);
        self::assertFalse($s->isBulkFlagged('7.7.7.7'));         // Gate A skipped → no pin written
    }

    public function test_allowlisted_ip_recovers_from_an_existing_pin(): void
    {
        $s = $this->store();
        $s->flagBulkScan('7.7.7.7', 24);                          // already pinned from earlier testing
        self::assertTrue($s->isBulkFlagged('7.7.7.7'));
        $d = $this->gateAllow($s, ['7.7.7.7'])->decide('GET', '/admin/login.php', '7.7.7.7');
        self::assertTrue($d['generate']);
        self::assertSame('allowlisted', $d['reason']);
    }

    public function test_allowlist_matches_cidr(): void
    {
        $s = $this->store();
        foreach (['/a', '/b', '/c', '/d', '/e', '/f'] as $p) {
            $s->append(['ts' => gmdate('c'), 'ip' => '7.7.7.9', 'method' => 'GET', 'path' => $p]);
        }
        $d = $this->gateAllow($s, ['7.7.7.0/24'])->decide('GET', '/admin/login.php', '7.7.7.9');
        self::assertTrue($d['generate']);
        self::assertSame('allowlisted', $d['reason']);
    }

    public function test_allowlisted_ip_still_requires_a_plausible_path(): void
    {
        // The allowlist only bypasses Gate A (velocity/pin); Gate B still blocks obvious probes,
        // so a test IP sees exactly what a real user would for the same path.
        $d = $this->gateAllow($this->store(), ['7.7.7.7'])->decide('GET', '/random9271.php', '7.7.7.7');
        self::assertFalse($d['generate']);
        self::assertSame('probe', $d['reason']);
    }

    public function test_configurable_velocity_thresholds_can_be_raised(): void
    {
        $v = new VelocityTracker(100, 1000);
        self::assertFalse($v->isBulkScan(['recent' => 50, 'extended' => 500]));
        self::assertTrue($v->isBulkScan(['recent' => 100, 'extended' => 0]));
    }

    // --- the global generations/hour budget behind Gate A ---

    private function budget(int $perHour, int $charged = 0): LlmGenBudget
    {
        $p = sys_get_temp_dir() . '/fp_gate_budget_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;
        $b = new LlmGenBudget($p, $perHour);
        for ($i = 0; $i < $charged; $i++) {
            $b->charge();
        }

        return $b;
    }

    /** @param string[] $allow */
    private function budgetGate(SqliteHitStore $s, LlmGenBudget $b, array $allow = []): ProbeGate
    {
        return new ProbeGate(new ProbeClassifier(), new VelocityTracker(5, 15), $s, 24, $allow, $b);
    }

    public function test_exhausted_global_budget_denies_with_its_own_reason(): void
    {
        $d = $this->budgetGate($this->store(), $this->budget(2, 2))->decide('GET', '/super-rare-app/login.asp', '2.2.2.2');
        self::assertFalse($d['generate']);
        self::assertSame('gen-budget', $d['reason']);

        // One under the cap still generates.
        $d = $this->budgetGate($this->store(), $this->budget(2, 1))->decide('GET', '/super-rare-app/login.asp', '2.2.2.2');
        self::assertTrue($d['generate']);
        self::assertSame('plausible', $d['reason']);
    }

    public function test_allowlisted_ip_bypasses_the_global_budget(): void
    {
        $d = $this->budgetGate($this->store(), $this->budget(1, 1), ['7.7.7.7'])->decide('GET', '/admin/login.php', '7.7.7.7');
        self::assertTrue($d['generate']);
        self::assertSame('allowlisted', $d['reason']);
    }

    public function test_budget_storage_fault_fails_closed_to_deny(): void
    {
        // An unopenable ledger must stop fresh generation (never unbounded spend) — cache and the
        // static 404 still serve, so this is neither a self-DoS nor a tell.
        $b = new LlmGenBudget('/dev/null/no-such-dir/budget.sqlite', 1000);
        $d = $this->budgetGate($this->store(), $b)->decide('GET', '/super-rare-app/login.asp', '2.2.2.2');
        self::assertFalse($d['generate']);
        self::assertSame('gen-budget', $d['reason']);
    }

    public function test_bulk_scan_pin_still_lands_while_the_budget_is_spent(): void
    {
        $s = $this->store();
        foreach (['/a', '/b', '/c', '/d', '/e', '/f'] as $p) {
            $s->append(['ts' => gmdate('c'), 'ip' => '6.6.6.6', 'method' => 'GET', 'path' => $p]);
        }
        $d = $this->budgetGate($s, $this->budget(1, 1))->decide('GET', '/admin/login.php', '6.6.6.6');
        self::assertSame('bulk-scan', $d['reason'], 'velocity is judged before the budget so the pin is written');
        self::assertTrue($s->isBulkFlagged('6.6.6.6'));
    }

    public function test_human_following_served_decoy_links_is_never_pinned(): void
    {
        // Six served path-pairs inside the window — the controller's main row (served, unmatched) plus
        // the responder's own llm-fake row per path, the real dual-row write pattern. None is probing.
        $s = $this->store();
        foreach (['/portal/a', '/portal/b', '/portal/c', '/portal/d', '/portal/e', '/portal/f'] as $p) {
            $s->append(['ts' => gmdate('c'), 'ip' => '3.3.3.3', 'method' => 'GET', 'path' => $p, 'served' => true]);
            $s->append(['ts' => gmdate('c'), 'ip' => '3.3.3.3', 'method' => 'GET', 'path' => $p, 'event' => 'llm-fake', 'served' => true, 'matched' => true]);
        }
        $d = $this->gate($s)->decide('GET', '/super-rare-app/login.asp', '3.3.3.3');
        self::assertTrue($d['generate']);
        self::assertSame('plausible', $d['reason']);
        self::assertFalse($s->isBulkFlagged('3.3.3.3'));
    }
}

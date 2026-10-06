<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Audit;

use Funnypot\App\Audit\UhqsScorecard;
use PHPUnit\Framework\TestCase;

/** FP-0352: the pure UHQS/Safety-Gate computation. */
final class UhqsScorecardTest extends TestCase
{
    private function ev(array $over = []): array
    {
        return array_merge(
            ['A' => 100.0, 'B' => 100.0, 'C' => 100.0, 'E' => 100.0, 'F' => 100.0, 'containment' => 100.0, 'unauthorized_egress_leaks' => 0],
            $over
        );
    }

    private function sc(array $over = []): array
    {
        return UhqsScorecard::compute($this->ev($over), '2026-10-06T00:00:00+00:00', 'v1');
    }

    public function test_weights_sum_to_one(): void
    {
        self::assertEqualsWithDelta(1.0, array_sum(UhqsScorecard::WEIGHTS), 1e-9);
    }

    public function test_delta_c_is_one_at_and_above_the_gate(): void
    {
        foreach ([95.0, 96.0, 100.0] as $c) {
            self::assertSame(1.0, $this->sc(['containment' => $c])['safety_gate']['delta_c'], "containment {$c}");
        }
    }

    public function test_delta_c_is_quadratic_below_the_gate(): void
    {
        self::assertEqualsWithDelta(0.8836, $this->sc(['containment' => 94.0])['safety_gate']['delta_c'], 1e-9); // .94^2
        self::assertEqualsWithDelta(0.25, $this->sc(['containment' => 50.0])['safety_gate']['delta_c'], 1e-9);    // .5^2
        self::assertSame(0.0, $this->sc(['containment' => 0.0])['safety_gate']['delta_c']);
    }

    public function test_module_d_has_no_weight_in_the_composite(): void
    {
        // F4: across the δ_C==1.0 band (containment 100→95) with A–F fixed, UHQS must be UNCHANGED —
        // Module D never enters the weighted sum; it acts only through δ_C and the gate.
        $base = $this->sc(['containment' => 100.0])['uhqs'];
        foreach ([99.0, 97.0, 95.0] as $c) {
            self::assertSame($base, $this->sc(['containment' => $c])['uhqs'], "containment {$c} must not change UHQS");
        }
    }

    public function test_full_scores_grade_a(): void
    {
        $s = $this->sc();
        self::assertSame(100.0, $s['uhqs']);
        self::assertSame('A', $s['grade']);
        self::assertTrue(UhqsScorecard::isPass($s));
    }

    public function test_weighted_composite_value(): void
    {
        // All modules 80, containment 100 → weighted 80, δ_C 1 → UHQS 80 → grade B.
        $s = $this->sc(['A' => 80.0, 'B' => 80.0, 'C' => 80.0, 'E' => 80.0, 'F' => 80.0]);
        self::assertSame(80.0, $s['uhqs']);
        self::assertSame('B', $s['grade']);
    }

    public function test_weak_containment_suppresses_and_fails(): void
    {
        // Perfect modules but containment 50 → δ_C 0.25 → UHQS 25 → grade F, gate fails.
        $s = $this->sc(['containment' => 50.0]);
        self::assertSame(25.0, $s['uhqs']);
        self::assertSame('F', $s['grade']);
        self::assertFalse(UhqsScorecard::isPass($s));
    }

    public function test_egress_leak_fails_the_gate_even_at_full_containment(): void
    {
        $s = $this->sc(['unauthorized_egress_leaks' => 1]);
        self::assertSame(1.0, $s['safety_gate']['delta_c'], 'δ_C can be 1.0...');
        self::assertFalse($s['safety_gate']['passed'], '...but any egress leak still fails the gate');
        self::assertFalse(UhqsScorecard::isPass($s));
    }

    public function test_containment_94_fails_the_gate(): void
    {
        self::assertFalse(UhqsScorecard::isPass($this->sc(['containment' => 94.0])));
    }

    public function test_grade_band_cutoffs(): void
    {
        // UHQS == weighted (δ_C 1.0 at containment 100). Hit each band floor exactly.
        $uniform = static fn (float $v): array => ['A' => $v, 'B' => $v, 'C' => $v, 'E' => $v, 'F' => $v];
        self::assertSame('A', $this->sc($uniform(90.0))['grade']);
        self::assertSame('B', $this->sc($uniform(80.0))['grade']);
        self::assertSame('C', $this->sc($uniform(70.0))['grade']);
        self::assertSame('D', $this->sc($uniform(60.0))['grade']);
        self::assertSame('F', $this->sc($uniform(59.0))['grade']);
    }

    public function test_provenance_self_labelled_internal_default(): void
    {
        $s = $this->sc();
        self::assertSame('internal-default', $s['weights_source']);
        self::assertSame('internal-default', $s['grade_source']);
    }

    public function test_absent_containment_defaults_to_failing(): void
    {
        // Fail-safe: no containment evidence => 0 => δ_C 0 => gate fails (never a fabricated pass).
        $s = UhqsScorecard::compute(['A' => 100.0, 'B' => 100.0, 'C' => 100.0, 'E' => 100.0, 'F' => 100.0, 'unauthorized_egress_leaks' => 0], 'ts', 'v1');
        self::assertFalse(UhqsScorecard::isPass($s), 'absent containment must not pass');
    }
}

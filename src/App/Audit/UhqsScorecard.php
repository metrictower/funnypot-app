<?php

declare(strict_types=1);

namespace Funnypot\App\Audit;

/**
 * FP-0352 — the UHBS/UHQS self-scorecard computation, mirrored (NOT imported) from the public
 * "Universal Honeypot Benchmarking Standard" (github.com/uhbs/uhbs-standard, Apache-2.0). We reconstruct
 * the rubric + the `scorecard.schema.json` SHAPE as our own PHP — we do not vendor their file or the PyPI
 * `uhbs` package, and we never submit externally. Internal measurement only.
 *
 * Composite:  UHQS = δ_C · (w_A·A + w_B·B + w_C·C + w_E·E + w_F·F)   — NO w_D term.
 * Module D (containment) enters ONLY through the Safety Gate:
 *   δ_C = 1.0                 if containment ≥ 95
 *   δ_C = (containment/100)²  otherwise  (weak containment quadratically suppresses everything)
 * The gate FAILS when δ_C < 1.0 (containment < 95) OR unauthorized_egress_leaks > 0.
 *
 * Pure: no I/O. {@see \scripts/scorecard.php} gathers the evidence and prints/emits the exit signal.
 */
final class UhqsScorecard
{
    public const CONTAINMENT_GATE = 95;

    /**
     * Module weights for the composite (A/B/C/E/F; D is the gate, no weight). These are an INTERNAL-DEFAULT
     * calibration summing to 1.0 — NOT the canonical UHBS weights. Recovering the canonical weights would
     * require pulling the external UHBS schema into this PUBLIC repo, which the project's clean-room /
     * mirror-not-import posture keeps to the PRIVATE ingest bench; so the scorecard self-labels its
     * `weights_source` as `internal-default` (see compute()) so an internally-calibrated UHQS is never
     * mistaken for an externally-comparable UHBS score. Stable + explicit ⇒ regression-vs-baseline is valid.
     */
    public const WEIGHTS = ['A' => 0.25, 'B' => 0.25, 'C' => 0.20, 'E' => 0.10, 'F' => 0.20];
    public const WEIGHTS_SOURCE = 'internal-default';

    /** Grade bands over UHQS (internal-default cutoffs; labeled `grade_source` for the same reason). */
    private const GRADE_BANDS = [['A', 90.0], ['B', 80.0], ['C', 70.0], ['D', 60.0]]; // else 'F'
    public const GRADE_SOURCE = 'internal-default';

    /**
     * @param array{
     *   A:float,B:float,C:float,E:float,F:float,
     *   containment:float, unauthorized_egress_leaks:int,
     *   latency?:array{p50_ms?:float,p95_ms?:float,p99_ms?:float},
     *   critical_findings?:int, high_findings?:int
     * } $ev  per-module raw scores (0–100) + Module-D containment + evidence
     * @return array<string,mixed> a scorecard.schema.json-shaped array
     */
    public static function compute(array $ev, string $generatedAt, string $version): array
    {
        $containment = self::clamp((float) ($ev['containment'] ?? 0.0));
        $leaks = max(0, (int) ($ev['unauthorized_egress_leaks'] ?? 0));

        $deltaC = $containment >= self::CONTAINMENT_GATE ? 1.0 : ($containment / 100.0) ** 2;

        $weighted = 0.0;
        foreach (self::WEIGHTS as $mod => $w) {
            $weighted += $w * self::clamp((float) ($ev[$mod] ?? 0.0));
        }
        $uhqs = round(self::clamp($deltaC * $weighted), 2); // round once so the emitted score and grade agree

        $passed = ($deltaC === 1.0) && ($leaks === 0);

        return [
            'schema' => 'uhbs/scorecard (mirrored)',
            'version' => $version,
            'generated_at' => $generatedAt,
            'weights_source' => self::WEIGHTS_SOURCE,
            'grade_source' => self::GRADE_SOURCE,
            'modules' => [
                'A' => self::clamp((float) ($ev['A'] ?? 0.0)),
                'B' => self::clamp((float) ($ev['B'] ?? 0.0)),
                'C' => self::clamp((float) ($ev['C'] ?? 0.0)),
                'D' => $containment,
                'E' => self::clamp((float) ($ev['E'] ?? 0.0)),
                'F' => self::clamp((float) ($ev['F'] ?? 0.0)),
            ],
            'latency_ms' => [
                'p50' => (float) ($ev['latency']['p50_ms'] ?? 0.0),
                'p95' => (float) ($ev['latency']['p95_ms'] ?? 0.0),
                'p99' => (float) ($ev['latency']['p99_ms'] ?? 0.0),
            ],
            'static_audit' => [
                'critical_findings' => max(0, (int) ($ev['critical_findings'] ?? 0)),
                'high_findings' => max(0, (int) ($ev['high_findings'] ?? 0)),
            ],
            'safety_gate' => [
                'containment_score' => $containment,
                'delta_c' => $deltaC,
                'unauthorized_egress_leaks' => $leaks,
                'passed' => $passed,
            ],
            'uhqs' => $uhqs,
            'grade' => self::grade($uhqs),
        ];
    }

    private static function grade(float $uhqs): string
    {
        foreach (self::GRADE_BANDS as [$letter, $floor]) {
            if ($uhqs >= $floor) {
                return $letter;
            }
        }

        return 'F';
    }

    private static function clamp(float $v): float
    {
        return max(0.0, min(100.0, $v));
    }

    /** True when the full composite + gate indicate a passing deployment (the CI green condition). */
    public static function isPass(array $scorecard): bool
    {
        return (bool) ($scorecard['safety_gate']['passed'] ?? false);
    }
}

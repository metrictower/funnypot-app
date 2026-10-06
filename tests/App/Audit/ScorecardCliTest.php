<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Audit;

use PHPUnit\Framework\TestCase;

/** FP-0352: the scorecard CLI exit-code signal + the NO-TELL guard (never a decoy route). */
final class ScorecardCliTest extends TestCase
{
    private string $script;
    private array $tmp = [];

    protected function setUp(): void
    {
        $this->script = dirname(__DIR__, 3) . '/scripts/scorecard.php';
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            @unlink($f);
        }
    }

    /** @return array{code:int,out:string} */
    private function invoke(string $args = ''): array
    {
        $out = [];
        $code = 0;
        exec('php ' . escapeshellarg($this->script) . ($args !== '' ? ' ' . $args : '') . ' 2>/dev/null', $out, $code);

        return ['code' => $code, 'out' => implode("\n", $out)];
    }

    private function evidence(array $data): string
    {
        $p = tempnam(sys_get_temp_dir(), 'fp-ev-') . '.json';
        file_put_contents($p, json_encode($data));
        $this->tmp[] = $p;

        return $p;
    }

    public function test_empty_evidence_fails_safe_exit_1(): void
    {
        $r = $this->invoke(); // no evidence -> containment 0 -> gate fails
        self::assertSame(1, $r['code']);
    }

    public function test_passing_evidence_exits_0(): void
    {
        $ev = $this->evidence(['A' => 100, 'B' => 100, 'C' => 100, 'E' => 100, 'F' => 100, 'containment' => 100, 'unauthorized_egress_leaks' => 0]);
        $r = $this->invoke('--evidence=' . escapeshellarg($ev));
        self::assertSame(0, $r['code']);
        $json = json_decode($r['out'], true);
        self::assertEquals(100.0, $json['uhqs']);
        self::assertSame('A', $json['grade']);
        self::assertTrue($json['safety_gate']['passed']);
    }

    public function test_egress_leak_exits_1(): void
    {
        $ev = $this->evidence(['A' => 100, 'B' => 100, 'C' => 100, 'E' => 100, 'F' => 100, 'containment' => 100, 'unauthorized_egress_leaks' => 1]);
        self::assertSame(1, $this->invoke('--evidence=' . escapeshellarg($ev))['code']);
    }

    public function test_weak_containment_exits_1(): void
    {
        $ev = $this->evidence(['A' => 100, 'B' => 100, 'C' => 100, 'E' => 100, 'F' => 100, 'containment' => 80, 'unauthorized_egress_leaks' => 0]);
        self::assertSame(1, $this->invoke('--evidence=' . escapeshellarg($ev))['code']);
    }

    public function test_unknown_arg_exits_2(): void
    {
        self::assertSame(2, $this->invoke('--bogus')['code']);
    }

    public function test_missing_evidence_file_exits_2(): void
    {
        self::assertSame(2, $this->invoke('--evidence=/nonexistent/nope.json')['code']);
    }

    public function test_output_is_valid_json_with_expected_shape(): void
    {
        $json = json_decode($this->invoke()['out'], true);
        self::assertIsArray($json);
        foreach (['modules', 'safety_gate', 'uhqs', 'grade', 'weights_source', 'grade_source'] as $k) {
            self::assertArrayHasKey($k, $json);
        }
        self::assertArrayHasKey('delta_c', $json['safety_gate']);
    }

    public function test_no_tell_scorecard_is_not_a_decoy_route_or_handler(): void
    {
        // A reachable /scorecard.json or /uhqs would be a decisive honeypot tell. The feature is a CLI only —
        // assert no routing/controller surface references it.
        $base = dirname(__DIR__, 3) . '/src/App/Http';
        foreach (['Router.php', 'HoneypotController.php', 'DashboardController.php'] as $f) {
            $src = (string) file_get_contents($base . '/' . $f);
            self::assertSame(0, preg_match('/scorecard|uhqs|uhbs/i', $src), "{$f} must not reference the scorecard (no decoy route/handler)");
        }
    }
}

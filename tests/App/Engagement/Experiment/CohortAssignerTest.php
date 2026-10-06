<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement\Experiment;

use Funnypot\App\Engagement\Experiment\BaselineReason;
use Funnypot\App\Engagement\Experiment\ExperimentDefinition;
use Funnypot\App\Engagement\Experiment\HmacCohortAssigner;
use PHPUnit\Framework\TestCase;

final class CohortAssignerTest extends TestCase
{
    /** @param int[] $weights */
    private function def(array $weights, int $revision = 1, string $id = 'exp-one'): ExperimentDefinition
    {
        $variants = [];
        foreach ($weights as $i => $w) {
            $letter = chr(97 + $i);
            $variants[] = ['id' => $letter, 'weight' => $w, 'implementation_id' => 'impl/' . $letter . '/v1'];
        }
        $fields = [
            'experiment_id' => $id,
            'revision' => $revision,
            'seam' => 'seam.one',
            'control_variant' => 'a',
            'variants' => $variants,
            'eligibility_version' => 'elig/v1',
            'safety_contract_version' => 'safety/v1',
        ];
        $fields['config_hash'] = strtolower(hash('sha256', json_encode($fields, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n"));

        return ExperimentDefinition::fromLedgerEntry($fields);
    }

    public function test_matches_independently_computed_vector_and_is_deterministic(): void
    {
        $key = str_repeat("\x11", 32);
        $subject = str_repeat("\x22", 32);
        $def = $this->def([1, 1]); // t=2

        // Independent recomputation of the spec §3.3 math (NOT a call into the assigner internals).
        $base = "engagement-cohort/v1\0exp-one\x00" . '1' . "\x00" . $subject;
        $digest = hash_hmac('sha256', $base, $key, true);
        $x0 = unpack('N', substr($digest, 0, 4))[1];
        $expected = ($x0 % 2) < 1 ? 'a' : 'b'; // cumulative [1,2]

        $a = new HmacCohortAssigner();
        $d1 = $a->assign($def, $key, $subject);
        $d2 = $a->assign($def, $key, $subject);
        self::assertTrue($d1->enrolled);
        self::assertSame($expected, $d1->variantId);
        self::assertSame($d1->variantId, $d2->variantId, 'deterministic for the same inputs');
        self::assertSame('exp-one', $d1->experimentId);
        self::assertSame(1, $d1->experimentRevision);
        self::assertSame($def->configHash, $d1->experimentConfigHash);
    }

    public function test_varies_by_experiment_key_and_revision(): void
    {
        $subject = str_repeat("\x33", 32);
        $def1 = $this->def([1, 1], 1);
        $def2 = $this->def([1, 1], 2); // different revision => different cohort domain input

        // Find a key where rev1 and rev2 disagree (exists with overwhelming probability).
        $a = new HmacCohortAssigner();
        $disagree = false;
        for ($i = 0; $i < 64; $i++) {
            $key = hash('sha256', 'k' . $i, true);
            if ($a->assign($def1, $key, $subject)->variantId !== $a->assign($def2, $key, $subject)->variantId) {
                $disagree = true;
                break;
            }
        }
        self::assertTrue($disagree, 'revision must change the mapping for at least some keys');
    }

    public function test_equal_weights_split_roughly_evenly_no_bias(): void
    {
        // t=3, three equal arms — the modulo-bias-prone case. Over many subjects it must stay near 1/3 each.
        $def = $this->def([1, 1, 1]);
        $key = str_repeat("\x44", 32);
        $a = new HmacCohortAssigner();
        $counts = ['a' => 0, 'b' => 0, 'c' => 0];
        $n = 3000;
        for ($i = 0; $i < $n; $i++) {
            $subject = hash('sha256', 's' . $i, true);
            $counts[$a->assign($def, $key, $subject)->variantId]++;
        }
        foreach ($counts as $arm => $c) {
            self::assertEqualsWithDelta($n / 3, $c, $n * 0.06, "arm {$arm} share off expected third: {$c}");
        }
    }

    public function test_rejects_biased_tail_then_rehashes_on_counter(): void
    {
        // t=3 => limit = floor(2^32/3)*3 = 4294967295; a word of 0xFFFFFFFF (==4294967295) is rejected.
        $def = $this->def([1, 2]); // t=3, cumulative [1,3]
        $allReject = str_repeat("\xFF", 32);       // 8 words all == 4294967295 => all rejected
        $acceptZero = "\x00\x00\x00\x00" . str_repeat("\x00", 28); // word0 == 0 => point 0 => arm 'a'

        $calls = [];
        $hmac = function (string $k, string $msg) use (&$calls, $allReject, $acceptZero): string {
            $calls[] = $msg;
            // counter 0 message has no trailing NUL+counter; counter 1 ends with "\0\x01".
            return str_ends_with($msg, "\x00\x01") ? $acceptZero : $allReject;
        };
        $a = new HmacCohortAssigner($hmac);
        $d = $a->assign($def, 'key', 'subject');
        self::assertTrue($d->enrolled);
        self::assertSame('a', $d->variantId);
        self::assertGreaterThanOrEqual(2, count($calls), 'must have re-hashed with a counter after all 8 words rejected');
    }

    public function test_exhaustion_returns_unenrolled_baseline(): void
    {
        $def = $this->def([1, 2]); // t=3
        $allReject = str_repeat("\xFF", 32);
        $a = new HmacCohortAssigner(static fn (string $k, string $m): string => $allReject);
        $d = $a->assign($def, 'key', 'subject');
        self::assertFalse($d->enrolled);
        self::assertSame(BaselineReason::SAMPLING_EXHAUSTED, $d->reason);
        self::assertNull($d->experimentId, 'a baseline decision carries no experiment fields');
        self::assertNull($d->variantId);
    }

    public function test_cumulative_boundaries(): void
    {
        $def = $this->def([1, 2]); // t=3, cumulative [1,3]: point 0 => a; points 1,2 => b
        foreach ([0 => 'a', 1 => 'b', 2 => 'b'] as $point => $expected) {
            $word = pack('N', $point); // first word == $point (< limit)
            $digest = $word . str_repeat("\x00", 28);
            $a = new HmacCohortAssigner(static fn (string $k, string $m): string => $digest);
            self::assertSame($expected, $a->assign($def, 'k', 's')->variantId, "point {$point}");
        }
    }

    public function test_subject_key_is_domain_separated_and_keyed(): void
    {
        $key = str_repeat("\x55", 32);
        $rand = str_repeat("\x66", 16);
        $sk = HmacCohortAssigner::subjectKey($key, $rand);
        self::assertSame(32, strlen($sk));
        self::assertSame($sk, HmacCohortAssigner::subjectKey($key, $rand), 'deterministic');
        // Different domain prefix (cohort) over the same bytes must not collide with the subject derivation.
        self::assertNotSame($sk, hash_hmac('sha256', "engagement-cohort/v1\0" . $rand, $key, true));
        // Keyed: a different experiment key yields a different subject key.
        self::assertNotSame($sk, HmacCohortAssigner::subjectKey(str_repeat("\x56", 32), $rand));
    }
}

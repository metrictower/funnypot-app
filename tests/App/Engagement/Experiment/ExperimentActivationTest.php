<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement\Experiment;

use Funnypot\App\Engagement\Experiment\ExperimentActivation;
use Funnypot\App\Engagement\Experiment\ExperimentRegistry;
use PHPUnit\Framework\TestCase;

final class ExperimentActivationTest extends TestCase
{
    private function registry(): ExperimentRegistry
    {
        // Two definitions on DIFFERENT seams, each with two revisions available in the registry.
        return ExperimentRegistry::fromLedgerArray([
            ExperimentRegistryTest::entry(['experiment_id' => 'exp-one', 'revision' => 1, 'seam' => 'seam.one']),
            ExperimentRegistryTest::entry(['experiment_id' => 'exp-one', 'revision' => 2, 'seam' => 'seam.one']),
            ExperimentRegistryTest::entry(['experiment_id' => 'exp-two', 'revision' => 1, 'seam' => 'seam.two']),
        ]);
    }

    public function test_empty_string_is_disabled_without_an_error_reason(): void
    {
        $act = ExperimentActivation::resolve('', $this->registry());
        self::assertTrue($act->isEmpty());
        self::assertNull($act->healthReason(), 'empty is the normal disabled state, not an error');
    }

    public function test_valid_tuple_activates(): void
    {
        $act = ExperimentActivation::resolve('exp-one@1', $this->registry());
        self::assertFalse($act->isEmpty());
        self::assertNull($act->healthReason());
        self::assertNotNull($act->activeForSeam('seam.one'));
        self::assertSame('exp-one', $act->activeForSeam('seam.one')->experimentId);
        self::assertNull($act->activeForSeam('seam.two'));
    }

    public function test_two_tuples_on_distinct_seams_activate(): void
    {
        $act = ExperimentActivation::resolve('exp-one@1,exp-two@1', $this->registry());
        self::assertNotNull($act->activeForSeam('seam.one'));
        self::assertNotNull($act->activeForSeam('seam.two'));
        self::assertNull($act->healthReason());
    }

    public function test_two_revisions_on_one_seam_activate_nothing(): void
    {
        $act = ExperimentActivation::resolve('exp-one@1,exp-one@2', $this->registry());
        self::assertTrue($act->isEmpty());
        self::assertSame('seam_conflict', $act->healthReason());
    }

    public function test_unknown_tuple_activates_nothing(): void
    {
        $act = ExperimentActivation::resolve('exp-one@1,ghost@9', $this->registry());
        self::assertTrue($act->isEmpty(), 'whole-set validation: one unknown tuple disables all');
        self::assertSame('unknown_tuple', $act->healthReason());
    }

    public function test_duplicate_and_malformed_and_oversize(): void
    {
        $reg = $this->registry();
        self::assertSame('duplicate_tuple', ExperimentActivation::resolve('exp-one@1,exp-one@1', $reg)->healthReason());
        self::assertSame('malformed_tuple', ExperimentActivation::resolve('exp-one@1, exp-two@1', $reg)->healthReason(), 'whitespace is not allowed');
        self::assertSame('malformed_tuple', ExperimentActivation::resolve('exp-one@01', $reg)->healthReason(), 'leading-zero revision rejected');
        self::assertSame('activation_too_large', ExperimentActivation::resolve(str_repeat('a', 1025), $reg)->healthReason());
    }

    public function test_faulted_registry_activates_nothing(): void
    {
        $faulted = ExperimentRegistry::fromLedgerArray([
            ExperimentRegistryTest::entry(),
            ExperimentRegistryTest::entry(), // duplicate tuple -> faulted
        ]);
        $act = ExperimentActivation::resolve('exp-one@1', $faulted);
        self::assertTrue($act->isEmpty());
        self::assertSame('registry_faulted', $act->healthReason());
    }

    public function test_more_than_16_tuples_activate_nothing(): void
    {
        $tuples = [];
        for ($i = 0; $i < 17; $i++) {
            $tuples[] = 'e' . $i . '@1';
        }
        $act = ExperimentActivation::resolve(implode(',', $tuples), $this->registry());
        self::assertSame('too_many_entries', $act->healthReason());
    }
}

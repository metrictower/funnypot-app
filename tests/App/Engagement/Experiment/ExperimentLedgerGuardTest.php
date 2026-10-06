<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement\Experiment;

use PHPUnit\Framework\TestCase;

final class ExperimentLedgerGuardTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/../../../../tools/check-experiment-ledger.php';
    }

    private function ledger(array $tuples): string
    {
        $experiments = [];
        foreach ($tuples as $t) {
            $experiments[] = [
                'experiment_id' => $t[0],
                'revision' => $t[1],
                'seam' => 'seam.' . $t[0],
                'control_variant' => 'a',
                'variants' => [
                    ['id' => 'a', 'weight' => 1, 'implementation_id' => 'impl/a/v1'],
                    ['id' => 'b', 'weight' => $t[2] ?? 1, 'implementation_id' => 'impl/b/v1'],
                ],
                'eligibility_version' => 'elig/v1',
                'safety_contract_version' => 'safety/v1',
                'config_hash' => str_repeat('0', 64),
            ];
        }

        return json_encode(['experiments' => $experiments], JSON_UNESCAPED_SLASHES);
    }

    public function test_pure_append_passes(): void
    {
        $base = $this->ledger([['exp-one', 1]]);
        $current = $this->ledger([['exp-one', 1], ['exp-two', 1]]);
        self::assertTrue(experiment_ledger_append_ok($base, $current)['ok']);
    }

    public function test_identical_passes(): void
    {
        $base = $this->ledger([['exp-one', 1]]);
        self::assertTrue(experiment_ledger_append_ok($base, $base)['ok']);
    }

    public function test_mutation_of_existing_tuple_fails(): void
    {
        $base = $this->ledger([['exp-one', 1, 1]]);
        $current = $this->ledger([['exp-one', 1, 5]]); // weight changed
        self::assertFalse(experiment_ledger_append_ok($base, $current)['ok']);
    }

    public function test_deletion_fails(): void
    {
        $base = $this->ledger([['exp-one', 1], ['exp-two', 1]]);
        $current = $this->ledger([['exp-one', 1]]);
        self::assertFalse(experiment_ledger_append_ok($base, $current)['ok']);
    }

    public function test_reorder_fails(): void
    {
        $base = $this->ledger([['exp-one', 1], ['exp-two', 1]]);
        $current = $this->ledger([['exp-two', 1], ['exp-one', 1]]);
        self::assertFalse(experiment_ledger_append_ok($base, $current)['ok']);
    }

    public function test_tuple_reuse_in_append_fails(): void
    {
        $base = $this->ledger([['exp-one', 1]]);
        $current = $this->ledger([['exp-one', 1], ['exp-one', 1]]);
        self::assertFalse(experiment_ledger_append_ok($base, $current)['ok']);
    }

    public function test_unreadable_base_fails_closed(): void
    {
        self::assertFalse(experiment_ledger_append_ok(null, $this->ledger([['exp-one', 1]]))['ok']);
    }

    public function test_invalid_json_fails_closed(): void
    {
        self::assertFalse(experiment_ledger_append_ok('{not json', $this->ledger([['exp-one', 1]]))['ok']);
        self::assertFalse(experiment_ledger_append_ok($this->ledger([['exp-one', 1]]), 'nope')['ok']);
    }
}

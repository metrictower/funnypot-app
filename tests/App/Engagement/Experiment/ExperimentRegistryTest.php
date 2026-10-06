<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement\Experiment;

use Funnypot\App\Engagement\Experiment\ExperimentDefinition;
use Funnypot\App\Engagement\Experiment\ExperimentRegistry;
use PHPUnit\Framework\TestCase;

final class ExperimentRegistryTest extends TestCase
{
    private const LEDGER = __DIR__ . '/../../../../resources/experiments/engagement-revisions.json';

    /** @param array<string,mixed> $overrides */
    public static function entry(array $overrides = []): array
    {
        $fields = [
            'experiment_id' => 'exp-one',
            'revision' => 1,
            'seam' => 'seam.one',
            'control_variant' => 'a',
            'variants' => [
                ['id' => 'a', 'weight' => 1, 'implementation_id' => 'impl/a/v1'],
                ['id' => 'b', 'weight' => 1, 'implementation_id' => 'impl/b/v1'],
            ],
            'eligibility_version' => 'elig/v1',
            'safety_contract_version' => 'safety/v1',
        ];
        $fields = array_merge($fields, $overrides);
        // Compute the correct canonical hash so a VALID entry round-trips (mirrors canonicalBytes order).
        $canon = json_encode($fields, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
        $fields['config_hash'] = strtolower(hash('sha256', $canon));

        return $fields;
    }

    public function test_real_ledger_loads_and_hash_verifies_end_to_end(): void
    {
        $r = ExperimentRegistry::fromLedgerFile(self::LEDGER);
        self::assertFalse($r->faulted(), 'committed ledger must load and every config_hash must verify');
        $def = $r->definition('labyrinth-export-links@1');
        self::assertInstanceOf(ExperimentDefinition::class, $def);
        self::assertSame('labyrinth.navigation', $def->seam);
        self::assertSame('current-links', $def->controlVariant);
        self::assertCount(2, $def->variants);
        self::assertSame(2, $def->totalWeight());
    }

    public function test_canonical_bytes_are_the_documented_fixed_form(): void
    {
        $def = ExperimentDefinition::fromLedgerEntry(self::entry());
        $expected = '{"experiment_id":"exp-one","revision":1,"seam":"seam.one","control_variant":"a",'
            . '"variants":[{"id":"a","weight":1,"implementation_id":"impl/a/v1"},'
            . '{"id":"b","weight":1,"implementation_id":"impl/b/v1"}],'
            . '"eligibility_version":"elig/v1","safety_contract_version":"safety/v1"}' . "\n";
        self::assertSame($expected, $def->canonicalBytes());
        self::assertSame($def->expectedHash(), $def->configHash);
    }

    public function test_valid_entry_round_trips(): void
    {
        $r = ExperimentRegistry::fromLedgerArray([self::entry()]);
        self::assertFalse($r->faulted());
        self::assertNotNull($r->definition('exp-one@1'));
    }

    public function test_hash_mismatch_drops_the_definition(): void
    {
        $e = self::entry();
        $e['config_hash'] = str_repeat('a', 64); // wrong
        $r = ExperimentRegistry::fromLedgerArray([$e]);
        self::assertNull($r->definition('exp-one@1'), 'a tampered hash must drop the definition');
    }

    public function test_tampered_semantic_field_fails_hash(): void
    {
        $e = self::entry();
        // Flip a weight WITHOUT recomputing the hash — canonical bytes now differ from the stored hash.
        $e['variants'][0]['weight'] = 9;
        $r = ExperimentRegistry::fromLedgerArray([$e]);
        self::assertNull($r->definition('exp-one@1'));
    }

    public function test_unsupported_key_drops_the_definition(): void
    {
        $e = self::entry(['extra' => 'nope']);
        $r = ExperimentRegistry::fromLedgerArray([$e]);
        self::assertNull($r->definition('exp-one@1'));
    }

    public function test_absent_control_drops_the_definition(): void
    {
        $e = self::entry(['control_variant' => 'zzz']);
        $r = ExperimentRegistry::fromLedgerArray([$e]);
        self::assertNull($r->definition('exp-one@1'));
    }

    public function test_grammar_and_range_violations_drop(): void
    {
        foreach ([
            ['experiment_id' => 'Bad_Upper'],
            ['revision' => 0],
            ['variants' => [['id' => 'a', 'weight' => 0, 'implementation_id' => 'x/v1'], ['id' => 'b', 'weight' => 1, 'implementation_id' => 'y/v1']]],
            ['variants' => [['id' => 'a', 'weight' => 1, 'implementation_id' => 'x/v1']]], // only 1 variant
        ] as $bad) {
            $r = ExperimentRegistry::fromLedgerArray([self::entry($bad)]);
            self::assertTrue($r->definition('exp-one@1') === null, 'bad entry must be dropped: ' . json_encode($bad));
        }
    }

    public function test_duplicate_tuple_faults_the_registry(): void
    {
        $r = ExperimentRegistry::fromLedgerArray([self::entry(), self::entry()]);
        self::assertTrue($r->faulted(), 'a duplicate tuple must fail closed');
    }

    public function test_more_than_16_entries_faults(): void
    {
        $entries = [];
        for ($i = 0; $i < 17; $i++) {
            $entries[] = self::entry(['experiment_id' => 'exp-' . $i]);
        }
        $r = ExperimentRegistry::fromLedgerArray($entries);
        self::assertTrue($r->faulted());
    }

    public function test_missing_file_faults_closed(): void
    {
        $r = ExperimentRegistry::fromLedgerFile(__DIR__ . '/does-not-exist.json');
        self::assertTrue($r->faulted());
    }
}

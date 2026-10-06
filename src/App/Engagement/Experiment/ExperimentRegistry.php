<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * The closed set of valid experiment definitions loaded from the committed append-only ledger
 * (FP-0311 §2.1/§2.2). A single malformed entry is dropped; a structural fault (more than 16 valid
 * definitions, a duplicate tuple, or an unreadable/invalid ledger) faults the whole registry so that
 * activation resolves to nothing — fail closed. Exposes only typed definitions, never a loose array.
 */
final class ExperimentRegistry
{
    private const MAX_DEFINITIONS = 16;

    /** @param array<string,ExperimentDefinition> $byTuple keyed by "id@revision" */
    private function __construct(
        private readonly array $byTuple,
        private readonly bool $faulted
    ) {
    }

    /** Load from the ledger file. A read/JSON fault yields a faulted (empty) registry — fail closed. */
    public static function fromLedgerFile(string $path): self
    {
        if (!is_file($path) || !is_readable($path)) {
            return self::faultedRegistry();
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return self::faultedRegistry();
        }
        try {
            $doc = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::faultedRegistry();
        }
        if (!is_array($doc) || !isset($doc['experiments']) || !is_array($doc['experiments'])) {
            return self::faultedRegistry();
        }

        return self::fromLedgerArray($doc['experiments']);
    }

    /**
     * @param array<int,mixed> $entries decoded ledger entries (each the §2.1 fields + config_hash)
     */
    public static function fromLedgerArray(array $entries): self
    {
        if (!array_is_list($entries) || count($entries) > self::MAX_DEFINITIONS) {
            return self::faultedRegistry(); // more tuples than the hard cap — fail closed
        }

        $byTuple = [];
        foreach ($entries as $entry) {
            if (!is_array($entry)) {
                return self::faultedRegistry();
            }
            try {
                $def = ExperimentDefinition::fromLedgerEntry($entry);
            } catch (InvalidExperimentException) {
                // A single malformed definition is dropped, not fatal.
                continue;
            }
            if (isset($byTuple[$def->tuple()])) {
                return self::faultedRegistry(); // duplicate tuple — fail closed
            }
            $byTuple[$def->tuple()] = $def;
        }

        return new self($byTuple, false);
    }

    public function faulted(): bool
    {
        return $this->faulted;
    }

    public function definition(string $tuple): ?ExperimentDefinition
    {
        return $this->byTuple[$tuple] ?? null;
    }

    /** @return array<string,ExperimentDefinition> keyed by tuple */
    public function all(): array
    {
        return $this->byTuple;
    }

    private static function faultedRegistry(): self
    {
        return new self([], true);
    }
}

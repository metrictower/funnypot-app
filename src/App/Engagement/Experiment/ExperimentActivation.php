<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * Resolves the operator activation string (FP-0311 §2.3) against the closed registry into the set of
 * active definitions, at most one per seam. The ONLY operator input: a comma-separated list of exact
 * `experiment_id@decimal_revision` tuples, max 1024 bytes, no whitespace aliases. It can enable a
 * reviewed tuple but can never supply variants, weights, hashes, implementation ids, keys or a cohort.
 *
 * Validate-whole-then-resolve: the entire set is parsed and checked first; an unknown/duplicate/malformed
 * tuple, more than 16 entries, two active revisions on one seam, or a faulted registry activates NOTHING
 * and records one bounded health reason. An empty string is the normal disabled state (no reason).
 */
final class ExperimentActivation
{
    private const MAX_BYTES = 1024;
    private const MAX_ENTRIES = 16;
    private const TUPLE_RX = '/^[a-z][a-z0-9._-]{0,47}@[1-9][0-9]{0,9}$/';

    /** @param array<string,ExperimentDefinition> $bySeam at most one active definition per seam */
    private function __construct(
        private readonly array $bySeam,
        private readonly ?string $healthReason
    ) {
    }

    public static function resolve(string $raw, ExperimentRegistry $registry): self
    {
        if ($raw === '') {
            return new self([], null); // disabled: the normal state, not an error
        }
        if (strlen($raw) > self::MAX_BYTES) {
            return self::disabled('activation_too_large');
        }
        if ($registry->faulted()) {
            return self::disabled('registry_faulted');
        }

        $tokens = explode(',', $raw);
        if (count($tokens) > self::MAX_ENTRIES) {
            return self::disabled('too_many_entries');
        }

        $seen = [];
        $defs = [];
        $bySeam = [];
        foreach ($tokens as $tok) {
            if (preg_match(self::TUPLE_RX, $tok) !== 1) {
                return self::disabled('malformed_tuple');
            }
            if (isset($seen[$tok])) {
                return self::disabled('duplicate_tuple');
            }
            $seen[$tok] = true;

            $def = $registry->definition($tok);
            if ($def === null) {
                return self::disabled('unknown_tuple');
            }
            if (isset($bySeam[$def->seam])) {
                return self::disabled('seam_conflict'); // two active revisions on one seam
            }
            $bySeam[$def->seam] = $def;
            $defs[] = $def;
        }

        return new self($bySeam, null);
    }

    public function activeForSeam(string $seam): ?ExperimentDefinition
    {
        return $this->bySeam[$seam] ?? null;
    }

    public function isEmpty(): bool
    {
        return $this->bySeam === [];
    }

    /** One bounded reason the set resolved to nothing due to an ERROR (null when legitimately empty). */
    public function healthReason(): ?string
    {
        return $this->healthReason;
    }

    private static function disabled(string $reason): self
    {
        return new self([], $reason);
    }
}

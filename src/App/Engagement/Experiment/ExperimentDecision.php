<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * The outcome of an assignment attempt (FP-0311 §3.3). Either:
 *  - enrolled: a valid active tuple + eligible subject + a computed variant — carries the four
 *    persistence fields (id, revision, config_hash, variant_id) FP-0308 records; or
 *  - baseline: current behaviour with exactly one internal BaselineReason and NO experiment fields.
 *
 * The caller selects the implementation id to render: the enrolled variant's, or — for baseline — the
 * definition's control implementation when one is known, else its own current default. Immutable.
 */
final class ExperimentDecision
{
    private function __construct(
        public readonly bool $enrolled,
        public readonly ?string $experimentId,
        public readonly ?int $experimentRevision,
        public readonly ?string $experimentConfigHash,
        public readonly ?string $variantId,
        public readonly ?string $implementationId,
        public readonly ?BaselineReason $reason
    ) {
    }

    public static function enrolled(ExperimentDefinition $def, ExperimentVariant $variant): self
    {
        return new self(
            true,
            $def->experimentId,
            $def->revision,
            $def->configHash,
            $variant->id,
            $variant->implementationId,
            null
        );
    }

    public static function baseline(BaselineReason $reason): self
    {
        return new self(false, null, null, null, null, null, $reason);
    }
}

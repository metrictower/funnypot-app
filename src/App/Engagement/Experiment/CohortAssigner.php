<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * Deterministically maps a verified subject to a variant of an active definition (FP-0311 §3.3). The
 * method signature deliberately admits ONLY the scoped experiment key and the derived subject key —
 * never IP/UA/attribution/geo/known_attacker, a database episode id, a lure/artifact id, analytics
 * state, or any attacker-provided string. Those cannot influence assignment because they are not here.
 */
interface CohortAssigner
{
    public function assign(ExperimentDefinition $definition, string $experimentKey, string $subjectKey): ExperimentDecision;
}

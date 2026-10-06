<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * The bounded, fixed set of reasons an assignment fell back to current baseline (FP-0311 §3.3). A
 * baseline decision carries exactly one of these and NO experiment fields, so a disabled/missing/faulted
 * fallback never pollutes the control denominator. Internal only — never emitted in a served response.
 */
enum BaselineReason: string
{
    case NOT_ACTIVE = 'not_active';            // no active definition for the seam
    case NO_SUBJECT = 'no_subject';            // no eligible verified subject present
    case PLATFORM_UNSUPPORTED = 'platform';    // PHP_INT_SIZE !== 8 (exact unsigned range unavailable)
    case SAMPLING_EXHAUSTED = 'sampling';      // all rejection-sampling words rejected
    case ASSIGNER_FAULT = 'fault';             // an unexpected assigner error
}

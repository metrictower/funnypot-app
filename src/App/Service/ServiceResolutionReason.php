<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * Stable reason codes for every resolver rejection, warning and pending state. They are part of the
 * admin/preview contract: the UI shows exact ids and reasons, never a bare boolean.
 */
final class ServiceResolutionReason
{
    // hard rejections
    public const MODE_INVALID = 'mode-invalid';
    public const INPUT_MALFORMED = 'input-malformed';
    public const INPUT_TOO_LARGE = 'input-too-large';
    public const BUNDLE_UNKNOWN = 'bundle-unknown';
    public const BASE_FAMILY_MISSING = 'base-family-missing';
    public const BASE_FAMILY_UNKNOWN = 'base-family-unknown';
    public const SERVICE_UNKNOWN = 'service-unknown';
    public const NON_SELECTABLE_ID = 'service-not-selectable';
    public const DUPLICATE_ID = 'duplicate-service-id';
    public const MISSING_COMPANION = 'missing-companion';
    public const CAPABILITY_MISSING = 'capability-missing';
    public const EXCLUSION_CONFLICT = 'exclusion-conflict';
    public const UNDECLARED_COLLISION = 'undeclared-collision';
    public const CONFLICT_VARIANT_MISSING = 'conflict-variant-missing';
    public const CONFLICT_VARIANT_INVALID = 'conflict-variant-invalid';
    public const UDP_UNSAFE = 'udp-unsafe';
    public const PROCESS_CEILING = 'process-ceiling-exceeded';
    public const BUDGET_BELOW_REQUIRED = 'budget-below-required';
    public const PROTOCOLS_DISABLED = 'protocols-disabled';
    public const ALLOWED_IDS_VIOLATION = 'allowed-ids-violation';
    public const MAX_EXPOSURE_CEILING = 'max-exposure-ceiling-exceeded';
    public const BUNDLE_INELIGIBLE = 'bundle-ineligible';

    // soft warnings (never a rejection)
    public const FAMILY_COHERENCE = 'family-coherence-warning';
    public const HIGH_FINGERPRINT_ALL = 'high-fingerprint-all-mode';

    // pending states (published/nginx gap)
    public const RESTART_REQUIRED = 'restart-required';
    public const REDEPLOY_REQUIRED = 'redeploy-required';

    private function __construct()
    {
    }
}

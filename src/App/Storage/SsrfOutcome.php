<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Ssrf\SsrfState;

/**
 * What an SSRF-store transaction body decided: the state to write (null leaves the row alone), whether
 * it is a state change (counted against the write caps), the units to charge and the value to return.
 */
final class SsrfOutcome
{
    public function __construct(
        public readonly ?SsrfState $state,
        public readonly bool $stateChange,
        public readonly int $units,
        public readonly mixed $value,
    ) {
    }
}

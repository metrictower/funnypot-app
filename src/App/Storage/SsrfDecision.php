<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Ssrf\SsrfState;

/**
 * The decision an SSRF-store transaction runs, between loading the rows and writing them. A method on a
 * named type rather than a closure, so the SSRF namespace never makes an indirect call.
 */
interface SsrfDecision
{
    public function decide(?SsrfState $state, SsrfTx $tx): SsrfOutcome;
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Closure;
use Funnypot\App\Storage\SsrfDecision;
use Funnypot\App\Storage\SsrfOutcome;
use Funnypot\App\Storage\SsrfTx;
use Funnypot\App\Tarpit\Ssrf\SsrfState;

/** A test-only decision that runs a closure (the SSRF namespace itself never calls one). */
final class ClosureDecision implements SsrfDecision
{
    public function __construct(private Closure $fn)
    {
    }

    public function decide(?SsrfState $state, SsrfTx $tx): SsrfOutcome
    {
        return ($this->fn)($state, $tx);
    }
}

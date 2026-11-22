<?php

declare(strict_types=1);

// expect: output: echo
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_echo(): void
{
    echo "x";
}

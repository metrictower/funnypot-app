<?php

declare(strict_types=1);

// expect: include
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_include(): void
{
    include $x;
}

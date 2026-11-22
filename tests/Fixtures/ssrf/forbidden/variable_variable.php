<?php

declare(strict_types=1);

// expect: variable_variable
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_variable_variable(): void
{
    $a = "b"; $$a = 1;
}

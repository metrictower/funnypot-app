<?php

declare(strict_types=1);

// expect: variable_call
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_variable_call(): void
{
    $f = "system"; $f("id");
}

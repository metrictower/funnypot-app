<?php

declare(strict_types=1);

// expect: variable_method
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_variable_method(): void
{
    $o = new \stdClass(); $m = "x"; $o->$m();
}

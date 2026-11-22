<?php

declare(strict_types=1);

// expect: dynamic_call: array element
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_array_element_call(): void
{
    $fns = ['x' => 'shell_exec']; $fns['x']('id');
}

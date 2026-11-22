<?php

declare(strict_types=1);

// expect: dynamic_call: string literal
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_string_literal_call(): void
{
    'shell_exec'('id');
}

<?php

declare(strict_types=1);

// expect: function: call_user_func
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_call_user_func(): void
{
    call_user_func("system", "id");
}

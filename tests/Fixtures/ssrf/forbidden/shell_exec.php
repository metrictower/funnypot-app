<?php

declare(strict_types=1);

// expect: function: shell_exec
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_shell_exec(): void
{
    shell_exec("id");
}

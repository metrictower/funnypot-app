<?php

declare(strict_types=1);

// expect: function: proc_open
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_proc_open(): void
{
    $p = proc_open(["id"], [], $pipes);
}

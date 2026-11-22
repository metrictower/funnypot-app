<?php

declare(strict_types=1);

// expect: new: mysqli
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_new_mysqli(): void
{
    new \mysqli("x.invalid");
}

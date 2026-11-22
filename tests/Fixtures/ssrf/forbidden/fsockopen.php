<?php

declare(strict_types=1);

// expect: function: fsockopen
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_fsockopen(): void
{
    fsockopen("x.invalid", 80);
}

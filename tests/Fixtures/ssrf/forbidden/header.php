<?php

declare(strict_types=1);

// expect: function: header
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_header(): void
{
    header("X-A: b");
}

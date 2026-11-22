<?php

declare(strict_types=1);

// expect: function: gethostbyname
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_gethostbyname(): void
{
    gethostbyname("x.invalid");
}

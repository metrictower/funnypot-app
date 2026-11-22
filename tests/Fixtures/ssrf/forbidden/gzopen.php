<?php

declare(strict_types=1);

// expect: function: gzopen
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_gzopen(): void
{
    gzopen("http://x.invalid/", "r");
}

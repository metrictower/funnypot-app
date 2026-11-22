<?php

declare(strict_types=1);

// expect: eval
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_eval(): void
{
    eval("return 1;");
}

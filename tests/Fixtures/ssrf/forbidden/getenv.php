<?php

declare(strict_types=1);

// expect: function: getenv
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_getenv(): void
{
    getenv("HOME");
}

<?php

declare(strict_types=1);

// expect: backtick
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_backtick(): void
{
    $x = `id`;
}

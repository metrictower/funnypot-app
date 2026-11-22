<?php

declare(strict_types=1);

// expect: function: random_bytes
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_random_bytes(): void
{
    $r = random_bytes(4);
}

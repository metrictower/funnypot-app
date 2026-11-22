<?php

declare(strict_types=1);

// expect: string_callable: array_map
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_string_callable(): void
{
    array_map("file", ["http://x.invalid/"]);
}

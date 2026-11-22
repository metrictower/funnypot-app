<?php

declare(strict_types=1);

// expect: function: file_get_contents
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_file_get_contents(): void
{
    file_get_contents("http://x.invalid/");
}

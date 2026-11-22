<?php

declare(strict_types=1);

// expect: variable_static
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_variable_static(): void
{
    $m = "open"; \Funnypot\App\Storage\Sqlite::$m("x");
}

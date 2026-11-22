<?php

declare(strict_types=1);

// expect: error_log_type
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_error_log_type1(): void
{
    error_log("m", 1, "a@x.invalid");
}

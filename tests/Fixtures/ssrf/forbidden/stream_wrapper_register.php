<?php

declare(strict_types=1);

// expect: function: stream_wrapper_register
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_stream_wrapper_register(): void
{
    stream_wrapper_register("x", "Y");
}

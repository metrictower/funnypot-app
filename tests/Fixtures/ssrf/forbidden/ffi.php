<?php

declare(strict_types=1);

// expect: static: FFI::cdef
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_ffi(): void
{
    \FFI::cdef("int x;");
}

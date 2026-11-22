<?php

declare(strict_types=1);

// expect: function: ftp_connect
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_ftp_connect(): void
{
    ftp_connect("x.invalid");
}

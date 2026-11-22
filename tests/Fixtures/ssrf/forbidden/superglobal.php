<?php

declare(strict_types=1);

// expect: superglobal: $_SERVER
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_superglobal(): void
{
    $x = $_SERVER["REMOTE_ADDR"];
}

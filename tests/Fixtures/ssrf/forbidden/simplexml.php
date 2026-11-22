<?php

declare(strict_types=1);

// expect: function: simplexml_load_file
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_simplexml(): void
{
    simplexml_load_file("http://x.invalid/");
}

<?php

declare(strict_types=1);

// expect: function: curl_init
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_curl_init(): void
{
    curl_init("http://x.invalid/");
}

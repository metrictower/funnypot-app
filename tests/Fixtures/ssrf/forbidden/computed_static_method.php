<?php

declare(strict_types=1);

// expect: dynamic_call: computed static method
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_computed_static_method(): void
{
    $f = \Closure::{'fromCallable'}('curl_init'); $f->__invoke('x');
}

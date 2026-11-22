<?php

declare(strict_types=1);

// expect: string_callable: Foo::bar
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_static_string_callable(): void
{
    \Funnypot\App\Tarpit\Ssrf\SsrfKeys::x('Foo::bar');
}

<?php

declare(strict_types=1);

// expect: array_callable
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_array_callable_lowercase_class(): void
{
    $o = new \stdClass();
    $o->register(['closure', 'fromCallable']);
}

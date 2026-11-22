<?php

declare(strict_types=1);

// expect: new: SplFileObject
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_splfileobject(): void
{
    new \SplFileObject("http://x.invalid/");
}

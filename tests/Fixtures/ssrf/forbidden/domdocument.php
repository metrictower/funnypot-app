<?php

declare(strict_types=1);

// expect: new: DOMDocument
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_domdocument(): void
{
    (new \DOMDocument())->load("http://x.invalid/");
}

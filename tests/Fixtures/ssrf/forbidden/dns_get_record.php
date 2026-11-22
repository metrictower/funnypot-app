<?php

declare(strict_types=1);

// expect: function: dns_get_record
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_dns_get_record(): void
{
    dns_get_record("x.invalid");
}

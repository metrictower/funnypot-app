<?php

declare(strict_types=1);

// expect: function: ldap_connect
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_ldap_connect(): void
{
    ldap_connect("x.invalid");
}

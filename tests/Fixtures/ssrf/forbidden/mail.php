<?php

declare(strict_types=1);

// expect: function: mail
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_mail(): void
{
    mail("a@x.invalid", "s", "b");
}

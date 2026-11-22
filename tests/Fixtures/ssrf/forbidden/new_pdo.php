<?php

declare(strict_types=1);

// expect: new: PDO
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_new_pdo(): void
{
    new \PDO("mysql:host=x.invalid");
}

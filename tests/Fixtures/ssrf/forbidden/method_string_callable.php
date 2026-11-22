<?php

declare(strict_types=1);

// expect: string_callable: shell_exec
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_method_string_callable(): void
{
    $db = \Funnypot\App\Storage\Sqlite::open('x'); $db->sqliteCreateFunction('f', 'shell_exec');
}

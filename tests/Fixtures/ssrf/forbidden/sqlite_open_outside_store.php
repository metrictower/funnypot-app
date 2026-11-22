<?php

declare(strict_types=1);

// expect: static: Funnypot\App\Storage\Sqlite::open outside the store
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_sqlite_open_outside_store(): void
{
    \Funnypot\App\Storage\Sqlite::open("/tmp/x.sqlite");
}

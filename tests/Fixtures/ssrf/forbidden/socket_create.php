<?php

declare(strict_types=1);

// expect: function: socket_create
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_socket_create(): void
{
    socket_create(AF_INET, SOCK_STREAM, 0);
}

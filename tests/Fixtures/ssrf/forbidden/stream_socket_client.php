<?php

declare(strict_types=1);

// expect: function: stream_socket_client
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_stream_socket_client(): void
{
    stream_socket_client("tcp://x.invalid:80");
}

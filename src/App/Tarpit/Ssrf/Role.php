<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/** The platform's three fetch workers. Each has its own egress allowlist. */
enum Role: string
{
    case Hook = 'hook';
    case Import = 'import';
    case Storage = 'storage';
}

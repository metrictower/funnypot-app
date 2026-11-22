<?php

declare(strict_types=1);

// expect: array_callable
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

final class ArrayCallableThis
{
    public function f(): void
    {
        $this->register([self::class, 'g'], [$this, 'g']);
    }
}

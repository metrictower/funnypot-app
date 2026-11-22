<?php

declare(strict_types=1);

// Census positive control: a key-shaped literal split across a concatenation still counts as one.
// Never autoloaded or executed.

namespace Funnypot\Tests\Fixtures\Ssrf\Census;

final class SplitKeyLiteral
{
    public const KEY = 'AK' . 'IAQ3EGRMPLX7CENSUS1';
}

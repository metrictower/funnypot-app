<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use RuntimeException;

/** A path past Linux's limits (a component over 255 bytes, or over 4096 bytes in all): ENAMETOOLONG. */
final class NameTooLong extends RuntimeException
{
    public function __construct(public readonly string $typed)
    {
        parent::__construct('File name too long');
    }
}

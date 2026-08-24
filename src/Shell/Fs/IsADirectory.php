<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/** read() on a directory. Distinct from PathNotFound so callers render the right bash error. */
final class IsADirectory extends \RuntimeException
{
    public static function for(string $path): self
    {
        return new self($path);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/** The single "path does not exist" error. Callers render bash-standard text; path is carried for logging. */
final class PathNotFound extends \RuntimeException
{
    public static function for(string $path): self
    {
        return new self($path);
    }
}

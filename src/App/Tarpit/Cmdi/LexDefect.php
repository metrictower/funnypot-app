<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use RuntimeException;

/** A real parse error: the {@see AshVocabulary} message id and the closed-set token it names. */
final class LexDefect extends RuntimeException
{
    public function __construct(public readonly string $id, public readonly string $token = '')
    {
        parent::__construct($id);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use RuntimeException;

/** No generator input or candidate belongs in the public exception message. */
final class InertSecretExhausted extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('inert-secret-clean-exhausted');
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

final class SandboxProjectionException extends \RuntimeException
{
    public function __construct(private string $errorCode)
    {
        parent::__construct('sandbox projection failed: ' . $errorCode);
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }
}

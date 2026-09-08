<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

final class SandboxPublicationResult
{
    public function __construct(public readonly string $code, public readonly ?string $generation = null)
    {
    }

    public function successful(): bool
    {
        return in_array($this->code, ['selected-new', 'unchanged-current', 'recovered-selected'], true);
    }
}

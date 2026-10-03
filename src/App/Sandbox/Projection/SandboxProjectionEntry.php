<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

final class SandboxProjectionEntry
{
    public function __construct(
        public readonly ProjectionRegistryEntry $registered,
        public readonly SandboxProjectionSource $source,
    ) {
        if ($registered->entrySchema !== $source->sourceClass) {
            throw new SandboxProjectionException('projection-source-class-mismatch');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return $this->registered->toArray() + $this->source->toArray();
    }
}

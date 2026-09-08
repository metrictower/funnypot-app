<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

class CandidateGenerationFactory
{
    public function __construct(private ?SandboxFileOps $ops = null)
    {
        $this->ops ??= new SandboxFileOps();
    }

    public function mint(): string
    {
        $id = $this->ops->randomHex(16);
        if (preg_match('/^[0-9a-f]{32}$/', $id) !== 1) {
            throw new SandboxProjectionException('generation-id-invalid');
        }

        return $id;
    }
}

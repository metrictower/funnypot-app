<?php

declare(strict_types=1);

namespace Funnypot\App\Runtime;

final class RuntimeEndpointBinding
{
    public function __construct(
        public readonly string $endpointId,
        public readonly string $transport,
        public readonly int $containerPort,
        public readonly string $roleId,
    ) {
    }

    /** @return array{endpoint_id:string,transport:string,container_port:int,role_id:string} */
    public function toArray(): array
    {
        return ['endpoint_id' => $this->endpointId, 'transport' => $this->transport, 'container_port' => $this->containerPort, 'role_id' => $this->roleId];
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * One immutable endpoint row from demo/ports.json, in typed form. A bind names its own container
 * socket; a forward names the bind it reaches on a different host port. Consumers never re-parse the
 * raw manifest — the catalog materializes these once.
 */
final class ServiceEndpoint
{
    /** @param list<string> $targets */
    private function __construct(
        public readonly string $endpointId,
        public readonly string $serviceId,
        public readonly ?string $processId,
        public readonly string $ownerKind,
        public readonly string $transport,
        public readonly int $containerPort,
        public readonly int $hostPort,
        public readonly ?string $forwardTargetEndpointId,
        public readonly bool $tls,
        public readonly array $targets,
        public readonly bool $scannerExposed,
        public readonly bool $runtimeToggleable,
    ) {
    }

    /** @param array<string,mixed> $e a validated ports.json endpoint row */
    public static function fromRow(array $e): self
    {
        $targets = [];
        foreach ((array) ($e['targets'] ?? []) as $t) {
            if (is_string($t)) {
                $targets[] = $t;
            }
        }

        return new self(
            (string) $e['endpoint_id'],
            (string) $e['service_id'],
            $e['process_id'] === null ? null : (string) $e['process_id'],
            (string) $e['owner_kind'],
            (string) $e['transport'],
            (int) $e['container_port'],
            (int) $e['host_port'],
            $e['forward_target_endpoint_id'] === null ? null : (string) $e['forward_target_endpoint_id'],
            (bool) $e['tls'],
            $targets,
            (bool) $e['scanner_exposed'],
            (bool) $e['runtime_toggleable'],
        );
    }

    public function isBind(): bool
    {
        return $this->forwardTargetEndpointId === null;
    }

    public function isCanonicalWeb(): bool
    {
        return $this->ownerKind === 'canonical-web';
    }

    public function isNginxAlias(): bool
    {
        return $this->ownerKind === 'nginx-alias';
    }

    /** An externally observable non-canonical exposure tuple "transport/host_port" published for $target. */
    public function externalTuple(): string
    {
        return $this->transport . '/' . $this->hostPort;
    }

    public function publishedOn(string $target): bool
    {
        return in_array($target, $this->targets, true);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The canonical, sorted result of a successful resolution: the exact service/process set, its bind
 * endpoints, its externally observable exposures for the target, the chosen nginx alias endpoints, the
 * reserved media tuples and the honest counts (logical services, child processes, exposures, reserved
 * media). It carries a stable, non-secret `variant_id` derived from the selection — never from the
 * ranking key.
 */
final class ResolvedServiceProfile
{
    /**
     * @param list<string>                                                        $serviceIds
     * @param list<string>                                                        $processIds
     * @param list<array{endpoint_id:string,transport:string,container_port:int}> $bindEndpoints
     * @param list<string>                                                        $exposures  "transport/host_port"
     * @param list<string>                                                        $nginxHttpAliasEndpointIds
     * @param list<string>                                                        $nginxHttpsAliasEndpointIds
     * @param list<string>                                                        $reservedMediaTuples
     */
    public function __construct(
        public readonly string $mode,
        public readonly ?string $bundleId,
        public readonly string $baseFamily,
        public readonly string $variantId,
        public readonly array $serviceIds,
        public readonly array $processIds,
        public readonly array $bindEndpoints,
        public readonly array $exposures,
        public readonly array $nginxHttpAliasEndpointIds,
        public readonly array $nginxHttpsAliasEndpointIds,
        public readonly array $reservedMediaTuples,
    ) {
    }

    public function logicalServiceCount(): int
    {
        return count($this->serviceIds);
    }

    public function processCount(): int
    {
        return count($this->processIds);
    }

    public function exposureCount(): int
    {
        return count($this->exposures);
    }

    public function reservedMediaCount(): int
    {
        return count($this->reservedMediaTuples);
    }

    /** @return array{mode:string,bundle:?string,base_family:string,variant_id:string} */
    public function profileTuple(): array
    {
        return ['mode' => $this->mode, 'bundle' => $this->bundleId, 'base_family' => $this->baseFamily, 'variant_id' => $this->variantId];
    }

    public function effectiveProfile(): EffectiveServiceProfile
    {
        return new EffectiveServiceProfile($this->baseFamily, $this->variantId, $this->serviceIds);
    }

    /** @return array<string,mixed> a canonical view for previews/audit/tests */
    public function toArray(): array
    {
        return [
            'mode' => $this->mode,
            'bundle' => $this->bundleId,
            'base_family' => $this->baseFamily,
            'variant_id' => $this->variantId,
            'service_ids' => $this->serviceIds,
            'process_ids' => $this->processIds,
            'bind_endpoints' => $this->bindEndpoints,
            'exposures' => $this->exposures,
            'nginx_http_alias_endpoint_ids' => $this->nginxHttpAliasEndpointIds,
            'nginx_https_alias_endpoint_ids' => $this->nginxHttpsAliasEndpointIds,
            'reserved_media_tuples' => $this->reservedMediaTuples,
            'counts' => [
                'logical_services' => $this->logicalServiceCount(),
                'processes' => $this->processCount(),
                'exposures' => $this->exposureCount(),
                'reserved_media' => $this->reservedMediaCount(),
            ],
        ];
    }
}

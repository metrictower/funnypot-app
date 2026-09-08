<?php

declare(strict_types=1);

namespace Funnypot\App\Runtime;

use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceExposureManifest;

final class ExposureRuntimeAdapter
{
    /** @return list<RuntimeEndpointBinding> */
    public function bindings(ServiceExposureManifest $manifest, ?ServiceCatalog $catalog = null): array
    {
        $catalog ??= ServiceCatalog::fromPackage();
        $doc = $manifest->toArray();
        if (!is_string($doc['catalog_hash'] ?? null) || !hash_equals($catalog->catalogHash(), $doc['catalog_hash'])) {
            throw new RuntimePolicyException('runtime exposure: catalog hash mismatch');
        }
        $effective = $manifest->effectiveArtifact()->toArray();
        foreach (['catalog_hash', 'identity_public_hash', 'desired_revision', 'plan_hash', 'published_hash', 'profile'] as $key) {
            if (!array_key_exists($key, $doc) || !array_key_exists($key, $effective) || $doc[$key] !== $effective[$key]) {
                throw new RuntimePolicyException('runtime exposure: effective artifact mismatch');
            }
        }
        if (($doc['effective_revision'] ?? null) !== ($effective['revision'] ?? null)
            || ($doc['desired_service_ids'] ?? null) !== ($effective['effective_service_ids'] ?? null)
            || ($doc['desired_process_ids'] ?? null) !== ($effective['effective_process_ids'] ?? null)
            || ($doc['desired_exposures'] ?? null) !== ($effective['effective_exposures'] ?? null)) {
            throw new RuntimePolicyException('runtime exposure: effective closure mismatch');
        }

        $published = $doc['published'] ?? null;
        if (!is_array($published) || !array_is_list($published) || count($published) !== count(array_unique($published, SORT_STRING))) {
            throw new RuntimePolicyException('runtime exposure: duplicate or invalid publish tuple');
        }
        $rows = $doc['bind_endpoints'] ?? null;
        if (!is_array($rows) || !array_is_list($rows)) {
            throw new RuntimePolicyException('runtime exposure: invalid bind endpoint list');
        }
        $bindings = [];
        $seenIds = [];
        $seenSockets = [];
        foreach ($rows as $row) {
            if (!is_array($row) || array_keys($row) !== ['endpoint_id', 'transport', 'container_port']
                || !is_string($row['endpoint_id']) || !is_string($row['transport']) || !is_int($row['container_port'])) {
                throw new RuntimePolicyException('runtime exposure: malformed bind endpoint');
            }
            $endpoint = $catalog->endpoint($row['endpoint_id']);
            if ($endpoint === null || !$endpoint->isBind()) {
                throw new RuntimePolicyException('runtime exposure: unknown or non-bind endpoint');
            }
            if ($endpoint->transport !== $row['transport'] || $endpoint->containerPort !== $row['container_port']) {
                throw new RuntimePolicyException('runtime exposure: bind endpoint tuple mismatch');
            }
            $socket = $row['transport'] . '/' . $row['container_port'];
            if (isset($seenIds[$row['endpoint_id']]) || isset($seenSockets[$socket])) {
                throw new RuntimePolicyException('runtime exposure: duplicate bind tuple');
            }
            $role = match ($endpoint->ownerKind) {
                'canonical-web', 'nginx-alias' => 'edge',
                'listener', 'media-capability' => 'protocols',
                default => throw new RuntimePolicyException('runtime exposure: forbidden endpoint owner kind'),
            };
            $effectiveServices = $effective['effective_service_ids'] ?? [];
            if ($role !== 'edge' && (!is_array($effectiveServices) || !in_array($endpoint->serviceId, $effectiveServices, true))) {
                throw new RuntimePolicyException('runtime exposure: endpoint outside accepted manifest');
            }
            $seenIds[$row['endpoint_id']] = true;
            $seenSockets[$socket] = true;
            $bindings[] = new RuntimeEndpointBinding($row['endpoint_id'], $row['transport'], $row['container_port'], $role);
        }

        return $bindings;
    }
}

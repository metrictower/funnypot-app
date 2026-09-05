<?php

declare(strict_types=1);

namespace Funnypot\App\Admin;

use Funnypot\App\Identity\ServiceProfileIdentity;
use Funnypot\App\Service\CanonicalJson;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ResolvedServiceProfile;
use Funnypot\App\Service\ServiceCapabilityPolicy;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceProfileConflictException;
use Funnypot\App\Service\ServiceProfileInput;
use Funnypot\App\Service\ServiceProfilePreparer;
use Funnypot\App\Service\ServiceProfileResolver;
use Funnypot\App\Service\ServiceProfileStore;
use Funnypot\App\Service\ServiceResolutionReason;
use Funnypot\App\Service\ServiceStatusReader;
use Funnypot\App\Service\ServiceStatusSnapshot;
use InvalidArgumentException;

/**
 * The authenticated admin surface over the service-profile subsystem: read the catalog, read live
 * status/audit, preview a change and apply it under CAS. It writes ONLY the closed-vocabulary desired
 * profile through {@see ServiceProfileStore} — no Docker socket, process primitive, path or numeric
 * port. Its status payload is the only HTTP surface exposing heartbeat health, and it sits behind the
 * existing session gate.
 */
final class ServiceProfileAdmin
{
    public function __construct(
        private ServiceCatalog $catalog,
        private ServiceProfileStore $store,
        private ServiceStatusReader $statusReader,
        private ServiceProfilePreparer $preparer,
        private ServiceProfileResolver $resolver,
        private ServiceCapabilityPolicy $policy,
        private ServiceProfileIdentity $identity,
    ) {
    }

    /** @return array<string,mixed> */
    public function catalogPayload(): array
    {
        $services = [];
        foreach ($this->catalog->services() as $id => $d) {
            $services[$id] = [
                'label' => $d->label,
                'families' => $d->families,
                'selectable' => $d->selectable,
                'capability' => $d->capability,
                'process_units' => $d->processUnits,
                'udp_class' => $d->udpClass,
                'requires' => $d->requires,
                'excludes' => $d->excludes,
                'media_of' => $d->mediaOf,
            ];
        }
        ksort($services);
        $bundles = [];
        foreach ($this->catalog->bundles() as $id => $b) {
            $bundles[$id] = [
                'label' => $b->label,
                'base_family' => $b->baseFamily,
                'bootstrap' => $b->bootstrap,
                'required' => $b->required,
                'optional_slots' => $b->optionalSlots,
            ];
        }
        ksort($bundles);

        return [
            'ok' => true,
            'base_families' => $this->catalog->baseFamilies(),
            'process_ceiling' => $this->catalog->processCeiling(),
            'conflict_groups' => $this->catalog->conflictGroups(),
            'services' => $services,
            'bundles' => $bundles,
            'current_revision' => $this->store->currentRevision(),
        ];
    }

    /** @return array<string,mixed> the ONLY HTTP surface exposing heartbeat health (session-gated) */
    public function statusPayload(): array
    {
        [$snap, $reason] = $this->statusReader->readVerified();
        $view = $this->statusReader->current();
        $art = $snap?->effectiveArtifact();
        $ageSeconds = null;
        if ($snap !== null) {
            $ageSeconds = max(0, time() - $snap->writtenAt());
        }

        return [
            'ok' => true,
            'status_freshness' => $view->freshness(),
            'heartbeat_age_seconds' => $ageSeconds,
            'state' => $snap?->state(),
            'acceptance_mode' => $snap?->acceptanceMode(),
            'process_health' => $snap?->processHealth() ?? [],
            'effective_artifact' => $art === null ? null : [
                'schema' => $art->schema(),
                'revision' => $art->revision(),
                'generation' => $art->generation(),
                'hash' => $art->hash(),
            ],
            'base_family' => $view->profile()->baseFamily(),
            'variant_id' => $view->profile()->variantId(),
        ];
    }

    /** @return list<array<string,mixed>> */
    public function auditPayload(int $limit = 100): array
    {
        return $this->store->audits($limit);
    }

    /**
     * @param array<string,mixed> $rawInput
     * @return array<string,mixed>
     */
    public function preview(array $rawInput): array
    {
        try {
            $input = ServiceProfileInput::fromArray($rawInput);
        } catch (InvalidArgumentException $e) {
            return ['ok' => false, 'errors' => [['code' => $e->getMessage()]]];
        }
        $preview = $this->resolver->preview($input, $this->catalog, $this->policy, $this->identity);
        if (!$preview->ok) {
            return ['ok' => false, 'errors' => $preview->errors, 'warnings' => $preview->warnings];
        }
        $resolved = $preview->resolved;
        $fields = $this->preparer->fields($input, $resolved, $this->store->currentRevision());

        return [
            'ok' => true,
            'current_revision' => $this->store->currentRevision(),
            'preview_hash' => $fields['preview_hash'],
            'resolved' => $resolved->toArray(),
            'warnings' => $preview->warnings,
            'pending' => $this->pending($resolved),
        ];
    }

    /**
     * @param array<string,mixed> $rawInput
     * @return array<string,mixed>
     * @throws ServiceProfileConflictException on stale revision / hash / reconciling (HTTP 409)
     */
    public function apply(array $rawInput, int $expectedRevision, string $previewHash, string $actor, string $sourceIp): array
    {
        $input = ServiceProfileInput::fromArray($rawInput);
        $revision = $this->store->applyCas(
            $expectedRevision,
            $previewHash,
            function () use ($input): array {
                $p = $this->resolver->preview($input, $this->catalog, $this->policy, $this->identity);
                if (!$p->ok) {
                    throw new ServiceProfileConflictException('resolution-changed');
                }

                return $this->preparer->fields($input, $p->resolved, $this->store->currentRevision());
            },
            $actor,
            $sourceIp,
        );

        return ['ok' => true, 'revision' => $revision];
    }

    /**
     * Restart/redeploy pending: any change from the currently effective exposure set is restart- or
     * redeploy-required, since PHP can neither hot-reload an nginx alias nor open a host port.
     *
     * @return array<string,mixed>
     */
    private function pending(ResolvedServiceProfile $resolved): array
    {
        $current = $this->currentEffective();
        $currentExposures = $current === null ? [] : (array) ($current->toArray()['effective_exposures'] ?? []);
        $added = array_values(array_diff($resolved->exposures, $currentExposures));
        $removed = array_values(array_diff($currentExposures, $resolved->exposures));
        sort($added);
        sort($removed);

        $aliasPorts = [];
        foreach ([...$resolved->nginxHttpAliasEndpointIds, ...$resolved->nginxHttpsAliasEndpointIds] as $eid) {
            $ep = $this->catalog->endpoint($eid);
            if ($ep !== null) {
                $aliasPorts[] = $ep->transport . '/' . $ep->hostPort;
            }
        }
        $reasons = [];
        $aliasDelta = array_values(array_intersect($added, $aliasPorts));
        $portDelta = array_values(array_diff($added, $aliasPorts));
        if ($aliasDelta !== []) {
            $reasons[] = ['code' => ServiceResolutionReason::RESTART_REQUIRED, 'ids' => $aliasDelta];
        }
        if ($portDelta !== [] || $removed !== []) {
            $reasons[] = ['code' => ServiceResolutionReason::REDEPLOY_REQUIRED, 'ids' => array_values(array_unique([...$portDelta, ...$removed]))];
        }

        return ['added_exposures' => $added, 'removed_exposures' => $removed, 'reasons' => $reasons];
    }

    private function currentEffective(): ?EffectiveExposureArtifact
    {
        [$snap] = $this->statusReader->readVerified();
        if ($snap instanceof ServiceStatusSnapshot) {
            return $snap->effectiveArtifact();
        }

        return null;
    }
}

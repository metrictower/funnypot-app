<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\ServiceProfileIdentity;

/**
 * The pure resolution of a typed desired input against the joined catalog, the target capability set
 * and the scoped identity. Same input/catalog/target/key => byte-identical output independent of
 * catalog insertion order, client IP, date or call order. It never opens a socket, reads a store or
 * writes anything; the ranking key is used only as an HMAC key for optional-slot selection.
 *
 * Only `all` waives soft family-coherence membership. Every mode retains the hard rules: capability,
 * dependency, exclusion, declared-conflict variant, process ceiling, UDP safety and exposure budget.
 */
final class ServiceProfileResolver
{
    public const VARIANT_PREFIX = 'spv1_';
    private const RANK_DOMAIN = 'funnypot/service-slot-rank/v1';
    private const VARIANT_DOMAIN = 'funnypot/service-variant/v1';

    public function preview(
        ServiceProfileInput $input,
        ServiceCatalog $catalog,
        ServiceCapabilityPolicy $policy,
        ServiceProfileIdentity $identity,
    ): ServiceProfilePreview {
        $errors = [];
        $warnings = [];

        // 1. mode-shape + base family.
        $baseFamily = null;
        $bundle = null;
        if ($input->mode === 'named') {
            $bundle = $catalog->bundle((string) $input->bundleId);
            if ($bundle === null) {
                return ServiceProfilePreview::rejected([['code' => ServiceResolutionReason::BUNDLE_UNKNOWN, 'ids' => [(string) $input->bundleId]]]);
            }
            $baseFamily = $bundle->baseFamily;
        } else {
            $baseFamily = (string) $input->baseFamily;
            if (!$catalog->isBaseFamily($baseFamily)) {
                return ServiceProfilePreview::rejected([['code' => ServiceResolutionReason::BASE_FAMILY_UNKNOWN, 'ids' => [$baseFamily]]]);
            }
        }

        // 2. build the requested selectable set.
        [$selected, $buildErrors] = $this->buildSet($input, $catalog, $bundle, $identity, $baseFamily);
        $errors = [...$errors, ...$buildErrors];
        if ($errors !== []) {
            return ServiceProfilePreview::rejected($errors, $warnings);
        }

        // 4. required-companion expansion (named/all); manual reports missing companions instead.
        if ($input->mode === 'manual') {
            $missing = [];
            foreach ($selected as $id) {
                foreach ($catalog->descriptor($id)->requires as $req) {
                    if (!in_array($req, $selected, true)) {
                        $missing[$req] = true;
                    }
                }
            }
            if ($missing !== []) {
                $ids = array_keys($missing);
                sort($ids);
                $errors[] = ['code' => ServiceResolutionReason::MISSING_COMPANION, 'ids' => $ids];
            }
        } else {
            $selected = $this->expandRequired($selected, $catalog);
        }

        // 5. capability + exclusion checks.
        foreach ($selected as $id) {
            $desc = $catalog->descriptor($id);
            if ($desc->capability !== null && !$policy->capabilityEnabled($desc->capability)) {
                $errors[] = ['code' => ServiceResolutionReason::CAPABILITY_MISSING, 'ids' => [$id], 'detail' => $desc->capability];
            }
            if (!$policy->idAllowed($id)) {
                $errors[] = ['code' => ServiceResolutionReason::ALLOWED_IDS_VIOLATION, 'ids' => [$id]];
            }
        }
        foreach ($selected as $id) {
            foreach ($catalog->descriptor($id)->excludes as $ex) {
                if (in_array($ex, $selected, true)) {
                    $pair = [$id, $ex];
                    sort($pair);
                    $errors[] = ['code' => ServiceResolutionReason::EXCLUSION_CONFLICT, 'ids' => $pair];
                }
            }
        }

        // 6. declared conflict groups: at most one member selected (all requires an explicit variant).
        foreach ($catalog->conflictGroups() as $group => $members) {
            $chosen = array_values(array_filter($members, static fn (string $m): bool => in_array($m, $selected, true)));
            if (count($chosen) > 1) {
                $errors[] = ['code' => ServiceResolutionReason::UNDECLARED_COLLISION, 'ids' => $chosen, 'detail' => $group];
            }
        }

        // 7. protocols-disabled hard ceiling.
        if ($policy->protocolsDisabled() && $selected !== []) {
            $errors[] = ['code' => ServiceResolutionReason::PROTOCOLS_DISABLED, 'ids' => $selected];
        }

        // 7b. process ceiling.
        $processIds = $this->processIds($selected, $catalog);
        $processCount = 0;
        foreach ($selected as $id) {
            $processCount += $catalog->descriptor($id)->processUnits;
        }
        if ($processCount > $catalog->processCeiling()) {
            $errors[] = ['code' => ServiceResolutionReason::PROCESS_CEILING, 'detail' => $processCount . '/' . $catalog->processCeiling()];
        }

        // 8/9. media inclusion + exposure counting + budget.
        [$bindEndpoints, $exposures, $httpAliases, $httpsAliases, $reservedMedia] = $this->exposures($selected, $catalog, $policy);

        if (($ceiling = $policy->maxExposureCeiling()) !== null && $input->maxExposure > $ceiling) {
            $errors[] = ['code' => ServiceResolutionReason::MAX_EXPOSURE_CEILING, 'detail' => $input->maxExposure . '>' . $ceiling];
        }
        if (count($exposures) > $input->maxExposure) {
            $errors[] = ['code' => ServiceResolutionReason::BUDGET_BELOW_REQUIRED, 'detail' => count($exposures) . '>' . $input->maxExposure];
        }

        // soft warnings: family coherence (never for `all`, which waives it).
        if ($input->mode !== 'all') {
            $incoherent = [];
            foreach ($selected as $id) {
                if (!$catalog->descriptor($id)->inFamily($baseFamily)) {
                    $incoherent[] = $id;
                }
            }
            if ($incoherent !== []) {
                sort($incoherent);
                $warnings[] = ['code' => ServiceResolutionReason::FAMILY_COHERENCE, 'ids' => $incoherent, 'detail' => $baseFamily];
            }
        } else {
            $warnings[] = ['code' => ServiceResolutionReason::HIGH_FINGERPRINT_ALL];
        }

        if ($errors !== []) {
            return ServiceProfilePreview::rejected($errors, $warnings);
        }

        sort($selected);
        $variantId = $this->variantId($input->mode, $baseFamily, $selected, $input->conflictVariants);
        $resolved = new ResolvedServiceProfile(
            $input->mode,
            $bundle?->id,
            $baseFamily,
            $variantId,
            $selected,
            $processIds,
            $bindEndpoints,
            $exposures,
            $httpAliases,
            $httpsAliases,
            $reservedMedia,
        );

        return ServiceProfilePreview::resolved($resolved, $warnings);
    }

    /**
     * @param NamedServiceBundle|null $bundle
     * @return array{0:list<string>,1:list<array{code:string,ids?:list<string>,detail?:string}>}
     */
    private function buildSet(ServiceProfileInput $input, ServiceCatalog $catalog, ?NamedServiceBundle $bundle, ServiceProfileIdentity $identity, string $baseFamily): array
    {
        $errors = [];
        $selected = [];
        if ($input->mode === 'named') {
            foreach ($bundle->required as $r) {
                $selected[$r] = true;
            }
            foreach ($bundle->optionalSlots as $slot => $candidates) {
                $eligible = array_values(array_filter($candidates, function (string $c) use ($catalog): bool {
                    $d = $catalog->descriptor($c);
                    return $d !== null && $d->selectable;
                }));
                if ($eligible === []) {
                    continue;
                }
                $pick = $this->rankSlot($identity, (string) $bundle->id, $baseFamily, (string) $slot, $eligible);
                $selected[$pick] = true;
            }
        } elseif ($input->mode === 'manual') {
            foreach ($input->manualServiceIds as $id) {
                $desc = $catalog->descriptor($id);
                if ($desc === null) {
                    $errors[] = ['code' => ServiceResolutionReason::SERVICE_UNKNOWN, 'ids' => [$id]];
                    continue;
                }
                if (!$desc->selectable) {
                    $errors[] = ['code' => ServiceResolutionReason::NON_SELECTABLE_ID, 'ids' => [$id]];
                    continue;
                }
                $selected[$id] = true;
            }
        } else { // all
            foreach ($catalog->selectableIds() as $id) {
                $selected[$id] = true;
            }
            // Resolve each declared conflict group by the explicit variant; drop the non-chosen members.
            foreach ($catalog->conflictGroups() as $group => $members) {
                $choice = $input->conflictVariants[$group] ?? null;
                if ($choice === null) {
                    $errors[] = ['code' => ServiceResolutionReason::CONFLICT_VARIANT_MISSING, 'detail' => (string) $group, 'ids' => $members];
                    continue;
                }
                if (!in_array($choice, $members, true)) {
                    $errors[] = ['code' => ServiceResolutionReason::CONFLICT_VARIANT_INVALID, 'detail' => (string) $group, 'ids' => [$choice]];
                    continue;
                }
                foreach ($members as $m) {
                    if ($m !== $choice) {
                        unset($selected[$m]);
                    }
                }
            }
        }

        return [array_keys($selected), $errors];
    }

    /**
     * @param list<string> $selected
     * @return list<string>
     */
    private function expandRequired(array $selected, ServiceCatalog $catalog): array
    {
        $set = [];
        foreach ($selected as $id) {
            $set[$id] = true;
        }
        $changed = true;
        while ($changed) {
            $changed = false;
            foreach (array_keys($set) as $id) {
                foreach ($catalog->descriptor($id)->requires as $req) {
                    if (!isset($set[$req])) {
                        $set[$req] = true;
                        $changed = true;
                    }
                }
            }
        }

        return array_keys($set);
    }

    /**
     * @param list<string> $selected
     * @return list<string> sorted process ids (canonical + media excluded; only child-process owners)
     */
    private function processIds(array $selected, ServiceCatalog $catalog): array
    {
        $out = [];
        foreach ($selected as $id) {
            foreach ($catalog->descriptor($id)->endpoints as $ep) {
                if ($ep->processId !== null && ($ep->ownerKind === 'listener')) {
                    $out[$ep->processId] = true;
                }
            }
        }
        $ids = array_keys($out);
        sort($ids);

        return $ids;
    }

    /**
     * Media inclusion (rtp rides sip) + forward-closed exposure counting for the target.
     *
     * @param list<string> $selected
     * @return array{0:list<array{endpoint_id:string,transport:string,container_port:int}>,1:list<string>,2:list<string>,3:list<string>,4:list<string>}
     */
    private function exposures(array $selected, ServiceCatalog $catalog, ServiceCapabilityPolicy $policy): array
    {
        $target = $policy->target;
        // include media capabilities riding a selected signalling service
        $withMedia = $selected;
        foreach ($selected as $id) {
            $media = $catalog->mediaFor($id);
            if ($media !== null) {
                $withMedia[] = $media->id;
            }
        }
        $binds = [];
        $exposures = [];
        $http = [];
        $https = [];
        $reserved = [];
        foreach ($withMedia as $id) {
            foreach ($catalog->descriptor($id)->endpoints as $ep) {
                if ($ep->isBind()) {
                    $binds[$ep->endpointId] = ['endpoint_id' => $ep->endpointId, 'transport' => $ep->transport, 'container_port' => $ep->containerPort];
                }
                if (!$ep->inBasePublishSet($target)) {
                    continue;
                }
                if ($ep->ownerKind === 'media-capability') {
                    $reserved[] = $ep->externalTuple();
                    continue;
                }
                if ($ep->isNginxAlias()) {
                    if ($ep->tls) {
                        $https[] = $ep->endpointId;
                    } else {
                        $http[] = $ep->endpointId;
                    }
                }
                $exposures[] = $ep->externalTuple();
            }
        }
        $binds = array_values($binds);
        usort($binds, static fn (array $a, array $b): int => [$a['transport'], $a['container_port']] <=> [$b['transport'], $b['container_port']]);
        $exposures = array_values(array_unique($exposures));
        sort($exposures);
        sort($http);
        sort($https);
        $reserved = array_values(array_unique($reserved));
        sort($reserved);

        return [$binds, $exposures, $http, $https, $reserved];
    }

    /**
     * @param list<string> $candidates already eligibility-filtered
     */
    private function rankSlot(ServiceProfileIdentity $identity, string $bundle, string $family, string $slot, array $candidates): string
    {
        sort($candidates);
        $best = null;
        $bestMac = '';
        foreach ($candidates as $cand) {
            $msg = CanonicalJson::encode(['v' => 1, 'bundle' => $bundle, 'family' => $family, 'slot' => $slot, 'candidate' => $cand]);
            $mac = hash_hmac('sha256', self::RANK_DOMAIN . "\0" . $msg, $identity->rankingKey());
            if ($best === null || strcmp($mac, $bestMac) < 0) {
                $best = $cand;
                $bestMac = $mac;
            }
        }

        return (string) $best;
    }

    /**
     * @param list<string>         $serviceIds sorted
     * @param array<string,string> $conflictVariants
     */
    private function variantId(string $mode, string $family, array $serviceIds, array $conflictVariants): string
    {
        ksort($conflictVariants);
        $digest = CanonicalJson::digest(self::VARIANT_DOMAIN, [
            'mode' => $mode,
            'base_family' => $family,
            'service_ids' => $serviceIds,
            'conflict_variants' => $conflictVariants,
        ]);

        return self::VARIANT_PREFIX . substr($digest, 0, 32);
    }
}

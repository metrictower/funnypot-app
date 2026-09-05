<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Ops\PortManifest;
use RuntimeException;

/**
 * The strict join of the raw port inventory (Funnypot\App\Ops\PortManifest, demo/ports.json — the
 * tuple authority) and the semantic descriptor file (resources/service-profiles.php — meaning only).
 * It fails closed if either side is orphaned: every listener/media endpoint must have exactly one
 * semantic owner, every descriptor endpoint id must exist in the manifest, every bundle/conflict-group
 * member must be a selectable service, and any selectable UDP endpoint must carry a tested safety
 * class. The canonical catalog hash lets a preview/manifest detect a catalog change.
 *
 * Canonical web (80/443) and the non-curated nginx aliases stay owned by the manifest's `web` service
 * and are never selectable here — profile selection controls listeners, media capabilities and the
 * curated web-alias surfaces only.
 */
final class ServiceCatalog
{
    public const SCHEMA = 'funnypot-service-profiles/v1';
    public const HASH_DOMAIN = 'funnypot/service-catalog/v1';

    /** @var array<string,ServiceDescriptor> */
    private array $services;
    /** @var array<string,NamedServiceBundle> */
    private array $bundles;
    /** @var list<string> */
    private array $baseFamilies;
    /** @var array<string,list<string>> */
    private array $conflictGroups;
    private int $processCeiling;
    /** @var array<string,ServiceEndpoint> */
    private array $endpointsById;
    private string $catalogHash;

    /**
     * @param array<string,ServiceDescriptor> $services
     * @param array<string,NamedServiceBundle> $bundles
     * @param list<string> $baseFamilies
     * @param array<string,list<string>> $conflictGroups
     * @param array<string,ServiceEndpoint> $endpointsById
     */
    private function __construct(array $services, array $bundles, array $baseFamilies, array $conflictGroups, int $processCeiling, array $endpointsById, string $catalogHash)
    {
        $this->services = $services;
        $this->bundles = $bundles;
        $this->baseFamilies = $baseFamilies;
        $this->conflictGroups = $conflictGroups;
        $this->processCeiling = $processCeiling;
        $this->endpointsById = $endpointsById;
        $this->catalogHash = $catalogHash;
    }

    public static function fromPackage(?string $portsPath = null, ?string $semanticPath = null): self
    {
        $root = dirname(__DIR__, 3);
        $portsPath ??= $root . '/demo/ports.json';
        $semanticPath ??= $root . '/resources/service-profiles.php';
        $manifest = PortManifest::fromFile($portsPath);
        $problems = $manifest->validate();
        if ($problems !== []) {
            throw new RuntimeException('service catalog: ports.json is invalid: ' . implode('; ', $problems));
        }
        /** @var array<string,mixed> $semantic */
        $semantic = require $semanticPath;

        return self::fromSources($manifest, $semantic);
    }

    /** @param array<string,mixed> $semantic */
    public static function fromSources(PortManifest $manifest, array $semantic): self
    {
        if (($semantic['schema'] ?? null) !== self::SCHEMA) {
            throw new RuntimeException('service catalog: semantic schema mismatch');
        }

        // Index endpoints, and forbid a raw port/bind/command key ever leaking into the semantic file.
        $endpointsById = [];
        foreach ($manifest->endpoints() as $row) {
            $ep = ServiceEndpoint::fromRow($row);
            $endpointsById[$ep->endpointId] = $ep;
        }

        $rawServices = is_array($semantic['services'] ?? null) ? $semantic['services'] : [];
        foreach ($rawServices as $sid => $d) {
            foreach (['port', 'bind', 'container_port', 'host_port', 'spawn', 'command'] as $forbidden) {
                if (is_array($d) && array_key_exists($forbidden, $d)) {
                    throw new RuntimeException("service catalog: descriptor '{$sid}' must not carry a raw '{$forbidden}' key");
                }
            }
        }

        $udpClasses = self::stringList($semantic['udp_classes'] ?? []);
        $probeIds = self::stringList($semantic['probe_ids'] ?? []);

        // Build descriptors, joining each declared endpoint id to a manifest endpoint.
        $services = [];
        $claimed = [];   // endpoint_id => service id that owns it
        foreach ($rawServices as $sid => $d) {
            if (!is_string($sid) || preg_match('/^[a-z0-9][a-z0-9-]*$/', $sid) !== 1) {
                throw new RuntimeException('service catalog: service id must be a canonical lowercase id');
            }
            $eps = [];
            foreach (self::stringList($d['endpoint_ids'] ?? []) as $eid) {
                if (!isset($endpointsById[$eid])) {
                    throw new RuntimeException("service catalog: service '{$sid}' names unknown endpoint '{$eid}'");
                }
                if (isset($claimed[$eid])) {
                    throw new RuntimeException("service catalog: endpoint '{$eid}' is claimed by both '{$claimed[$eid]}' and '{$sid}'");
                }
                $claimed[$eid] = $sid;
                $eps[] = $endpointsById[$eid];
            }
            if ($eps === []) {
                throw new RuntimeException("service catalog: service '{$sid}' owns no endpoint");
            }
            $desc = ServiceDescriptor::fromSemantic($sid, is_array($d) ? $d : [], $eps);
            if (!in_array($desc->probeId, $probeIds, true)) {
                throw new RuntimeException("service catalog: service '{$sid}' has unknown probe id '{$desc->probeId}'");
            }
            if ($desc->hasUdp() && $desc->selectable && $desc->udpClass === null) {
                throw new RuntimeException("service catalog: selectable UDP service '{$sid}' has no safety class");
            }
            if ($desc->udpClass !== null && !in_array($desc->udpClass, $udpClasses, true)) {
                throw new RuntimeException("service catalog: service '{$sid}' has unknown udp class '{$desc->udpClass}'");
            }
            $services[$sid] = $desc;
        }

        // Every listener/media endpoint must have exactly one semantic owner (the 40-process guarantee).
        foreach ($endpointsById as $eid => $ep) {
            if (($ep->ownerKind === 'listener' || $ep->ownerKind === 'media-capability') && !isset($claimed[$eid])) {
                throw new RuntimeException("service catalog: listener/media endpoint '{$eid}' has no semantic owner");
            }
        }

        // Dependency/exclusion/media/capability references must resolve to known services.
        foreach ($services as $sid => $desc) {
            foreach ([...$desc->requires, ...$desc->excludes] as $ref) {
                if (!isset($services[$ref])) {
                    throw new RuntimeException("service catalog: service '{$sid}' references unknown service '{$ref}'");
                }
            }
            if ($desc->mediaOf !== null && !isset($services[$desc->mediaOf])) {
                throw new RuntimeException("service catalog: media service '{$sid}' rides unknown service '{$desc->mediaOf}'");
            }
        }

        $baseFamilies = self::stringList($semantic['base_families'] ?? []);
        $processCeiling = (int) ($semantic['process_ceiling'] ?? 0);

        $conflictGroups = [];
        foreach ((array) ($semantic['conflict_groups'] ?? []) as $group => $members) {
            $list = self::stringList($members);
            foreach ($list as $m) {
                if (!isset($services[$m])) {
                    throw new RuntimeException("service catalog: conflict group '{$group}' names unknown service '{$m}'");
                }
            }
            $conflictGroups[(string) $group] = $list;
        }

        $bundles = [];
        foreach ((array) ($semantic['bundles'] ?? []) as $bid => $b) {
            $bundle = NamedServiceBundle::fromArray((string) $bid, is_array($b) ? $b : []);
            if (!in_array($bundle->baseFamily, $baseFamilies, true)) {
                throw new RuntimeException("service catalog: bundle '{$bid}' has unknown base family '{$bundle->baseFamily}'");
            }
            foreach ($bundle->required as $r) {
                if (!isset($services[$r])) {
                    throw new RuntimeException("service catalog: bundle '{$bid}' requires unknown service '{$r}'");
                }
            }
            foreach ($bundle->optionalSlots as $slot => $cands) {
                foreach ($cands as $c) {
                    if (!isset($services[$c])) {
                        throw new RuntimeException("service catalog: bundle '{$bid}' slot '{$slot}' names unknown service '{$c}'");
                    }
                }
            }
            $bundles[(string) $bid] = $bundle;
        }

        $catalogHash = self::computeHash($services, $bundles, $baseFamilies, $conflictGroups, $processCeiling);

        return new self($services, $bundles, $baseFamilies, $conflictGroups, $processCeiling, $endpointsById, $catalogHash);
    }

    /** @return array<string,ServiceDescriptor> */
    public function services(): array
    {
        return $this->services;
    }

    public function descriptor(string $id): ?ServiceDescriptor
    {
        return $this->services[$id] ?? null;
    }

    /** @return list<string> selectable service ids, sorted */
    public function selectableIds(): array
    {
        $out = [];
        foreach ($this->services as $id => $desc) {
            if ($desc->selectable) {
                $out[] = $id;
            }
        }
        sort($out);

        return $out;
    }

    /** @return array<string,NamedServiceBundle> */
    public function bundles(): array
    {
        return $this->bundles;
    }

    public function bundle(string $id): ?NamedServiceBundle
    {
        return $this->bundles[$id] ?? null;
    }

    /** @return list<string> */
    public function baseFamilies(): array
    {
        return $this->baseFamilies;
    }

    public function isBaseFamily(string $family): bool
    {
        return in_array($family, $this->baseFamilies, true);
    }

    /** @return array<string,list<string>> */
    public function conflictGroups(): array
    {
        return $this->conflictGroups;
    }

    public function processCeiling(): int
    {
        return $this->processCeiling;
    }

    public function endpoint(string $endpointId): ?ServiceEndpoint
    {
        return $this->endpointsById[$endpointId] ?? null;
    }

    public function catalogHash(): string
    {
        return $this->catalogHash;
    }

    /** The media capability (rtp) riding $signallingId, if any. */
    public function mediaFor(string $signallingId): ?ServiceDescriptor
    {
        foreach ($this->services as $desc) {
            if ($desc->mediaOf === $signallingId) {
                return $desc;
            }
        }

        return null;
    }

    /**
     * @param array<string,ServiceDescriptor> $services
     * @param array<string,NamedServiceBundle> $bundles
     * @param list<string> $baseFamilies
     * @param array<string,list<string>> $conflictGroups
     */
    private static function computeHash(array $services, array $bundles, array $baseFamilies, array $conflictGroups, int $processCeiling): string
    {
        $svc = [];
        foreach ($services as $id => $d) {
            $eids = array_map(static fn (ServiceEndpoint $e): string => $e->endpointId, $d->endpoints);
            sort($eids);
            $svc[$id] = [
                'label' => $d->label,
                'families' => self::sortedCopy($d->families),
                'requires' => self::sortedCopy($d->requires),
                'excludes' => self::sortedCopy($d->excludes),
                'capability' => $d->capability,
                'process_units' => $d->processUnits,
                'probe_id' => $d->probeId,
                'udp_class' => $d->udpClass,
                'media_of' => $d->mediaOf,
                'selectable' => $d->selectable,
                'endpoint_ids' => $eids,
            ];
        }
        ksort($svc);
        $bnd = [];
        foreach ($bundles as $id => $b) {
            $slots = [];
            foreach ($b->optionalSlots as $slot => $cands) {
                $slots[$slot] = self::sortedCopy($cands);
            }
            ksort($slots);
            $bnd[$id] = [
                'base_family' => $b->baseFamily,
                'bootstrap' => $b->bootstrap,
                'required' => self::sortedCopy($b->required),
                'optional_slots' => $slots,
            ];
        }
        ksort($bnd);
        $groups = [];
        foreach ($conflictGroups as $g => $m) {
            $groups[$g] = self::sortedCopy($m);
        }
        ksort($groups);

        return CanonicalJson::digest(self::HASH_DOMAIN, [
            'schema' => self::SCHEMA,
            'base_families' => self::sortedCopy($baseFamilies),
            'process_ceiling' => $processCeiling,
            'services' => $svc,
            'bundles' => $bnd,
            'conflict_groups' => $groups,
        ]);
    }

    /** @param list<string> $a @return list<string> */
    private static function sortedCopy(array $a): array
    {
        sort($a);

        return $a;
    }

    /** @return list<string> */
    private static function stringList(mixed $v): array
    {
        $out = [];
        foreach ((array) $v as $item) {
            if (is_string($item)) {
                $out[] = $item;
            }
        }

        return $out;
    }
}

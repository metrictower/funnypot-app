<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The semantic meaning of one selectable service: its persona-family membership (soft), hard
 * dependencies/exclusions, required app capability, child-process count, fixed probe id, optional UDP
 * safety class and the exact ports.json endpoints it owns. Built by ServiceCatalog from the joined
 * semantic descriptor and the raw manifest; it holds no raw port number of its own.
 */
final class ServiceDescriptor
{
    /**
     * @param list<string>          $families
     * @param list<string>          $requires
     * @param list<string>          $excludes
     * @param list<ServiceEndpoint> $endpoints
     */
    private function __construct(
        public readonly string $id,
        public readonly string $label,
        public readonly array $families,
        public readonly array $requires,
        public readonly array $excludes,
        public readonly ?string $capability,
        public readonly int $processUnits,
        public readonly string $probeId,
        public readonly ?string $udpClass,
        public readonly ?string $mediaOf,
        public readonly bool $selectable,
        public readonly array $endpoints,
    ) {
    }

    /**
     * @param array<string,mixed>   $d         the raw semantic descriptor
     * @param list<ServiceEndpoint> $endpoints its joined endpoint objects
     */
    public static function fromSemantic(string $id, array $d, array $endpoints): self
    {
        return new self(
            $id,
            (string) ($d['label'] ?? $id),
            self::stringList($d['families'] ?? []),
            self::stringList($d['requires'] ?? []),
            self::stringList($d['excludes'] ?? []),
            isset($d['capability']) ? (string) $d['capability'] : null,
            (int) ($d['process_units'] ?? 1),
            (string) ($d['probe_id'] ?? ''),
            isset($d['udp_class']) ? (string) $d['udp_class'] : null,
            isset($d['media_of']) ? (string) $d['media_of'] : null,
            (bool) ($d['selectable'] ?? true),
            $endpoints,
        );
    }

    public function inFamily(string $family): bool
    {
        return in_array($family, $this->families, true);
    }

    public function hasUdp(): bool
    {
        foreach ($this->endpoints as $e) {
            if ($e->transport === 'udp') {
                return true;
            }
        }

        return false;
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

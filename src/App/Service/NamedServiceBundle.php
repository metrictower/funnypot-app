<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * A named coherent bundle: the always-present required service ids and the optional slots (each a set
 * of candidate ids from which the resolver picks at most one by stable deploy-seed ranking). Only a
 * `bootstrap` bundle is eligible for first-boot auto-selection.
 */
final class NamedServiceBundle
{
    /**
     * @param list<string>                $required
     * @param array<string,list<string>>  $optionalSlots slot name => candidate ids (a set, not ordered)
     */
    private function __construct(
        public readonly string $id,
        public readonly string $label,
        public readonly string $baseFamily,
        public readonly bool $bootstrap,
        public readonly array $required,
        public readonly array $optionalSlots,
    ) {
    }

    /** @param array<string,mixed> $b */
    public static function fromArray(string $id, array $b): self
    {
        $required = [];
        foreach ((array) ($b['required'] ?? []) as $r) {
            if (is_string($r)) {
                $required[] = $r;
            }
        }
        $slots = [];
        foreach ((array) ($b['optional_slots'] ?? []) as $slot => $cands) {
            $list = [];
            foreach ((array) $cands as $c) {
                if (is_string($c)) {
                    $list[] = $c;
                }
            }
            $slots[(string) $slot] = $list;
        }

        return new self(
            $id,
            (string) ($b['label'] ?? $id),
            (string) ($b['base_family'] ?? 'neutral'),
            (bool) ($b['bootstrap'] ?? false),
            $required,
            $slots,
        );
    }
}

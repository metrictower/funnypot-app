<?php

declare(strict_types=1);

namespace Funnypot\App\Emulation;

/**
 * The operator's on/off choices layered over the {@see EmulationCatalog}. Choices live in a small
 * JSON overlay (`funnypot-vulns.json`, or whatever `FUNNYPOT_VULNS` points at) that lists only the
 * ids whose state differs from the catalog default — so a brand-new emulation auto-appears at its
 * declared default without touching the file. The JSON is the canonical control surface; a
 * dashboard is just a UI that reads {@see materialize()} and writes it back.
 *
 * The engine consumes this as a deny-set: {@see disabledIds()} feeds the existing exclude machinery
 * so a disabled attack/service/decoy is simply never served. Resolution is override → catalog
 * default → true.
 */
final class EmulationPolicy
{
    /** @param array<string,bool> $overrides id => enabled (only differences from the catalog default) */
    public function __construct(private EmulationCatalog $catalog, private array $overrides = [])
    {
    }

    public static function fromPackage(?string $overlayPath = null): self
    {
        return new self(EmulationCatalog::fromPackage(), self::readOverlay($overlayPath));
    }

    public static function fromCatalog(EmulationCatalog $catalog, ?string $overlayPath = null): self
    {
        return new self($catalog, self::readOverlay($overlayPath));
    }

    /** @return array<string,bool> */
    private static function readOverlay(?string $path): array
    {
        if ($path === null || !is_file($path)) {
            return [];
        }
        $raw = json_decode((string) @file_get_contents($path), true);
        if (!is_array($raw)) {
            return [];
        }
        $vulns = isset($raw['vulns']) && is_array($raw['vulns']) ? $raw['vulns'] : $raw;
        $out = [];
        foreach ($vulns as $id => $on) {
            if (is_string($id) && (is_bool($on) || is_int($on))) {
                $out[$id] = (bool) $on;
            }
        }

        return $out;
    }

    public function isEnabled(string $id): bool
    {
        if (array_key_exists($id, $this->overrides)) {
            return $this->overrides[$id];
        }

        return $this->catalog->defaultFor($id);
    }

    /** @return string[] catalog ids resolving to OFF — the engine deny-set */
    public function disabledIds(): array
    {
        $out = [];
        foreach ($this->catalog->ids() as $id) {
            if (!$this->isEnabled($id)) {
                $out[] = $id;
            }
        }

        return $out;
    }

    /** The nuclei-reflection corpus is a single group toggle. Absent from the catalog ⇒ on. */
    public function nucleiEnabled(): bool
    {
        return $this->catalog->has('nuclei-reflection') ? $this->isEnabled('nuclei-reflection') : true;
    }

    public function catalog(): EmulationCatalog
    {
        return $this->catalog;
    }

    /**
     * The full resolved list for saving / rendering: every catalog id with its effective state,
     * plus the entry metadata. Writing this back is how new entries get persisted at their default.
     *
     * @return array<string,array<string,mixed>>
     */
    public function resolved(): array
    {
        $out = [];
        foreach ($this->catalog->all() as $id => $entry) {
            $out[$id] = $entry + ['enabled' => $this->isEnabled($id)];
        }

        return $out;
    }

    /**
     * The id => enabled map to persist in the JSON overlay (catalog ∪ current choices). Stale
     * overrides for ids no longer in the catalog are dropped — the catalog is the source of truth.
     *
     * @return array<string,bool>
     */
    public function materialize(): array
    {
        $out = [];
        foreach ($this->catalog->ids() as $id) {
            $out[$id] = $this->isEnabled($id);
        }
        ksort($out);

        return $out;
    }
}

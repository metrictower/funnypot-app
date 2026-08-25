<?php

declare(strict_types=1);

namespace Funnypot\App\Emulation;

/**
 * The catalog of everything funnypot can emulate — attack classes, protocol services, product
 * decoys, and the nuclei-reflection corpus — DERIVED at build time from the templates themselves
 * (see {@see \Funnypot\App\Build\CatalogCompiler}), never hand-maintained. Adding a template and
 * recompiling auto-registers a new entry, so the operator's on/off list can never drift out of
 * sync with what the engine actually ships.
 *
 * Each entry: id, kind (attack|service|route|corpus), title, category, cve, severity, ports
 * (services only), default (enabled unless the operator says otherwise), source path. This class
 * is the read-only manifest; {@see EmulationPolicy} layers the operator's choices on top.
 */
final class EmulationCatalog
{
    /** @param array<string,array<string,mixed>> $entries id => entry */
    public function __construct(private array $entries)
    {
    }

    public static function fromFile(string $path): self
    {
        $data = is_file($path) ? require $path : [];

        return new self(is_array($data) ? $data : []);
    }

    public static function fromPackage(): self
    {
        // Depth is counted from src/App/Emulation/ to the repo root. Keep it in step if this class
        // ever moves again — a wrong depth resolves to a path that simply does not exist, so the
        // catalog silently comes back empty and every emulation reads as enabled.
        return self::fromFile(dirname(__DIR__, 3) . '/resources/compiled/funnypot-catalog.php');
    }

    /** @return array<string,array<string,mixed>> */
    public function all(): array
    {
        return $this->entries;
    }

    /** @return array<string,mixed>|null */
    public function get(string $id): ?array
    {
        return $this->entries[$id] ?? null;
    }

    public function has(string $id): bool
    {
        return isset($this->entries[$id]);
    }

    /** Whether an entry is enabled when the operator has expressed no preference. Unknown ⇒ true. */
    public function defaultFor(string $id): bool
    {
        return (bool) ($this->entries[$id]['default'] ?? true);
    }

    /** @return string[] */
    public function ids(): array
    {
        return array_keys($this->entries);
    }

    /** @return array<string,array<string,mixed>> entries of one kind (attack|service|route|corpus) */
    public function byKind(string $kind): array
    {
        return array_filter($this->entries, static fn (array $e): bool => ($e['kind'] ?? '') === $kind);
    }

    public function count(): int
    {
        return count($this->entries);
    }
}

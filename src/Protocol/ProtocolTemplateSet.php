<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * The compiled protocol templates, keyed by protocol id. The listener asks it for the emulator
 * bound to a given protocol (per port). Runtime is PHP-only: rules are a frozen PHP array
 * (compiled from YAML at build time).
 */
final class ProtocolTemplateSet
{
    /** @param array<string,array<string,mixed>> $protocols compiled protocols, by id */
    public function __construct(
        private array $protocols,
        private ?int $identitySeed = null,
        private ?string $secret = null
    ) {
    }

    public static function fromFile(string $path, ?int $identitySeed = null, ?string $secret = null): self
    {
        $data = is_file($path) ? require $path : [];

        return new self(is_array($data) ? $data : [], $identitySeed, $secret);
    }

    public static function fromPackage(?int $identitySeed = null, ?string $secret = null): self
    {
        return self::fromFile(dirname(__DIR__, 2) . '/resources/compiled/funnypot-protocols.php', $identitySeed, $secret);
    }

    /** @return string[] */
    public function ids(): array
    {
        return array_keys($this->protocols);
    }

    public function has(string $id): bool
    {
        return isset($this->protocols[$id]);
    }

    public function emulator(string $id): ?ProtocolEmulator
    {
        return isset($this->protocols[$id])
            ? new ProtocolEmulator($this->protocols[$id], null, $this->identitySeed, $this->secret)
            : null;
    }

    /**
     * Default port → protocol-id map, from each protocol's `listen`. The listener/deploy can
     * override the binding, but this is the out-of-the-box wiring.
     *
     * @return array<int,string>
     */
    public function listenMap(): array
    {
        $map = [];
        foreach ($this->protocols as $id => $p) {
            foreach ((array) ($p['listen'] ?? []) as $port) {
                $map[(int) $port] = $id;
            }
        }

        return $map;
    }
}

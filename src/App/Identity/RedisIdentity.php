<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

use Funnypot\Core\Support\PersonaIdentity;

/**
 * The Redis engine's view: persona material plus the `redis-telemetry/v1` fingerprint key and
 * nothing else — no HTTP/shell/SIP key, no master, no derivation-by-label. The bundle is emitted and
 * root-verified on every preparation so the dedicated engine can consume this exact contract.
 */
final class RedisIdentity
{
    public const BUNDLE = 'redis';

    private const KEYS = ['persona_material', 'redis_telemetry_fingerprint_key'];

    private function __construct(private string $personaMaterial, private string $redisTelemetryFingerprintKey)
    {
    }

    public static function fromDeriver(IdentityKeyDeriver $d, string $personaMaterial): self
    {
        return new self($personaMaterial, $d->redisTelemetryFingerprintKey());
    }

    /** @param array<string,mixed> $payload */
    public static function fromPayload(array $payload): self
    {
        $p = IdentityBundleReader::requireExactly($payload, self::KEYS);

        return new self($p['persona_material'], IdentityKeyDeriver::decodeKey($p['redis_telemetry_fingerprint_key']));
    }

    public static function load(IdentityPaths $paths, ?IdentityFileOps $ops = null): self
    {
        return self::fromPayload((new IdentityBundleReader($paths, $ops))->read(self::BUNDLE)['payload']);
    }

    /** @return array<string,string> */
    public function toPayload(): array
    {
        return [
            'persona_material' => $this->personaMaterial,
            'redis_telemetry_fingerprint_key' => IdentityKeyDeriver::encodeKey($this->redisTelemetryFingerprintKey),
        ];
    }

    public function personaMaterial(): string
    {
        return $this->personaMaterial;
    }

    public function personaSeed(): int
    {
        return PersonaIdentity::seedFromMaterial($this->personaMaterial);
    }

    public function redisTelemetryFingerprintKey(): string
    {
        return $this->redisTelemetryFingerprintKey;
    }
}

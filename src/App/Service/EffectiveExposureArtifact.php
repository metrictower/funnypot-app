<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use RuntimeException;

/**
 * The immutable, content-addressed record of one accepted effective/LKG exposure set — the nested
 * `funnypot-effective-service-exposure/v1` object a downstream generation (FP-0319 views, FP-0107
 * role startup/cutover/rollback) binds to. Its `generation` (32 hex) and `hash` (64 hex) derive from
 * the canonical bytes of everything else, so they change only when the accepted exposure set changes.
 *
 * Acceptance mode (bootstrap vs health) is deliberately NOT part of this payload: the supervisor's
 * first health acceptance of a bootstrap-accepted set changes no byte, revision, generation or hash,
 * so first-boot never rotates downstream views. That flag lives only in the runtime store/heartbeat.
 */
final class EffectiveExposureArtifact
{
    public const SCHEMA = 'funnypot-effective-service-exposure/v1';
    public const HASH_DOMAIN = 'funnypot/effective-service-exposure/v1';

    /** @param array<string,mixed> $payload the canonical payload WITHOUT generation/hash */
    private function __construct(
        private array $payload,
        private string $generation,
        private string $hash,
        private string $canonicalBytes,
    ) {
    }

    /**
     * @param list<string> $serviceIds
     * @param list<string> $processIds
     * @param list<string> $exposures   externally observable "transport/host_port" tuples
     * @param array{mode:string,bundle:?string,base_family:string,variant_id:string} $profile
     */
    public static function create(
        int $revision,
        int $desiredRevision,
        string $target,
        string $publishMode,
        string $catalogHash,
        string $identityPublicHash,
        string $planHash,
        string $publishedHash,
        array $profile,
        array $serviceIds,
        array $processIds,
        array $exposures,
    ): self {
        sort($serviceIds);
        sort($processIds);
        sort($exposures);
        $payload = [
            'schema' => self::SCHEMA,
            'revision' => $revision,
            'desired_revision' => $desiredRevision,
            'target' => $target,
            'publish_mode' => $publishMode,
            'catalog_hash' => $catalogHash,
            'identity_public_hash' => $identityPublicHash,
            'plan_hash' => $planHash,
            'published_hash' => $publishedHash,
            'profile' => [
                'mode' => $profile['mode'],
                'bundle' => $profile['bundle'],
                'base_family' => $profile['base_family'],
                'variant_id' => $profile['variant_id'],
            ],
            'effective_service_ids' => array_values($serviceIds),
            'effective_process_ids' => array_values($processIds),
            'effective_exposures' => array_values($exposures),
        ];

        return self::fromPayload($payload);
    }

    /** @param array<string,mixed> $payload the payload WITHOUT generation/hash */
    private static function fromPayload(array $payload): self
    {
        $bytes = CanonicalJson::encode($payload);
        $hash = hash('sha256', self::HASH_DOMAIN . "\0" . $bytes);

        return new self($payload, substr($hash, 0, 32), $hash, $bytes);
    }

    /**
     * Parse and self-verify a decoded artifact object (with generation/hash present): recompute the
     * hash from the payload and reject a mismatch, so a corrupt or tampered artifact fails closed.
     *
     * @param array<string,mixed> $doc
     */
    public static function fromArray(array $doc): self
    {
        if (($doc['schema'] ?? null) !== self::SCHEMA) {
            throw new RuntimeException('effective artifact: schema mismatch');
        }
        $storedGen = $doc['generation'] ?? null;
        $storedHash = $doc['hash'] ?? null;
        if (!is_string($storedGen) || !is_string($storedHash)) {
            throw new RuntimeException('effective artifact: missing generation/hash');
        }
        unset($doc['generation'], $doc['hash']);
        $self = self::fromPayload($doc);
        if (!hash_equals($self->hash, $storedHash) || !hash_equals($self->generation, $storedGen)) {
            throw new RuntimeException('effective artifact: hash mismatch');
        }

        return $self;
    }

    public function schema(): string
    {
        return self::SCHEMA;
    }

    public function revision(): int
    {
        return (int) $this->payload['revision'];
    }

    public function desiredRevision(): int
    {
        return (int) $this->payload['desired_revision'];
    }

    public function generation(): string
    {
        return $this->generation;
    }

    public function hash(): string
    {
        return $this->hash;
    }

    public function canonicalBytes(): string
    {
        return $this->canonicalBytes;
    }

    /** The full artifact object including generation/hash, for embedding in a manifest/heartbeat. @return array<string,mixed> */
    public function toArray(): array
    {
        return $this->payload + ['generation' => $this->generation, 'hash' => $this->hash];
    }
}

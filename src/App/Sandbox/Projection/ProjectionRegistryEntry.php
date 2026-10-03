<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

final class ProjectionRegistryEntry
{
    public const REQUIRED = 'required';
    public const PAIR = 'pair';
    public const EXACTLY_ONE = 'exactly-one';
    public const ZERO_ANONYMOUS = 'zero-anonymous';
    public const GENERATED_ANONYMOUS = \Funnypot\App\Identity\SourceOpenAttestation::GENERATED_ANONYMOUS;

    /**
     * @param list<string> $attestationIds
     * @param list<RestartConsumer> $restartConsumers
     */
    public function __construct(
        public readonly string $entrySchema,
        public readonly string $entryId,
        public readonly string $presence,
        public readonly ProjectionDestinationOwner $destinationOwner,
        public readonly string $destinationId,
        public readonly string $relativePath,
        public readonly int $directoryMode,
        public readonly int $fileMode,
        public readonly string $contentClass,
        public readonly array $restartConsumers,
        public readonly array $attestationIds,
        public readonly string $linkCountPolicy,
    ) {
        if (!in_array($presence, [self::REQUIRED, self::PAIR], true)
            || !in_array($contentClass, ['public', 'private'], true)
            || !in_array($linkCountPolicy, [self::EXACTLY_ONE, self::ZERO_ANONYMOUS], true)
            || preg_match('/^[a-z0-9-]+\/v[0-9]+$/', $entrySchema) !== 1
            || preg_match('/^[a-z0-9][a-z0-9-]*$/', $entryId) !== 1
            || preg_match('#^[a-z0-9-]+(?:/[a-z0-9-]+)+$#', $destinationId) !== 1
            || preg_match('#^views/[a-z0-9-]+(?:/[a-z0-9.-]+)+$#', $relativePath) !== 1
            || !str_starts_with($relativePath, 'views/' . $destinationOwner->value . '/')
            || $directoryMode !== 0500 || !in_array($fileMode, [0400, 0444], true)
            || strlen($relativePath) > SandboxProjection::MAX_PATH_BYTES) {
            throw new SandboxProjectionException('projection-registry-invalid');
        }
        foreach ($restartConsumers as $consumer) {
            if (!$consumer instanceof RestartConsumer) { throw new SandboxProjectionException('projection-registry-invalid'); }
        }
        foreach ($attestationIds as $id) {
            if (!is_string($id) || !in_array($id, [
                \Funnypot\App\Identity\SourceOpenAttestation::DIRECT_NOFOLLOW,
                \Funnypot\App\Identity\SourceOpenAttestation::LETSENCRYPT_MANAGED_CHAIN,
                \Funnypot\App\Identity\SourceOpenAttestation::GENERATED_ANONYMOUS,
            ], true)) { throw new SandboxProjectionException('projection-registry-invalid'); }
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        [$uid, $gid] = $this->destinationOwner->ownership();

        return [
            'entry_schema' => $this->entrySchema,
            'entry_id' => $this->entryId,
            'presence' => $this->presence,
            'destination_owner' => $this->destinationOwner->value,
            'destination_id' => $this->destinationId,
            'destination_path' => $this->relativePath,
            'directory_uid' => $uid,
            'directory_gid' => $gid,
            'directory_mode' => $this->directoryMode,
            'file_uid' => $uid,
            'file_gid' => $gid,
            'file_mode' => $this->fileMode,
            'content_class' => $this->contentClass,
            'restart_consumers' => array_map(static fn (RestartConsumer $r): string => $r->value, $this->restartConsumers),
            'attestation_ids' => $this->attestationIds,
            'link_count_policy' => $this->linkCountPolicy,
        ];
    }
}

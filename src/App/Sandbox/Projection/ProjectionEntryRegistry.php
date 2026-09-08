<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Identity\SourceOpenAttestation;
use Funnypot\App\Service\CanonicalJson;

final class ProjectionEntryRegistry
{
    public const HASH_DOMAIN = 'funnypot/projection-registry/v1';

    /** @var array<string,ProjectionRegistryEntry> */
    private array $entries = [];

    /** @param list<ProjectionRegistryEntry>|null $entries test injection only */
    public function __construct(?array $entries = null)
    {
        foreach ($entries ?? self::foundationEntries() as $entry) {
            if (!$entry instanceof ProjectionRegistryEntry || isset($this->entries[$entry->entrySchema])) {
                throw new SandboxProjectionException('projection-registry-invalid');
            }
            $this->entries[$entry->entrySchema] = $entry;
        }
        if (count($this->entries) > SandboxProjection::MAX_ENTRIES) {
            throw new SandboxProjectionException('projection-registry-invalid');
        }
    }

    public static function v1(): self
    {
        return new self();
    }

    public function entry(string $sourceClass): ?ProjectionRegistryEntry
    {
        return $this->entries[$sourceClass] ?? null;
    }

    /** @return list<ProjectionRegistryEntry> */
    public function entries(): array
    {
        return array_values($this->entries);
    }

    /** @return list<array<string,mixed>> */
    public function records(): array
    {
        return array_map(static fn (ProjectionRegistryEntry $e): array => $e->toArray(), $this->entries());
    }

    public function registryHash(): string
    {
        return CanonicalJson::digest(self::HASH_DOMAIN, $this->records());
    }

    /** @return list<ProjectionRegistryEntry> */
    private static function foundationEntries(): array
    {
        $direct = [SourceOpenAttestation::DIRECT_NOFOLLOW];
        $le = [SourceOpenAttestation::DIRECT_NOFOLLOW, SourceOpenAttestation::LETSENCRYPT_MANAGED_CHAIN];

        return [
            self::row(PreparedIdentitySource::HTTP, 'web-http-identity', ProjectionRegistryEntry::REQUIRED, ProjectionDestinationOwner::WEB, 'web/identity/http', 'views/web/identity/http.json', 0400, 'private', [RestartConsumer::WEB], $direct),
            self::row(PreparedIdentitySource::SHELL, 'protocol-shell-identity', ProjectionRegistryEntry::REQUIRED, ProjectionDestinationOwner::PROTOCOLS, 'protocols/identity/shell', 'views/protocols/identity/shell.json', 0400, 'private', [RestartConsumer::PROTOCOLS], $direct),
            self::row(PreparedIdentitySource::SIP, 'protocol-sip-identity', ProjectionRegistryEntry::REQUIRED, ProjectionDestinationOwner::PROTOCOLS, 'protocols/identity/sip', 'views/protocols/identity/sip.json', 0400, 'private', [RestartConsumer::PROTOCOLS], $direct),
            self::row(PreparedIdentitySource::REDIS, 'protocol-redis-identity', ProjectionRegistryEntry::REQUIRED, ProjectionDestinationOwner::PROTOCOLS, 'protocols/identity/redis', 'views/protocols/identity/redis.json', 0400, 'private', [RestartConsumer::PROTOCOLS], $direct),
            self::row(PreparedIdentitySource::TLS_CERTIFICATE, 'edge-main-tls-certificate', ProjectionRegistryEntry::REQUIRED, ProjectionDestinationOwner::EDGE, 'edge/tls/main-certificate', 'views/edge/tls/funnypot.crt', 0444, 'public', [RestartConsumer::EDGE], $direct),
            self::row(PreparedIdentitySource::TLS_PRIVATE_KEY, 'edge-main-tls-private-key', ProjectionRegistryEntry::REQUIRED, ProjectionDestinationOwner::EDGE, 'edge/tls/main-private-key', 'views/edge/tls/funnypot.key', 0400, 'private', [RestartConsumer::EDGE], $direct),
            self::row(PreparedIdentitySource::ADMIN_TLS_CERTIFICATE, 'edge-admin-tls-certificate', ProjectionRegistryEntry::PAIR, ProjectionDestinationOwner::EDGE, 'edge/tls/admin-certificate', 'views/edge/tls/admin.crt', 0444, 'public', [RestartConsumer::EDGE], $le),
            self::row(PreparedIdentitySource::ADMIN_TLS_PRIVATE_KEY, 'edge-admin-tls-private-key', ProjectionRegistryEntry::PAIR, ProjectionDestinationOwner::EDGE, 'edge/tls/admin-private-key', 'views/edge/tls/admin.key', 0400, 'private', [RestartConsumer::EDGE], $le),
            self::row(PreparedIdentitySource::POST_EXPLOIT, 'post-exploit-state-identity', ProjectionRegistryEntry::REQUIRED, ProjectionDestinationOwner::POST_EXPLOIT_STATE, 'post-exploit-state/identity', 'views/post-exploit-state/identity/post-exploit-state.json', 0400, 'private', [RestartConsumer::POST_EXPLOIT_STATE], $direct),
        ];
    }

    /** @param list<RestartConsumer> $consumers @param list<string> $attestations */
    private static function row(string $schema, string $id, string $presence, ProjectionDestinationOwner $owner, string $destinationId, string $path, int $fileMode, string $class, array $consumers, array $attestations): ProjectionRegistryEntry
    {
        return new ProjectionRegistryEntry($schema, $id, $presence, $owner, $destinationId, $path, 0500, $fileMode, $class, $consumers, $attestations, ProjectionRegistryEntry::EXACTLY_ONE);
    }
}

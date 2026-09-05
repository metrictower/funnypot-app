<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\SourceOpener;
use RuntimeException;
use Throwable;

/**
 * The one derived bind/publish artifact consumed by deploy, compose, preflight, the runtime
 * supervisor, admin status and downstream FP-0107. Its immutable plan portion (target, publish mode,
 * catalog/identity hashes, desired revision/hash, profile, desired service/process ids, bind
 * endpoints, desired exposures, published mappings and nginx alias ids) is committed to a `plan_hash`;
 * mutable health lives elsewhere. It embeds the byte-exact nested {@see EffectiveExposureArtifact}.
 *
 * As the file at {@see ServicePaths::PERSISTENT_MANIFEST} this is the ONLY downstream binding source.
 * The persistent copy carries fixed not-live status fields (`state: not-live`, empty per-process
 * health, `status_revision: 0`); the live heartbeat, never this file, holds current health.
 * {@see fromPersistentFile()} applies the same trusted-input reader rule the identity manifest uses
 * (lstat regular / nlink 1 / owner in {0, euid} / no g+o access -> fopen -> fstat equality -> read ->
 * fstat) so FP-0319 consumes it verbatim rather than adding a second opener.
 */
final class ServiceExposureManifest
{
    public const SCHEMA = 'funnypot-service-exposure/v1';
    public const PLAN_HASH_DOMAIN = 'funnypot/service-exposure-plan/v1';
    public const PUBLISHED_HASH_DOMAIN = 'funnypot/service-published/v1';
    public const MAX_BYTES = 262144;

    /** @param array<string,mixed> $payload full manifest payload (persistent, not-live status) */
    private function __construct(
        private array $payload,
        private EffectiveExposureArtifact $effective,
    ) {
    }

    /**
     * Assemble a manifest from resolved plan pieces, computing published_hash, plan_hash and the nested
     * effective artifact so all three agree.
     *
     * @param array{mode:string,bundle:?string,base_family:string,variant_id:string} $profile
     * @param list<string>                                                            $desiredServiceIds
     * @param list<string>                                                            $desiredProcessIds
     * @param list<array{endpoint_id:string,transport:string,container_port:int}>     $bindEndpoints
     * @param list<string>                                                            $desiredExposures
     * @param list<string>                                                            $published  "target transport/host:container"
     * @param list<string>                                                            $nginxHttpAliasEndpointIds
     * @param list<string>                                                            $nginxHttpsAliasEndpointIds
     */
    public static function build(
        string $target,
        string $publishMode,
        string $catalogHash,
        string $identityPublicHash,
        int $desiredRevision,
        string $desiredHash,
        int $effectiveRevision,
        array $profile,
        array $desiredServiceIds,
        array $desiredProcessIds,
        array $bindEndpoints,
        array $desiredExposures,
        array $published,
        array $nginxHttpAliasEndpointIds,
        array $nginxHttpsAliasEndpointIds,
    ): self {
        sort($desiredServiceIds);
        sort($desiredProcessIds);
        sort($desiredExposures);
        sort($published);
        sort($nginxHttpAliasEndpointIds);
        sort($nginxHttpsAliasEndpointIds);
        usort($bindEndpoints, static fn (array $a, array $b): int => [$a['transport'], $a['container_port']] <=> [$b['transport'], $b['container_port']]);

        $publishedHash = CanonicalJson::digest(self::PUBLISHED_HASH_DOMAIN, ['published' => array_values($published)]);

        $plan = [
            'schema' => self::SCHEMA,
            'target' => $target,
            'publish_mode' => $publishMode,
            'catalog_hash' => $catalogHash,
            'identity_public_hash' => $identityPublicHash,
            'desired_revision' => $desiredRevision,
            'desired_hash' => $desiredHash,
            'profile' => [
                'mode' => $profile['mode'],
                'bundle' => $profile['bundle'],
                'base_family' => $profile['base_family'],
                'variant_id' => $profile['variant_id'],
            ],
            'desired_service_ids' => array_values($desiredServiceIds),
            'desired_process_ids' => array_values($desiredProcessIds),
            'bind_endpoints' => array_values($bindEndpoints),
            'desired_exposures' => array_values($desiredExposures),
            'published' => array_values($published),
            'published_hash' => $publishedHash,
            'nginx_http_alias_endpoint_ids' => array_values($nginxHttpAliasEndpointIds),
            'nginx_https_alias_endpoint_ids' => array_values($nginxHttpsAliasEndpointIds),
        ];
        $planHash = CanonicalJson::digest(self::PLAN_HASH_DOMAIN, $plan);

        $effective = EffectiveExposureArtifact::create(
            $effectiveRevision,
            $desiredRevision,
            $target,
            $publishMode,
            $catalogHash,
            $identityPublicHash,
            $planHash,
            $publishedHash,
            $profile,
            $desiredServiceIds,
            $desiredProcessIds,
            $desiredExposures,
        );

        $payload = $plan + [
            'plan_hash' => $planHash,
            'effective_artifact' => $effective->toArray(),
            // Fixed not-live status fields: the persistent file is a binding source, never live health.
            'effective_revision' => $effectiveRevision,
            'state' => 'not-live',
            'status_revision' => 0,
            'pending_reasons' => [],
            'process_health' => [],
            'external_reachability' => 'unverified',
        ];

        return new self($payload, $effective);
    }

    public function planHash(): string
    {
        return (string) $this->payload['plan_hash'];
    }

    public function publishedHash(): string
    {
        return (string) $this->payload['published_hash'];
    }

    public function statusRevision(): int
    {
        return (int) $this->payload['status_revision'];
    }

    public function target(): string
    {
        return (string) $this->payload['target'];
    }

    public function publishMode(): string
    {
        return (string) $this->payload['publish_mode'];
    }

    public function effectiveArtifact(): EffectiveExposureArtifact
    {
        return $this->effective;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return $this->payload;
    }

    /** The canonical persistent-file bytes. */
    public function toJson(): string
    {
        return CanonicalJson::encode($this->payload);
    }

    /**
     * Parse and self-verify a decoded manifest object: re-verify the nested effective artifact's hash
     * and the plan_hash so a corrupt file fails closed.
     *
     * @param array<string,mixed> $doc
     */
    public static function fromArray(array $doc): self
    {
        if (($doc['schema'] ?? null) !== self::SCHEMA) {
            throw new RuntimeException('exposure manifest: schema mismatch');
        }
        if (!is_array($doc['effective_artifact'] ?? null)) {
            throw new RuntimeException('exposure manifest: missing effective_artifact');
        }
        $effective = EffectiveExposureArtifact::fromArray($doc['effective_artifact']);

        // Re-verify the plan hash over the immutable portion.
        $planKeys = [
            'schema', 'target', 'publish_mode', 'catalog_hash', 'identity_public_hash', 'desired_revision',
            'desired_hash', 'profile', 'desired_service_ids', 'desired_process_ids', 'bind_endpoints',
            'desired_exposures', 'published', 'published_hash', 'nginx_http_alias_endpoint_ids',
            'nginx_https_alias_endpoint_ids',
        ];
        $plan = [];
        foreach ($planKeys as $k) {
            if (!array_key_exists($k, $doc)) {
                throw new RuntimeException("exposure manifest: missing plan key '{$k}'");
            }
            $plan[$k] = $doc[$k];
        }
        $planHash = CanonicalJson::digest(self::PLAN_HASH_DOMAIN, $plan);
        if (!is_string($doc['plan_hash'] ?? null) || !hash_equals($planHash, (string) $doc['plan_hash'])) {
            throw new RuntimeException('exposure manifest: plan_hash mismatch');
        }

        return new self($doc, $effective);
    }

    /**
     * The typed loader FP-0319 binds to. Anchored at the storage root (a trusted, operator-owned
     * mount), it validates .funnypot/services/<file> beneath it by the direct no-follow reader rule,
     * then parses + self-verifies. On any failure it throws so a downstream generation never binds a
     * corrupt or absent manifest.
     */
    public static function fromPersistentFile(string $path, ?IdentityFileOps $ops = null): self
    {
        $ops ??= new IdentityFileOps();
        $file = basename($path);
        $servicesDir = dirname($path);
        $funnypotDir = dirname($servicesDir);
        $storageRoot = dirname($funnypotDir);
        if ($file === '' || basename($servicesDir) !== 'services' || basename($funnypotDir) !== '.funnypot') {
            throw new RuntimeException('exposure manifest: path is not under .funnypot/services');
        }
        $opener = new SourceOpener($ops);
        try {
            $src = $opener->openDirect(
                $storageRoot,
                ['.funnypot', 'services', $file],
                'exposure-manifest',
                self::MAX_BYTES,
                SourceOpener::MODE_PRIVATE,
                SourceOpener::MODE_PRIVATE,
            );
        } catch (Throwable $e) {
            throw new RuntimeException('exposure manifest: unreadable (' . $e->getMessage() . ')', 0, $e);
        }
        $ops->close($src->handle);
        $doc = json_decode($src->bytes, true);
        if (!is_array($doc)) {
            throw new RuntimeException('exposure manifest: not a JSON object');
        }

        return self::fromArray($doc);
    }
}

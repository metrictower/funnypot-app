<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

use Funnypot\Core\Support\PersonaIdentity;

/**
 * The web tier's scoped identity view: the visible persona material plus only the private keys the
 * php-fpm worker consumes (core render salt, web-console filesystem + session-MAC keys, the Docker
 * registry-token fingerprint key, the engagement analytics key). It never carries the install master,
 * a generic derivation service or another tier's key, and it is read from the 0640 root:www-data
 * bundle — never from the root-only shell/protocol bundles or the persistent manifest.
 *
 * personaMaterial() is an explicit operator override VERBATIM when one is configured (so today's
 * `seedFromMaterial` integer — and every persona a running install shows — is unchanged), else the
 * install-derived `fpi1_…` value.
 */
final class HttpIdentity
{
    public const BUNDLE = 'http';

    private const KEYS = [
        'persona_material', 'core_render_salt', 'shell_filesystem_key', 'console_session_mac_key',
        'docker_registry_token_key', 'engagement_analytics_key',
    ];

    private function __construct(
        private string $personaMaterial,
        private string $coreRenderSalt,
        private string $filesystemKey,
        private string $sessionMacKey,
        private string $dockerRegistryTokenKey,
        private string $engagementAnalyticsKey,
    ) {
    }

    public static function fromDeriver(IdentityKeyDeriver $d, string $personaMaterial): self
    {
        return new self(
            $personaMaterial,
            $d->coreRenderSalt(),
            $d->shellFilesystemKey(),
            $d->consoleSessionMacKey(),
            $d->dockerRegistryTokenKey(),
            $d->engagementAnalyticsKey(),
        );
    }

    /** @param array<string,mixed> $payload */
    public static function fromPayload(array $payload): self
    {
        $p = IdentityBundleReader::requireExactly($payload, self::KEYS);

        return new self(
            $p['persona_material'],
            IdentityKeyDeriver::decodeKey($p['core_render_salt']),
            IdentityKeyDeriver::decodeKey($p['shell_filesystem_key']),
            IdentityKeyDeriver::decodeKey($p['console_session_mac_key']),
            IdentityKeyDeriver::decodeKey($p['docker_registry_token_key']),
            IdentityKeyDeriver::decodeKey($p['engagement_analytics_key']),
        );
    }

    /** Load the web bundle from the runtime root (the only file the web process may read). */
    public static function load(IdentityPaths $paths, ?IdentityFileOps $ops = null): self
    {
        return self::fromPayload((new IdentityBundleReader($paths, $ops))->read(self::BUNDLE)['payload']);
    }

    /** @return array<string,string> */
    public function toPayload(): array
    {
        return [
            'persona_material' => $this->personaMaterial,
            'core_render_salt' => IdentityKeyDeriver::encodeKey($this->coreRenderSalt),
            'shell_filesystem_key' => IdentityKeyDeriver::encodeKey($this->filesystemKey),
            'console_session_mac_key' => IdentityKeyDeriver::encodeKey($this->sessionMacKey),
            'docker_registry_token_key' => IdentityKeyDeriver::encodeKey($this->dockerRegistryTokenKey),
            'engagement_analytics_key' => IdentityKeyDeriver::encodeKey($this->engagementAnalyticsKey),
        ];
    }

    public function personaMaterial(): string
    {
        return $this->personaMaterial;
    }

    /** The integer every app persona consumer seeds from — the same derivation as core Config::deploySeed(). */
    public function personaSeed(): int
    {
        return PersonaIdentity::seedFromMaterial($this->personaMaterial);
    }

    /** X-Powered-By default: the SAME PHP version /phpinfo.php shows for this persona. */
    public function defaultPoweredBy(): string
    {
        return 'PHP/' . PersonaIdentity::fromSeed($this->personaSeed())->productVersion('php');
    }

    public function coreRenderSalt(): string
    {
        return $this->coreRenderSalt;
    }

    public function filesystemKey(): string
    {
        return $this->filesystemKey;
    }

    public function sessionMacKey(): string
    {
        return $this->sessionMacKey;
    }

    public function dockerRegistryTokenKey(): string
    {
        return $this->dockerRegistryTokenKey;
    }

    public function engagementAnalyticsKey(): string
    {
        return $this->engagementAnalyticsKey;
    }
}

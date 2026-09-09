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

    /**
     * Additive keys a newer image writes but an older bundle may not carry. Read optionally so a new
     * image booting against a not-yet-re-prepared old bundle never fails the whole web tier; the
     * feature that consumes one enforces its presence only when it is enabled.
     */
    private const OPTIONAL_KEYS = ['attrition_journey_key'];

    private function __construct(
        private string $personaMaterial,
        private string $coreRenderSalt,
        private string $filesystemKey,
        private string $sessionMacKey,
        private string $dockerRegistryTokenKey,
        private string $engagementAnalyticsKey,
        private ?string $attritionJourneyKey = null,
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
            $d->attritionJourneyKey(),
        );
    }

    /** @param array<string,mixed> $payload */
    public static function fromPayload(array $payload): self
    {
        $p = IdentityBundleReader::requireWithOptional($payload, self::KEYS, self::OPTIONAL_KEYS);

        return new self(
            $p['persona_material'],
            IdentityKeyDeriver::decodeKey($p['core_render_salt']),
            IdentityKeyDeriver::decodeKey($p['shell_filesystem_key']),
            IdentityKeyDeriver::decodeKey($p['console_session_mac_key']),
            IdentityKeyDeriver::decodeKey($p['docker_registry_token_key']),
            IdentityKeyDeriver::decodeKey($p['engagement_analytics_key']),
            isset($p['attrition_journey_key']) ? IdentityKeyDeriver::decodeKey($p['attrition_journey_key']) : null,
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
        $out = [
            'persona_material' => $this->personaMaterial,
            'core_render_salt' => IdentityKeyDeriver::encodeKey($this->coreRenderSalt),
            'shell_filesystem_key' => IdentityKeyDeriver::encodeKey($this->filesystemKey),
            'console_session_mac_key' => IdentityKeyDeriver::encodeKey($this->sessionMacKey),
            'docker_registry_token_key' => IdentityKeyDeriver::encodeKey($this->dockerRegistryTokenKey),
            'engagement_analytics_key' => IdentityKeyDeriver::encodeKey($this->engagementAnalyticsKey),
        ];
        if ($this->attritionJourneyKey !== null) {
            $out['attrition_journey_key'] = IdentityKeyDeriver::encodeKey($this->attritionJourneyKey);
        }

        return $out;
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

    /** The attrition-journey HMAC key, or null when the bundle predates it (feature must stay off). */
    public function attritionJourneyKey(): ?string
    {
        return $this->attritionJourneyKey;
    }
}

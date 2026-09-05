<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * The closed derivation surface over the install master. HKDF-SHA256 with a fixed salt and one
 * versioned info string per named domain; every output is 32 bytes and no domain's output is ever
 * another domain's input. There is deliberately NO derive($label) method — a caller-chosen label
 * would let one consumer mint another consumer's key — so a new consumer adds a named method and a
 * pinned vector here, or does without.
 *
 * Two outputs are public by design: {@see personaMaterial()} (the visible-persona seed material,
 * `fpi1_…`) and {@see keysetCommitment()} (a one-way SHA-256 over the private proof output, stored
 * in the manifest so a changed master is detected even when a persona override keeps the visible
 * identity the same). The proof output itself is never serialized.
 */
final class IdentityKeyDeriver
{
    public const MASTER_BYTES = 32;
    public const KEY_BYTES = 32;
    public const SALT = 'funnypot/install-identity/v1';

    public const PERSONA_PREFIX = 'fpi1_';
    public const COMMITMENT_PREFIX = 'fpkc1_';
    public const PUBLIC_HASH_PREFIX = 'fpph1_';

    private const INFO_PERSONA = 'persona-material/v1';
    private const INFO_CORE_RENDER_SALT = 'core-render-salt/v1';
    private const INFO_SHELL_FS = 'shell-filesystem/v1';
    private const INFO_CONSOLE_MAC = 'console-session-mac/v1';
    private const INFO_DOCKER_TOKEN = 'docker-registry-token/v1';
    private const INFO_ANALYTICS = 'engagement-analytics/v1';
    private const INFO_EXPERIMENT = 'engagement-experiment/v1';
    private const INFO_SERVICE_PROFILE = 'service-profile/v1';
    private const INFO_KEYSET_PROOF = 'runtime-keyset-proof/v1';
    private const INFO_REDIS_TELEMETRY = 'redis-telemetry/v1';
    private const INFO_POST_EXPLOIT = 'post-exploit-state/v1';

    private const COMMITMENT_DOMAIN = 'funnypot/keyset-commitment/v1';
    private const PUBLIC_HASH_DOMAIN = 'funnypot/public-persona-hash/v1';

    /** Every info string, for the pairwise-inequality vector test. @var list<string> */
    public const DOMAINS = [
        self::INFO_PERSONA, self::INFO_CORE_RENDER_SALT, self::INFO_SHELL_FS, self::INFO_CONSOLE_MAC,
        self::INFO_DOCKER_TOKEN, self::INFO_ANALYTICS, self::INFO_EXPERIMENT, self::INFO_SERVICE_PROFILE,
        self::INFO_KEYSET_PROOF, self::INFO_REDIS_TELEMETRY, self::INFO_POST_EXPLOIT,
    ];

    private function __construct(private string $master)
    {
    }

    public static function fromMaster(string $master): self
    {
        if (strlen($master) !== self::MASTER_BYTES) {
            throw IdentityBootstrapException::withCode('master-length', IdentityBootstrapException::REMEDY_CONFIG);
        }
        if ($master === str_repeat("\0", self::MASTER_BYTES)) {
            throw IdentityBootstrapException::withCode('master-all-zero', IdentityBootstrapException::REMEDY_CONFIG);
        }

        return new self($master);
    }

    /** Stable printable visible-persona material for the install-derived case. Not a secret. */
    public function personaMaterial(): string
    {
        return self::PERSONA_PREFIX . self::encodeKey($this->derive(self::INFO_PERSONA));
    }

    public function coreRenderSalt(): string
    {
        return $this->derive(self::INFO_CORE_RENDER_SALT);
    }

    public function shellFilesystemKey(): string
    {
        return $this->derive(self::INFO_SHELL_FS);
    }

    public function consoleSessionMacKey(): string
    {
        return $this->derive(self::INFO_CONSOLE_MAC);
    }

    public function dockerRegistryTokenKey(): string
    {
        return $this->derive(self::INFO_DOCKER_TOKEN);
    }

    public function engagementAnalyticsKey(): string
    {
        return $this->derive(self::INFO_ANALYTICS);
    }

    public function engagementExperimentKey(): string
    {
        return $this->derive(self::INFO_EXPERIMENT);
    }

    public function serviceProfileKey(): string
    {
        return $this->derive(self::INFO_SERVICE_PROFILE);
    }

    public function redisTelemetryFingerprintKey(): string
    {
        return $this->derive(self::INFO_REDIS_TELEMETRY);
    }

    public function postExploitStateKey(): string
    {
        return $this->derive(self::INFO_POST_EXPLOIT);
    }

    /**
     * One-way commitment to this master's whole keyset. Stored in the manifest and every bundle
     * envelope; never equal to (and not invertible to) the private proof output it commits to.
     */
    public function keysetCommitment(): string
    {
        return self::COMMITMENT_PREFIX . hash('sha256', self::COMMITMENT_DOMAIN . "\0" . $this->derive(self::INFO_KEYSET_PROOF));
    }

    /** The secret-free public identity hash of whatever visible persona material is in effect. */
    public static function publicPersonaHash(string $personaMaterial): string
    {
        return self::PUBLIC_HASH_PREFIX . hash('sha256', self::PUBLIC_HASH_DOMAIN . "\0" . $personaMaterial);
    }

    /** base64url, no padding — the only encoding a private key takes in a bundle. */
    public static function encodeKey(string $raw): string
    {
        return sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /** Strict inverse of {@see encodeKey()}; exactly KEY_BYTES or a bootstrap failure. */
    public static function decodeKey(string $encoded, string $code = 'bundle-key-malformed'): string
    {
        try {
            $raw = sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException $e) {
            throw IdentityBootstrapException::withCode($code, IdentityBootstrapException::REMEDY_RUNTIME);
        }
        if (strlen($raw) !== self::KEY_BYTES) {
            throw IdentityBootstrapException::withCode($code, IdentityBootstrapException::REMEDY_RUNTIME);
        }

        return $raw;
    }

    private function derive(string $info): string
    {
        return hash_hkdf('sha256', $this->master, self::KEY_BYTES, $info, self::SALT);
    }
}

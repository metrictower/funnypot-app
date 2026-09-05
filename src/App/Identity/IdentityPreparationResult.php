<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

use Funnypot\App\Tls\TlsSelection;

/**
 * What one successful preparation produced, for the in-process caller only (the CLI, and the later
 * composite root preparation that projects sources into per-role views). Exposes the nine typed
 * sources with their open handles: the four scoped bundles, the selected main TLS pair, the
 * optional Let's Encrypt admin pair (present together or absent together), and the root-only
 * post-exploit source. Nothing here is serialized; a consumer that needs a fact re-derives it from
 * the handle it was given.
 */
final class IdentityPreparationResult
{
    public const SOURCE_GENERATED = 'generated';
    public const SOURCE_PERSISTED = 'persisted';
    public const SOURCE_EXPLICIT_FILE = 'explicit-file';
    public const SOURCE_EXPLICIT_ENV = 'explicit-env';

    public const PERSONA_DERIVED = 'derived';
    public const PERSONA_OVERRIDE = 'override';

    /** @param list<string> $warnings stable codes only */
    public function __construct(
        public readonly string $sourceClass,
        public readonly string $personaSource,
        public readonly string $publicPersonaHash,
        public readonly string $keysetCommitment,
        public readonly TlsSelection $tls,
        public readonly bool $httpGroupApplied,
        public readonly array $warnings,
        public readonly PreparedIdentitySource $httpBundle,
        public readonly PreparedIdentitySource $shellBundle,
        public readonly PreparedIdentitySource $sipBundle,
        public readonly PreparedIdentitySource $redisBundle,
        public readonly PreparedIdentitySource $tlsCertificate,
        public readonly PreparedIdentitySource $tlsPrivateKey,
        public readonly ?PreparedIdentitySource $adminTlsCertificate,
        public readonly ?PreparedIdentitySource $adminTlsPrivateKey,
        public readonly PreparedIdentitySource $postExploitBundle,
    ) {
        if (($adminTlsCertificate === null) !== ($adminTlsPrivateKey === null)) {
            throw new \InvalidArgumentException('admin TLS pair must be present together or absent together');
        }
    }

    /**
     * The nine sources keyed by source class (the admin pair omitted when absent).
     *
     * @return array<string,PreparedIdentitySource>
     */
    public function sources(): array
    {
        $out = [
            PreparedIdentitySource::HTTP => $this->httpBundle,
            PreparedIdentitySource::SHELL => $this->shellBundle,
            PreparedIdentitySource::SIP => $this->sipBundle,
            PreparedIdentitySource::REDIS => $this->redisBundle,
            PreparedIdentitySource::TLS_CERTIFICATE => $this->tlsCertificate,
            PreparedIdentitySource::TLS_PRIVATE_KEY => $this->tlsPrivateKey,
            PreparedIdentitySource::POST_EXPLOIT => $this->postExploitBundle,
        ];
        if ($this->adminTlsCertificate !== null && $this->adminTlsPrivateKey !== null) {
            $out[PreparedIdentitySource::ADMIN_TLS_CERTIFICATE] = $this->adminTlsCertificate;
            $out[PreparedIdentitySource::ADMIN_TLS_PRIVATE_KEY] = $this->adminTlsPrivateKey;
        }

        return $out;
    }

    public function close(): void
    {
        foreach ($this->sources() as $s) {
            $s->close();
        }
    }
}

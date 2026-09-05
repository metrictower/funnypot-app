<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * One verified source as handed downstream: its fixed source class, the STILL-OPEN read handle, the
 * opener attestation, and the verified envelope facts (bundle schema/public hash/commitment, or the
 * public certificate fingerprint for TLS). It carries no path and no bytes — a consumer proves
 * continuity by fstat-comparing the handle to the attestation and re-reading through that handle.
 */
final class PreparedIdentitySource
{
    public const HTTP = 'http-identity-source/v1';
    public const SHELL = 'shell-identity-source/v1';
    public const SIP = 'sip-identity-source/v1';
    public const REDIS = 'redis-identity-source/v1';
    public const TLS_CERTIFICATE = 'selected-tls-certificate-source/v1';
    public const TLS_PRIVATE_KEY = 'selected-tls-private-key-source/v1';
    public const ADMIN_TLS_CERTIFICATE = 'selected-admin-tls-certificate-source/v1';
    public const ADMIN_TLS_PRIVATE_KEY = 'selected-admin-tls-private-key-source/v1';
    public const POST_EXPLOIT = 'post-exploit-identity-source/v1';

    /**
     * @param resource             $handle
     * @param array<string,string> $envelope verified public facts (never a key, path or master)
     */
    public function __construct(
        public readonly string $sourceClass,
        public readonly mixed $handle,
        public readonly SourceOpenAttestation $attestation,
        public readonly int $byteLength,
        public readonly string $sha256,
        public readonly array $envelope,
    ) {
    }

    public static function fromOpened(string $sourceClass, OpenedSource $src, array $envelope): self
    {
        return new self($sourceClass, $src->handle, $src->attestation, strlen($src->bytes), $src->sha256(), $envelope);
    }

    public function close(): void
    {
        if (is_resource($this->handle)) {
            @fclose($this->handle);
        }
    }
}

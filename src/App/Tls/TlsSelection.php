<?php

declare(strict_types=1);

namespace Funnypot\App\Tls;

use Funnypot\App\Identity\OpenedSource;

/**
 * The verified outcome of TLS selection: which class won, the pair's still-open validated sources,
 * the public fingerprint recorded in the manifest, and (when configured and issued) the Let's
 * Encrypt admin pair. The cert/key paths exist only so the runtime links can point at the selected
 * files; they are never written into a manifest or bundle.
 */
final class TlsSelection
{
    public const EXPLICIT = 'explicit';
    public const LEGACY = 'legacy';
    public const GENERATED = 'generated';

    public function __construct(
        public readonly string $selection,
        public readonly string $hostname,
        public readonly string $certPath,
        public readonly string $keyPath,
        public readonly string $fingerprintSha256,
        public readonly OpenedSource $cert,
        public readonly OpenedSource $key,
        public readonly ?string $adminDomain,
        public readonly ?string $adminFingerprintSha256,
        public readonly ?OpenedSource $adminCert,
        public readonly ?OpenedSource $adminKey,
        /** @var list<string> */
        public readonly array $warnings,
    ) {
    }

    public function hasAdminPair(): bool
    {
        return $this->adminCert !== null && $this->adminKey !== null;
    }

    /** @return array<string,mixed> the secret-free manifest record */
    public function manifestRecord(): array
    {
        $r = [
            'selection' => $this->selection,
            'hostname' => $this->hostname,
            'fingerprint_sha256' => $this->fingerprintSha256,
        ];
        if ($this->adminDomain !== null) {
            $r['admin'] = [
                'domain' => $this->adminDomain,
                'fingerprint_sha256' => $this->adminFingerprintSha256,
            ];
        }

        return $r;
    }
}

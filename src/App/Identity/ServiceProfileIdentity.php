<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * The service-profile tier's scoped identity view: exactly the stable ranking key derived through the
 * install deriver's named `service-profile/v1` domain, plus the visible persona hash from the bundle
 * envelope. It exposes ONLY {@see rankingKey()} — no master, no generic derivation method and no other
 * tier's key — and is read from the same 0640 root:www-data runtime bundle the web tier uses. The
 * ranking key is only ever an HMAC key for optional-slot selection; it is never stored in the desired
 * database, audit or exposure manifest.
 */
final class ServiceProfileIdentity
{
    public const BUNDLE = 'service-profile';

    private const KEYS = ['ranking_key'];

    private function __construct(
        private string $rankingKey,
        private string $publicPersonaHash,
    ) {
    }

    public static function fromDeriver(IdentityKeyDeriver $d): self
    {
        return new self($d->serviceProfileKey(), '');
    }

    /**
     * @param array<string,mixed> $payload
     */
    public static function fromPayload(array $payload, string $publicPersonaHash = ''): self
    {
        $p = IdentityBundleReader::requireExactly($payload, self::KEYS);

        return new self(IdentityKeyDeriver::decodeKey($p['ranking_key']), $publicPersonaHash);
    }

    /** Load the scoped bundle from the runtime root (root or the web worker may read it). */
    public static function load(IdentityPaths $paths, ?IdentityFileOps $ops = null): self
    {
        $doc = (new IdentityBundleReader($paths, $ops))->read(self::BUNDLE);

        return self::fromPayload($doc['payload'], (string) ($doc['envelope']['public_persona_hash'] ?? ''));
    }

    /** @return array<string,string> */
    public function toPayload(): array
    {
        return ['ranking_key' => IdentityKeyDeriver::encodeKey($this->rankingKey)];
    }

    /** The raw 32-byte HMAC key for optional-slot ranking. Never serialize this anywhere else. */
    public function rankingKey(): string
    {
        return $this->rankingKey;
    }

    public function publicPersonaHash(): string
    {
        return $this->publicPersonaHash;
    }
}

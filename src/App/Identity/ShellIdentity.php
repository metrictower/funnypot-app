<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

use Funnypot\Core\Support\PersonaIdentity;

/**
 * The root-only listener view for the SSH/telnet fake shell and the generic protocol emulators:
 * persona material plus the shell filesystem key that defeats oracle-replay of the procedural
 * filesystem. The web console gets the SAME filesystem key through {@see HttpIdentity} — it never
 * opens this bundle.
 */
final class ShellIdentity
{
    public const BUNDLE = 'shell';

    private const KEYS = ['persona_material', 'shell_filesystem_key'];

    private function __construct(private string $personaMaterial, private string $filesystemKey)
    {
    }

    public static function fromDeriver(IdentityKeyDeriver $d, string $personaMaterial): self
    {
        return new self($personaMaterial, $d->shellFilesystemKey());
    }

    /** @param array<string,mixed> $payload */
    public static function fromPayload(array $payload): self
    {
        $p = IdentityBundleReader::requireExactly($payload, self::KEYS);

        return new self($p['persona_material'], IdentityKeyDeriver::decodeKey($p['shell_filesystem_key']));
    }

    public static function load(IdentityPaths $paths, ?IdentityFileOps $ops = null): self
    {
        return self::fromPayload((new IdentityBundleReader($paths, $ops))->read(self::BUNDLE)['payload']);
    }

    /** @return array<string,string> */
    public function toPayload(): array
    {
        return [
            'persona_material' => $this->personaMaterial,
            'shell_filesystem_key' => IdentityKeyDeriver::encodeKey($this->filesystemKey),
        ];
    }

    public function personaMaterial(): string
    {
        return $this->personaMaterial;
    }

    public function personaSeed(): int
    {
        return PersonaIdentity::seedFromMaterial($this->personaMaterial);
    }

    public function filesystemKey(): string
    {
        return $this->filesystemKey;
    }
}

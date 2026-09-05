<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;

/**
 * The SIP listener's view: persona material only (the PBX needs the seed + the persona email domain
 * for its 'org' extension directory, no private key). Resolved before the socket binds; there is no
 * environment re-read and no degrade-to-seed-zero path any more.
 */
final class SipIdentity
{
    public const BUNDLE = 'sip';

    private const KEYS = ['persona_material'];

    private function __construct(private string $personaMaterial)
    {
    }

    public static function fromDeriver(IdentityKeyDeriver $d, string $personaMaterial): self
    {
        return new self($personaMaterial);
    }

    /** The persona-only view carries no secret, so tests may build it from material directly. */
    public static function fromPersonaMaterial(string $personaMaterial): self
    {
        if ($personaMaterial === '') {
            throw IdentityBootstrapException::withCode('persona-material-empty', IdentityBootstrapException::REMEDY_RUNTIME);
        }

        return new self($personaMaterial);
    }

    /** @param array<string,mixed> $payload */
    public static function fromPayload(array $payload): self
    {
        $p = IdentityBundleReader::requireExactly($payload, self::KEYS);

        return new self($p['persona_material']);
    }

    public static function load(IdentityPaths $paths, ?IdentityFileOps $ops = null): self
    {
        return self::fromPayload((new IdentityBundleReader($paths, $ops))->read(self::BUNDLE)['payload']);
    }

    /** @return array<string,string> */
    public function toPayload(): array
    {
        return ['persona_material' => $this->personaMaterial];
    }

    public function personaMaterial(): string
    {
        return $this->personaMaterial;
    }

    public function personaSeed(): int
    {
        return PersonaIdentity::seedFromMaterial($this->personaMaterial);
    }

    /** The persona's email domain — the same one the office/HR panels render. */
    public function personaDomain(): string
    {
        return VisualPersona::fromSeed($this->personaSeed())->domain();
    }
}

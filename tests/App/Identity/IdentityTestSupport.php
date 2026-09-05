<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Http\CoreConfigFactory;
use Funnypot\App\Identity\HttpIdentity;
use Funnypot\App\Identity\IdentityKeyDeriver;
use Funnypot\App\Identity\InstallSecretStore;

/**
 * Fixed test identities for unit tests that construct HTTP-tier objects directly (no prepared
 * bundle). The master bytes are constructor-injected through the same closed API production uses
 * — never an environment switch — and the persona is an explicit override so the visible seed is the
 * historical `seedFromMaterial('httptest')` integer the wire fixtures were written against.
 */
final class IdentityTestSupport
{
    public const PERSONA = 'httptest';

    /** Deterministic 32-byte masters, one per tag; tag 'a' is the default install. */
    public static function master(string $tag = 'a'): string
    {
        return hash('sha256', 'funnypot-test-master|' . $tag, true);
    }

    /** The canonical one-line serialization of {@see master()} — what an explicit env/file input holds. */
    public static function canonicalMaster(string $tag = 'a'): string
    {
        return InstallSecretStore::serialize(self::master($tag));
    }

    public static function deriver(string $tag = 'a'): IdentityKeyDeriver
    {
        return IdentityKeyDeriver::fromMaster(self::master($tag));
    }

    public static function httpIdentity(string $persona = self::PERSONA, string $tag = 'a'): HttpIdentity
    {
        return HttpIdentity::fromDeriver(self::deriver($tag), $persona);
    }

    public static function coreConfigFactory(string $persona = self::PERSONA, string $tag = 'a', ?string $poweredBy = null): CoreConfigFactory
    {
        $id = self::httpIdentity($persona, $tag);

        return new CoreConfigFactory($id, $poweredBy ?? $id->defaultPoweredBy());
    }
}

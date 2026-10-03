<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Identity\HttpIdentity;
use Funnypot\App\Identity\IdentityBundleReader;
use Funnypot\App\Identity\PostExploitIdentity;
use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Identity\RedisIdentity;
use Funnypot\App\Identity\ShellIdentity;
use Funnypot\App\Identity\SipIdentity;

/** Closed binding between each foundation identity source class and its canonical bundle envelope. */
final class ProjectionEnvelopePolicy
{
    /** @param array<string,mixed> $envelope */
    public static function validIdentity(string $sourceClass, array $envelope): bool
    {
        $bundle = self::identityBundle($sourceClass);
        if ($bundle === null || !self::sameKeys($envelope, ['schema', 'bundle', 'public_persona_hash', 'keyset_commitment'])) {
            return false;
        }

        return ($envelope['schema'] ?? null) === IdentityBundleReader::SCHEMA
            && ($envelope['bundle'] ?? null) === $bundle
            && is_string($envelope['public_persona_hash'] ?? null)
            && preg_match('/^fpph1_[0-9a-f]{64}$/', $envelope['public_persona_hash']) === 1
            && is_string($envelope['keyset_commitment'] ?? null)
            && preg_match('/^fpkc1_[0-9a-f]{64}$/', $envelope['keyset_commitment']) === 1;
    }

    public static function identityBundle(string $sourceClass): ?string
    {
        return match ($sourceClass) {
            PreparedIdentitySource::HTTP => HttpIdentity::BUNDLE,
            PreparedIdentitySource::SHELL => ShellIdentity::BUNDLE,
            PreparedIdentitySource::SIP => SipIdentity::BUNDLE,
            PreparedIdentitySource::REDIS => RedisIdentity::BUNDLE,
            PreparedIdentitySource::POST_EXPLOIT => PostExploitIdentity::BUNDLE,
            default => null,
        };
    }

    /** @param array<string,mixed> $value @param list<string> $keys */
    private static function sameKeys(array $value, array $keys): bool
    {
        $actual = array_keys($value);
        sort($actual);
        sort($keys);
        return $actual === $keys;
    }
}

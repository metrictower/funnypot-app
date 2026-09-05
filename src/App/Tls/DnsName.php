<?php

declare(strict_types=1);

namespace Funnypot\App\Tls;

use Funnypot\App\Identity\IdentityBootstrapException;

/**
 * The one DNS-name grammar every hostname input passes BEFORE it reaches a filesystem path, an
 * OpenSSL subject/SAN, or a generated nginx file: lowercase LDH labels (1–63 chars, no leading/
 * trailing hyphen), dot-separated, at most 253 characters. No newline, slash, comma, wildcard,
 * space, bracket or `=` can survive it, so a value interpolated into a config can never open a new
 * directive. scripts/lib/dns-name.sh applies the same grammar in the deploy scripts before any SSH
 * command is built.
 */
final class DnsName
{
    public const PATTERN = '/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/';

    public static function isValid(string $name): bool
    {
        return preg_match(self::PATTERN, $name) === 1;
    }

    /** The validated name, or a bootstrap failure carrying $code (never the rejected value). */
    public static function validate(string $name, string $code): string
    {
        if (!self::isValid($name)) {
            throw IdentityBootstrapException::withCode($code, IdentityBootstrapException::REMEDY_CONFIG);
        }

        return $name;
    }
}

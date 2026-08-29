<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ldap;

/**
 * Configuration for the low-interaction LDAP honeypot (port 389).
 *
 * The service parses bind and search requests only to harvest the intel a scanner offers — bind
 * DNs, passwords and search filters — and never touches a real directory. The single meaningful
 * knob is whether a bind is answered success or invalidCredentials.
 *
 * Deny is the default: a bind is answered invalidCredentials (49) so a brute-forcer keeps
 * throwing candidates at us. Accept mode answers success (0) instead, but it is still a bare
 * result code — no session is granted, no entry is ever returned — so the box stays 100% inert
 * either way; the switch only changes which lure keeps the attacker talking longest.
 */
final class LdapConfig
{
    public function __construct(
        // false -> answer binds with invalidCredentials (default, keeps brute-forcers trying);
        // true  -> answer binds with success (a fake result code only; never a real session).
        public bool $acceptBinds = false
    ) {
    }

    public static function fromEnv(): self
    {
        $acceptRaw = getenv('FUNNYPOT_LDAP_ACCEPT');
        $accept = ($acceptRaw !== false) ? filter_var($acceptRaw, FILTER_VALIDATE_BOOLEAN) : false;

        return new self(acceptBinds: $accept);
    }
}

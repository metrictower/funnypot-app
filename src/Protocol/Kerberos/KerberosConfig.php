<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Kerberos;

/**
 * Configuration for the low-interaction Kerberos KDC honeypot (TCP 88).
 *
 * The KDC never issues a ticket; its whole purpose is to log the AS-REQ recon that user-enumeration
 * and AS-REP-roasting tools run against a domain controller. Two knobs shape the persona:
 *
 * - realm: the Kerberos realm the box claims, echoed back in the KRB-ERROR when a request omits its
 *   own realm.
 * - knownPrincipals: the set of account names the KDC pretends exist. A real KDC answers a request
 *   for an existing account with KDC_ERR_PREAUTH_REQUIRED and one for a missing account with
 *   KDC_ERR_C_PRINCIPAL_UNKNOWN, so an attacker enumerates valid usernames by which error comes back.
 *   Naming a small set of plausible accounts here makes those "exist" — baiting the attacker into
 *   spraying and roasting them (more captured intel), while every other name is answered as unknown.
 */
final class KerberosConfig
{
    /** @var list<string> lowercased account names answered as existing (preauth-required) */
    public array $knownPrincipals;

    /**
     * @param list<string> $knownPrincipals
     */
    public function __construct(
        public string $realm = 'CORP.LOCAL',
        array $knownPrincipals = ['administrator', 'admin', 'guest', 'krbtgt', 'svc_sql', 'svc_backup', 'helpdesk']
    ) {
        $this->knownPrincipals = array_values(array_unique(array_map('strtolower', $knownPrincipals)));
    }

    public static function fromEnv(): self
    {
        $realm = getenv('FUNNYPOT_KERBEROS_REALM') ?: 'CORP.LOCAL';

        $raw = getenv('FUNNYPOT_KERBEROS_KNOWN_PRINCIPALS');
        if ($raw !== false && trim($raw) !== '') {
            $known = array_values(array_filter(array_map('trim', explode(',', $raw)), static fn (string $s): bool => $s !== ''));
        } else {
            $known = ['administrator', 'admin', 'guest', 'krbtgt', 'svc_sql', 'svc_backup', 'helpdesk'];
        }

        return new self(realm: $realm, knownPrincipals: $known);
    }

    /** True when $account (the client principal's first name component) is a modelled account. */
    public function isKnownPrincipal(string $account): bool
    {
        return in_array(strtolower($account), $this->knownPrincipals, true);
    }
}

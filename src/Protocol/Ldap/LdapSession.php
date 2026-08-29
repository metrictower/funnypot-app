<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ldap;

/**
 * Per-connection state, buffers and captured intel for one LDAP connection.
 *
 * LDAP has no separate framing — each LDAPMessage is a self-delimiting BER SEQUENCE — and one
 * connection carries several messages (bind, then search, then unbind). Nothing is authenticated:
 * the captured bind DN, password and search filter are the entire product of the session.
 */
final class LdapSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** messageID of the last request seen; response messageIDs echo the request they answer. */
    public int $lastMessageId = 0;

    /** LDAP protocol version from the most recent bindRequest (1-127; scanners send 3). */
    public int $version = 0;

    /** Bind DN and simple-auth password harvested from a bindRequest (raw bytes as captured). */
    public string $bindDn = '';
    public string $bindPassword = '';

    /** SASL mechanism name when a bind used SASL rather than simple authentication. */
    public string $saslMechanism = '';

    /** Base DN and RFC 4515 string form of the filter harvested from a searchRequest. */
    public string $searchBase = '';
    public string $searchFilter = '';

    public bool $close = false;

    public int $lastActiveTime;

    public function __construct(
        public readonly string $ip,
        public readonly int $port,
        public readonly int $id
    ) {
        $this->lastActiveTime = time();
    }
}

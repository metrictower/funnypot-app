<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Cassandra;

/**
 * Configuration for the low-interaction Cassandra honeypot (CQL native protocol, port 9042).
 *
 * The service answers OPTIONS with a SUPPORTED list, demands password auth in response to STARTUP,
 * then captures the credential the client offers in AUTH_RESPONSE and denies it with an ERROR. It
 * never authenticates, opens a keyspace, or serves a row, so every value here is cosmetic persona:
 * it shapes the Cassandra identity the box presents (the CQL version advertised in SUPPORTED, the
 * authenticator class named in AUTHENTICATE that makes a standard driver send its credentials),
 * never real access.
 *
 * Naming PasswordAuthenticator is what turns the handshake into a credential-harvesting exchange:
 * a driver that receives AUTHENTICATE must reply with a SASL PLAIN token carrying its cleartext
 * username and password rather than proceeding straight to READY.
 */
final class CassandraConfig
{
    public function __construct(
        // CQL_VERSION advertised in the SUPPORTED response (the query language the box claims).
        public string $cqlVersion = '3.4.5',
        // Cassandra release version the persona claims (cosmetic; surfaces only in system tables we
        // never serve, kept for a coherent identity).
        public string $releaseVersion = '3.11.10',
        // Cluster name the persona claims (cosmetic, same rationale as releaseVersion).
        public string $clusterName = 'Test Cluster',
        // The authenticator class named in AUTHENTICATE. PasswordAuthenticator is what makes a driver
        // send its cleartext credential; a real cluster names the fully-qualified Java class.
        public string $authenticator = 'org.apache.cassandra.auth.PasswordAuthenticator'
    ) {
    }

    public static function fromEnv(): self
    {
        $cqlVersion = getenv('FUNNYPOT_CASSANDRA_CQL_VERSION') ?: '3.4.5';
        $releaseVersion = getenv('FUNNYPOT_CASSANDRA_RELEASE_VERSION') ?: '3.11.10';
        $clusterName = getenv('FUNNYPOT_CASSANDRA_CLUSTER') ?: 'Test Cluster';
        $authenticator = getenv('FUNNYPOT_CASSANDRA_AUTHENTICATOR') ?: 'org.apache.cassandra.auth.PasswordAuthenticator';

        return new self(
            cqlVersion: $cqlVersion,
            releaseVersion: $releaseVersion,
            clusterName: $clusterName,
            authenticator: $authenticator
        );
    }
}

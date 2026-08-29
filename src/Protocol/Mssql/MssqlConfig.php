<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Configuration for the low-interaction MSSQL honeypot (TDS, port 1433).
 *
 * The service answers a TDS PRELOGIN then captures the LOGIN7 credential and denies the logon with
 * an ERROR token. It never authenticates, opens a database, or serves a row, so every value here is
 * cosmetic persona: it shapes the SQL Server identity the box presents (version advertised in the
 * PRELOGIN response, server name echoed in the login-failed error), never real access.
 */
final class MssqlConfig
{
    public function __construct(
        // Server name echoed in the ERROR token (a real server names itself in the login-failed message).
        public string $serverName = 'SQL01',
        // Version advertised in the PRELOGIN VERSION option. Defaults to SQL Server 2019 (15.0.2000).
        public int $versionMajor = 15,
        public int $versionMinor = 0,
        public int $versionBuild = 2000,
        public int $versionSubBuild = 0
    ) {
    }

    public static function fromEnv(): self
    {
        $server = getenv('FUNNYPOT_MSSQL_SERVER') ?: 'SQL01';

        $version = getenv('FUNNYPOT_MSSQL_VERSION') ?: '15.0.2000.0';
        $parts = array_map('intval', explode('.', $version));

        return new self(
            serverName: $server,
            versionMajor: $parts[0] ?? 15,
            versionMinor: $parts[1] ?? 0,
            versionBuild: $parts[2] ?? 2000,
            versionSubBuild: $parts[3] ?? 0
        );
    }

    /**
     * The 6-byte PRELOGIN VERSION option payload (MS-TDS 2.2.6.5): major(1), minor(1),
     * build(2 big-endian), subbuild(2 big-endian).
     */
    public function versionData(): string
    {
        return chr($this->versionMajor & 0xFF)
            . chr($this->versionMinor & 0xFF)
            . pack('n', $this->versionBuild & 0xFFFF)
            . pack('n', $this->versionSubBuild & 0xFFFF);
    }

    /** Dotted version string for the recon log line. */
    public function versionString(): string
    {
        return sprintf('%d.%d.%d.%d', $this->versionMajor, $this->versionMinor, $this->versionBuild, $this->versionSubBuild);
    }
}

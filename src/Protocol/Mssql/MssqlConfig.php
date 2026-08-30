<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Configuration for the MSSQL honeypot (TDS, port 1433).
 *
 * Every value here is cosmetic persona: it shapes the SQL Server identity the box presents, never
 * real access. The service answers a TDS PRELOGIN then, depending on {@see $interaction}, either
 * denies the LOGIN7 (`low` — the original credential-capture path) or accepts it and serves a
 * fabricated authenticated session (`high` — recon result-sets + the xp_cmdshell/RCE trap). No value
 * ever touches a real database, filesystem, registry, or network.
 *
 * Version coherence is a single-source invariant: the PRELOGIN VERSION option and the `@@version`
 * banner are BOTH derived from the version fields below, so a scanner can never catch them disagreeing.
 */
final class MssqlConfig
{
    public function __construct(
        // Server name echoed in the ERROR token and answered for @@servername / SERVERPROPERTY.
        public string $serverName = 'SQL01',
        // Version advertised in the PRELOGIN VERSION option. Defaults to SQL Server 2019 RTM (15.0.2000.5).
        public int $versionMajor = 15,
        public int $versionMinor = 0,
        public int $versionBuild = 2000,
        public int $versionSubBuild = 5,
        // Interaction mode: `high` = accept login + serve + trap; `low` = capture credential then deny.
        public string $interaction = 'high',
        // Instance name for LOGINACK / @@servicename (a default install is MSSQLSERVER).
        public string $instanceName = 'MSSQLSERVER',
        // OS portion of the @@version banner. `<X64>` + a Windows build string is the real capture shape.
        public string $osBanner = 'Windows Server 2019 Standard 10.0 <X64> (Build 17763: )',
        // System databases plus any seeded application databases, answered for sys.databases.
        /** @var list<string> */
        public array $databases = ['master', 'tempdb', 'model', 'msdb'],
        // Deterministic per-deploy seed for persona DB/login names (identical seed => identical answers).
        public string $personaSeed = ''
    ) {
    }

    public static function fromEnv(): self
    {
        $server = getenv('FUNNYPOT_MSSQL_SERVER') ?: 'SQL01';

        $version = getenv('FUNNYPOT_MSSQL_VERSION') ?: '15.0.2000.5';
        $parts = array_map('intval', explode('.', $version));

        $mode = strtolower((string) (getenv('FUNNYPOT_MSSQL_MODE') ?: 'high'));
        if ($mode !== 'low') {
            $mode = 'high';
        }

        $instance = getenv('FUNNYPOT_MSSQL_INSTANCE') ?: 'MSSQLSERVER';
        $os = getenv('FUNNYPOT_MSSQL_OS') ?: 'Windows Server 2019 Standard 10.0 <X64> (Build 17763: )';
        $seed = getenv('FUNNYPOT_MSSQL_SEED') ?: ($server . ':' . $version);

        $dbEnv = getenv('FUNNYPOT_MSSQL_DATABASES');
        $databases = ['master', 'tempdb', 'model', 'msdb'];
        if (is_string($dbEnv) && $dbEnv !== '') {
            $extra = array_values(array_filter(array_map('trim', explode(',', $dbEnv)), static fn ($d) => $d !== ''));
            foreach ($extra as $d) {
                if (!in_array($d, $databases, true)) {
                    $databases[] = $d;
                }
            }
        } else {
            $databases = array_merge($databases, self::deriveSeededDatabases($seed));
        }

        return new self(
            serverName: $server,
            versionMajor: $parts[0] ?? 15,
            versionMinor: $parts[1] ?? 0,
            versionBuild: $parts[2] ?? 2000,
            versionSubBuild: $parts[3] ?? 5,
            interaction: $mode,
            instanceName: $instance,
            osBanner: $os,
            databases: $databases,
            personaSeed: $seed
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

    /** Marketing product year for the version major (15 -> 2019, 16 -> 2022, ...). */
    public function productYear(): string
    {
        return match ($this->versionMajor) {
            16 => '2022',
            15 => '2019',
            14 => '2017',
            13 => '2016',
            12 => '2014',
            11 => '2012',
            10 => '2008',
            default => '2019',
        };
    }

    /**
     * The authentic `@@version` banner, derived from the same version fields as the PRELOGIN VERSION
     * option so the two never disagree. Real servers use tab/newline continuation lines.
     */
    public function bannerVersion(): string
    {
        $year = $this->productYear();

        return sprintf(
            "Microsoft SQL Server %s (RTM) - %s (X64) \n\tSep 24 %s 13:48:23 \n\tCopyright (C) %s Microsoft Corporation\n\tStandard Edition (64-bit) on %s (Hypervisor)",
            $year,
            $this->versionString(),
            $year,
            $year,
            $this->osBanner
        );
    }

    /**
     * The full database list answered for sys.databases: the four system DBs plus any seeded app DBs.
     *
     * @return list<string>
     */
    public function databaseNames(): array
    {
        return array_values($this->databases);
    }

    /**
     * Seeded principal names answered for sys.syslogins / sys.server_principals: `sa` plus a couple of
     * deterministic persona logins.
     *
     * @return list<string>
     */
    public function loginNames(): array
    {
        $logins = ['sa'];
        foreach (self::deriveSeededLogins($this->personaSeed) as $l) {
            if (!in_array($l, $logins, true)) {
                $logins[] = $l;
            }
        }

        return $logins;
    }

    /**
     * Deterministic application-database names from the seed. Pure function of the seed so a replayed
     * probe always sees the same list.
     *
     * @return list<string>
     */
    private static function deriveSeededDatabases(string $seed): array
    {
        $pool = ['AppDB', 'ReportServer', 'Billing', 'CRM', 'Inventory', 'Payroll', 'WebPortal', 'Analytics'];
        $h = crc32($seed);
        $a = $pool[$h % count($pool)];
        $b = $pool[($h >> 8) % count($pool)];

        return $a === $b ? [$a] : [$a, $b];
    }

    /**
     * Deterministic persona login names from the seed.
     *
     * @return list<string>
     */
    private static function deriveSeededLogins(string $seed): array
    {
        $pool = ['svc_app', 'dbadmin', 'reportuser', 'webuser', 'backup_svc', 'etl_svc'];
        $h = crc32('login:' . $seed);
        $a = $pool[$h % count($pool)];
        $b = $pool[($h >> 8) % count($pool)];

        return $a === $b ? [$a] : [$a, $b];
    }
}

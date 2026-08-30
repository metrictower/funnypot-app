<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Pure T-SQL classifier for the high-interaction MSSQL honeypot. Given a decoded SQL batch it decides,
 * without any I/O, what fabricated answer to serve and what intel to log: recon SELECTs get seeded
 * persona result-sets; the sp_configure -> xp_cmdshell exploitation chain is trapped with the full
 * attacker command captured and plausible inert output returned.
 *
 * INERT by construction: this class never calls exec/shell/eval, never opens a file, socket, registry,
 * or database. Every value it returns is a persona constant or a fabricated string. Attacker arguments
 * (shell commands, UNC paths, OLE progids, connection strings) are only parsed as text and captured.
 */
final class MssqlQueryEngine
{
    public function __construct(private MssqlConfig $config)
    {
    }

    /**
     * Classify a whole SQL batch (may contain several statements) into the fabricated response and the
     * intel to log. The batch is also scanned as a whole so a dangerous proc cannot slip past by odd
     * statement splitting.
     */
    public function classify(string $batch, MssqlSession $s): MssqlQueryResult
    {
        $result = new MssqlQueryResult();

        foreach ($this->splitStatements($batch) as $stmt) {
            $stmt = trim($stmt);
            if ($stmt === '') {
                continue;
            }
            $this->classifyStatement($stmt, $batch, $s, $result);
        }

        // Evasion backstop: if per-statement classification captured nothing but the raw batch still
        // names a dangerous proc, capture it from the whole batch so the trap cannot be dodged.
        if ($result->rce === null && ($proc = $this->scanDangerous($batch)) !== null) {
            $this->captureDangerFallback($proc, $batch, $result);
        }

        return $result;
    }

    // ---- Statement classification ------------------------------------------------------------

    private function classifyStatement(string $stmt, string $batch, MssqlSession $s, MssqlQueryResult $result): void
    {
        // sp_configure / RECONFIGURE first: `sp_configure 'xp_cmdshell', 1` names a dangerous proc in
        // its argument but is a configuration statement, not an execution — it must not be mistaken for
        // one by the proc matchers below.
        if (self::names($stmt, 'sp_configure')) {
            $this->handleSpConfigure($stmt, $batch, $result);

            return;
        }
        if (preg_match('/^\s*reconfigure\b/i', $stmt)) {
            $result->events[] = self::queryEvent('RECONFIGURE');

            return;
        }

        // Dangerous / RCE-adjacent procs — these are the trap.
        if (self::names($stmt, 'xp_cmdshell')) {
            $this->trapXpCmdshell($stmt, $batch, $result);

            return;
        }
        if (self::names($stmt, 'xp_dirtree')) {
            $arg = $this->extractLiteralArg($stmt, 'xp_dirtree', $batch);
            $this->trap('xp_dirtree', $arg, $batch, $result);
            $result->resultSets[] = ['columns' => ['subdirectory', 'depth'], 'rows' => []]; // never enumerated

            return;
        }
        if (self::names($stmt, 'xp_fileexist')) {
            $arg = $this->extractLiteralArg($stmt, 'xp_fileexist', $batch);
            $this->trap('xp_fileexist', $arg, $batch, $result);
            $result->resultSets[] = [
                'columns' => ['File Exists', 'File is a Directory', 'Parent Directory Exists'],
                'rows' => [['0', '0', '1']],
            ];

            return;
        }
        if (self::names($stmt, 'xp_subdirs')) {
            $arg = $this->extractLiteralArg($stmt, 'xp_subdirs', $batch);
            $this->trap('xp_subdirs', $arg, $batch, $result);
            $result->resultSets[] = ['columns' => ['subdirectory'], 'rows' => []];

            return;
        }
        if (preg_match('/\bxp_(?:instance_)?reg\w*\b/i', $stmt, $rm)) {
            $proc = strtolower($rm[0]);
            $arg = $this->extractLiteralArg($stmt, $rm[0], $batch);
            $this->trap($proc, $arg, $batch, $result);
            if (stripos($proc, 'write') === false) {
                $result->resultSets[] = ['columns' => ['Value', 'Data'], 'rows' => [['(Default)', '']]];
            }

            return;
        }
        if (preg_match('/\bsp_oa(?:create|method|getproperty|setproperty|destroy)\b/i', $stmt, $om)) {
            $arg = $this->extractLiteralArg($stmt, $om[0], $batch);
            $this->trap(strtolower($om[0]), $arg, $batch, $result);
            $result->returnStatus = 0; // report the OLE call "succeeded"

            return;
        }
        if (self::names($stmt, 'openrowset')) {
            $arg = $this->extractLiteralArg($stmt, 'openrowset', $batch);
            $this->trap('openrowset', $arg, $batch, $result); // SSRF/exfil intent logged, never dialed

            return;
        }
        if (preg_match('/\bbulk\s+insert\b/i', $stmt)) {
            $arg = $this->extractLiteralArg($stmt, 'bulk insert', $batch);
            $this->trap('bulk_insert', $arg, $batch, $result);

            return;
        }

        // USE <db>: change database context (authentic ENVCHANGE + info).
        if (preg_match('/^\s*use\s+\[?([A-Za-z0-9_]+)\]?/i', $stmt, $um)) {
            $db = $um[1];
            $result->newDatabase = $db;
            $result->infoMessages[] = self::infoMsg(5701, 2, 0, "Changed database context to '{$db}'.");
            $result->events[] = self::queryEvent('USE ' . $db);

            return;
        }

        // Recon SELECTs / scalar functions.
        if ($this->classifyRecon($stmt, $s, $result)) {
            return;
        }

        // Any other statement: answer benignly (empty result), never an error — an error-on-everything
        // is itself a tell. Still logged as intel.
        $result->events[] = self::queryEvent($stmt);
    }

    /**
     * Recon SELECTs and scalar functions -> seeded persona result-sets. Returns true if handled. Every
     * value is a persona/seed constant, so a replayed probe always sees the same answer.
     */
    private function classifyRecon(string $stmt, MssqlSession $s, MssqlQueryResult $result): bool
    {
        $low = strtolower($stmt);

        if (str_contains($low, 'sys.databases')) {
            $rows = [];
            $id = 1;
            foreach ($this->config->databaseNames() as $name) {
                $rows[] = [$name, (string) $id++];
            }
            $result->resultSets[] = ['columns' => ['name', 'database_id'], 'rows' => $rows];
            $result->events[] = self::queryEvent($stmt);

            return true;
        }
        if (str_contains($low, 'sys.syslogins') || str_contains($low, 'sys.server_principals')) {
            $rows = [];
            foreach ($this->config->loginNames() as $name) {
                $rows[] = [$name];
            }
            $result->resultSets[] = ['columns' => ['name'], 'rows' => $rows];
            $result->events[] = self::queryEvent($stmt);

            return true;
        }
        if (str_contains($low, 'is_srvrolemember')) {
            // They think they are sysadmin — deepens engagement. NVARCHAR "1" is an accepted simplification.
            return $this->scalar('', '1', $stmt, $result);
        }
        if (str_contains($low, '@@version')) {
            return $this->scalar('', $this->config->bannerVersion(), $stmt, $result);
        }
        if (str_contains($low, '@@servername')
            || preg_match("/serverproperty\s*\(\s*'(?:servername|machinename)'/i", $stmt)) {
            return $this->scalar('', $this->config->serverName, $stmt, $result);
        }
        if (preg_match('/\b(?:system_user|suser_sname|suser_name|current_user|user_name|original_login)\b/i', $stmt)) {
            return $this->scalar('', $s->authUser ?? 'sa', $stmt, $result);
        }
        if (str_contains($low, 'db_name(')) {
            return $this->scalar('', $s->currentDb, $stmt, $result);
        }
        if (str_contains($low, '@@servicename')) {
            return $this->scalar('', $this->config->instanceName, $stmt, $result);
        }
        if (str_contains($low, 'host_name(')) {
            return $this->scalar('', $this->config->serverName, $stmt, $result);
        }

        // A generic SELECT we do not model: an empty result set + DONE (never an error).
        if (preg_match('/^\s*select\b/i', $stmt)) {
            $result->events[] = self::queryEvent($stmt);

            return true;
        }

        return false;
    }

    /** Emit a single unnamed/one-named scalar column with one row. */
    private function scalar(string $column, string $value, string $stmt, MssqlQueryResult $result): bool
    {
        $result->resultSets[] = ['columns' => [$column], 'rows' => [[$value]]];
        $result->events[] = self::queryEvent($stmt);

        return true;
    }

    // ---- The xp_cmdshell / config trap -------------------------------------------------------

    private function trapXpCmdshell(string $stmt, string $batch, MssqlQueryResult $result): void
    {
        $cmd = $this->extractLiteralArg($stmt, 'xp_cmdshell', $batch);
        $this->trap('xp_cmdshell', $cmd, $batch, $result);
        $result->resultSets[] = ['columns' => ['output'], 'rows' => $this->fabricateShellOutput($cmd)];
    }

    /** Record the critical capture for a dangerous proc. The argument is captured, never acted on. */
    private function trap(string $proc, string $arg, string $batch, MssqlQueryResult $result): void
    {
        $result->rce ??= new MssqlCapturedCommand($proc, $arg, $batch);
        $result->events[] = [
            'event' => 'mssql_rce_attempt',
            'severity' => 'critical',
            'reportable' => true,
            'summary' => $proc . ($arg !== '' ? " '{$arg}'" : ''),
            'command' => $arg,
            'proc' => $proc,
        ];
    }

    private function handleSpConfigure(string $stmt, string $batch, MssqlQueryResult $result): void
    {
        // sp_configure 'option', <value> — an enable/disable.
        if (preg_match('/sp_configure\s*(?:\'([^\']*)\'|"([^"]*)"|(\w+))\s*,\s*(\d+)/i', $stmt, $m)) {
            $name = $m[1] !== '' ? $m[1] : ($m[2] !== '' ? $m[2] : $m[3]);
            $value = (int) $m[4];
            $result->infoMessages[] = self::infoMsg(
                5457,
                1,
                0,
                "Configuration option '{$name}' changed from 0 to {$value}. Run the RECONFIGURE statement to install."
            );

            $dangerous = in_array(strtolower($name), [
                'xp_cmdshell',
                'ole automation procedures',
                'clr enabled',
                'ad hoc distributed queries',
            ], true);

            if ($dangerous && $value >= 1) {
                $result->rce ??= new MssqlCapturedCommand('sp_configure', "{$name} = {$value}", $batch);
                $result->events[] = [
                    'event' => 'mssql_rce_attempt',
                    'severity' => 'critical',
                    'reportable' => true,
                    'summary' => "sp_configure {$name}={$value}",
                    'command' => trim($stmt),
                    'proc' => 'sp_configure',
                ];
                if (strtolower($name) === 'xp_cmdshell') {
                    $result->enableXpCmdshell = true;
                }
            } else {
                $result->events[] = self::queryEvent("sp_configure {$name}={$value}");
            }

            return;
        }

        // Bare sp_configure — the run_value / config_value table.
        $result->resultSets[] = [
            'columns' => ['name', 'minimum', 'maximum', 'config_value', 'run_value'],
            'rows' => [
                ['clr enabled', '0', '1', '0', '0'],
                ['Ole Automation Procedures', '0', '1', '0', '0'],
                ['show advanced options', '0', '1', '1', '1'],
                ['xp_cmdshell', '0', '1', '0', '0'],
            ],
        ];
        $result->events[] = self::queryEvent('sp_configure');
    }

    /**
     * Fabricate plausible xp_cmdshell stdout. Most download-cradle commands (powershell -enc, certutil,
     * bitsadmin) write nothing to stdout, so the authentic default is a single NULL row.
     *
     * @return list<list<?string>>
     */
    private function fabricateShellOutput(string $cmd): array
    {
        $low = strtolower($cmd);

        if (str_contains($low, 'whoami')) {
            return [['nt authority\\system']];
        }
        if (str_contains($low, 'hostname')) {
            return [[$this->config->serverName]];
        }
        if (str_contains($low, 'ipconfig')) {
            return [
                ['Windows IP Configuration'],
                [''],
                ['Ethernet adapter Ethernet0:'],
                ['   Connection-specific DNS Suffix  . :'],
                ['   IPv4 Address. . . . . . . . . . . : 10.0.0.15'],
                ['   Subnet Mask . . . . . . . . . . . : 255.255.255.0'],
                ['   Default Gateway . . . . . . . . . : 10.0.0.1'],
            ];
        }
        if (preg_match('/\b(?:dir|type|ls|cat)\b/', $low)) {
            return [
                [' Volume in drive C has no label.'],
                [' Directory of C:\\'],
                [''],
                ['09/24/2019  01:48 PM    <DIR>          Program Files'],
                ['09/24/2019  01:48 PM    <DIR>          Windows'],
                ['               0 File(s)              0 bytes'],
            ];
        }

        // Authentic default: no stdout.
        return [[null]];
    }

    // ---- Parsing helpers ---------------------------------------------------------------------

    /**
     * True if the statement invokes the named proc. Tolerant of EXEC/EXECUTE, master.. / dbo. prefixes,
     * and [bracket] quoting — the proc name is distinctive enough that its presence as a token suffices.
     */
    private static function names(string $stmt, string $proc): bool
    {
        return preg_match('/\b' . preg_quote($proc, '/') . '\b/i', $stmt) === 1;
    }

    /**
     * Extract the first single-quoted string literal after the proc name, un-doubling T-SQL ''.
     * Falls back to resolving a parameter variable (EXEC xp_cmdshell @cmd, with SET @cmd='...' earlier
     * in the batch), else returns the variable name, else ''.
     */
    private function extractLiteralArg(string $stmt, string $proc, string $batch): string
    {
        $pos = stripos($stmt, $proc);
        $rest = $pos === false ? $stmt : substr($stmt, $pos + strlen($proc));

        if (preg_match('/\'((?:[^\']|\'\')*)\'/', $rest, $m)) {
            return str_replace("''", "'", $m[1]);
        }

        if (preg_match('/@(\w+)/', $rest, $vm)) {
            $var = $vm[1];
            if (preg_match('/@' . preg_quote($var, '/') . '\s*=\s*\'((?:[^\']|\'\')*)\'/i', $batch, $bm)) {
                return str_replace("''", "'", $bm[1]);
            }

            return '@' . $var;
        }

        return '';
    }

    /**
     * Split a batch into statements, respecting single-quoted strings so a command that itself contains
     * ';' (a chained PowerShell payload) is not cut apart. GO batch separators split first.
     *
     * @return list<string>
     */
    private function splitStatements(string $batch): array
    {
        $chunks = preg_split('/^\s*GO\s*;?\s*$/mi', $batch) ?: [$batch];
        $out = [];
        foreach ($chunks as $chunk) {
            $cur = '';
            $inStr = false;
            $len = strlen($chunk);
            for ($i = 0; $i < $len; $i++) {
                $c = $chunk[$i];
                if ($c === "'") {
                    if ($inStr && $i + 1 < $len && $chunk[$i + 1] === "'") {
                        $cur .= "''";
                        $i++;
                        continue;
                    }
                    $inStr = !$inStr;
                    $cur .= $c;
                    continue;
                }
                if ($c === ';' && !$inStr) {
                    $out[] = $cur;
                    $cur = '';
                    continue;
                }
                $cur .= $c;
            }
            $out[] = $cur;
        }

        return $out;
    }

    /** The dangerous procs the whole-batch evasion backstop scans for; returns the first present. */
    private function scanDangerous(string $batch): ?string
    {
        $low = strtolower($batch);
        foreach (['xp_cmdshell', 'xp_dirtree', 'xp_fileexist', 'xp_subdirs', 'openrowset'] as $p) {
            if (str_contains($low, $p)) {
                return $p;
            }
        }
        if (preg_match('/\bxp_(?:instance_)?reg\w*\b/i', $batch, $rm)) {
            return strtolower($rm[0]);
        }
        if (preg_match('/\bsp_oa(?:create|method|getproperty|setproperty|destroy)\b/i', $batch, $om)) {
            return strtolower($om[0]);
        }
        if (preg_match('/\bbulk\s+insert\b/i', $batch)) {
            return 'bulk_insert';
        }

        return null;
    }

    private function captureDangerFallback(string $proc, string $batch, MssqlQueryResult $result): void
    {
        $arg = $this->extractLiteralArg($batch, str_replace('_', ' ', $proc) === 'bulk insert' ? 'bulk insert' : $proc, $batch);
        $this->trap($proc, $arg, $batch, $result);
        if ($proc === 'xp_cmdshell') {
            $result->resultSets[] = ['columns' => ['output'], 'rows' => $this->fabricateShellOutput($arg)];
        }
    }

    /**
     * @return array{event:string,severity:string,reportable:bool,summary:string,command:?string,proc:?string}
     */
    private static function queryEvent(string $summary): array
    {
        return [
            'event' => 'mssql_query',
            'severity' => 'medium',
            'reportable' => true,
            'summary' => $summary,
            'command' => null,
            'proc' => null,
        ];
    }

    /**
     * @return array{number:int,state:int,class:int,text:string}
     */
    private static function infoMsg(int $number, int $state, int $class, string $text): array
    {
        return ['number' => $number, 'state' => $state, 'class' => $class, 'text' => $text];
    }
}

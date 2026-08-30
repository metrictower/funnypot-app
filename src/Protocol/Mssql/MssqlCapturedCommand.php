<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * A captured RCE/exfil-adjacent command from a trapped SQL batch. Pure intel — the {@see $rawArg}
 * (the shell command, UNC path, OLE progid, connection string, ...) is only ever logged, never
 * executed, opened, or dialed.
 */
final class MssqlCapturedCommand
{
    public function __construct(
        public string $proc,       // the dangerous proc/technique, e.g. 'xp_cmdshell'
        public string $rawArg,     // the captured argument (command / path / connection string / var name)
        public string $fullBatch   // the full batch text the command arrived in
    ) {
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * The fabricated answer to one SQL batch: the result-sets and info messages to encode back to the
 * client, the intel events to log, and (if the batch touched the RCE chain) the captured command and
 * the signal to flip the session's xp_cmdshell flag. Pure data — {@see MssqlQueryEngine} builds it
 * without any I/O; {@see MssqlServer} encodes and logs it.
 */
final class MssqlQueryResult
{
    /**
     * @param list<array{columns:list<string>,rows:list<list<?string>>}> $resultSets result-sets in wire order
     * @param list<array{number:int,state:int,class:int,text:string}> $infoMessages INFO tokens to emit
     * @param list<array{event:string,severity:string,reportable:bool,summary:string,command:?string,proc:?string}> $events intel to log
     */
    public function __construct(
        public array $resultSets = [],
        public array $infoMessages = [],
        public array $events = [],
        public ?MssqlCapturedCommand $rce = null,
        public bool $enableXpCmdshell = false,
        // Stored-proc return code to emit before DONE (RETURNSTATUS token), e.g. sp_OACreate success.
        public ?int $returnStatus = null,
        // New database context from a USE statement — the server updates the session and emits ENVCHANGE.
        public ?string $newDatabase = null
    ) {
    }
}

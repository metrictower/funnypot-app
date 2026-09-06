<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

/**
 * All mutable state for one Redis TCP connection: negotiated RESP version, selected DB, client
 * identity, the per-session decoy datastore, the fictional CONFIG / replication / persistence state,
 * intent-dedup bookkeeping and the queue of safe telemetry events the connection layer drains after
 * each command. Nothing here is shared between connections.
 *
 * The retained-metadata cap (client name + fictional dir/dbfilename + replica host, spec §5) is
 * accounted here so an attacker cannot grow session memory through repeated CONFIG SET / CLIENT
 * SETNAME. AUTH passwords and MODULE paths are never retained on the session — only length, class and
 * a keyed fingerprint survive command handling.
 */
final class RedisSession
{
    public int $respVersion = 2;
    public int $db = 0;
    public int $clientId;
    public string $clientName = '';
    public string $peerIp = '';

    /** Fictional CONFIG state (only dir/dbfilename are attacker-mutable). */
    public string $dir = '/var/lib/redis';
    public string $dbfilename = 'dump.rdb';

    /** Replication fiction: role master|slave, plus the pretend upstream. */
    public string $role = 'master';
    public string $replicaHost = '';
    public int $replicaPort = 0;
    public string $replicaLinkState = 'connect';

    /** Persistence fiction, advanced by the injected clock (no timer, no sleep). */
    public int $lastSave;
    public bool $bgsaveInProgress = false;
    public int $bgsaveDeadline = 0;
    public int $rdbChangesSinceSave = 0;

    public RedisDatastore $store;

    public bool $close = false;
    public int $commands = 0;

    /** Bumped on every accepted mutation, so the detector can memoise a persistence journey by generation. */
    public int $generation = 0;

    /** Exploit-journey summary (monotonic, O(1)): dangerous content staged + the current dir/dbfilename class. */
    public bool $stagedCron = false;
    public bool $stagedSsh = false;
    public string $configDestClass = 'other';

    /** Intent transitions already reported this session (dedup: one report per journey). */
    /** @var array<string,bool> */
    public array $reportedIntents = [];

    /** Safe, structured telemetry events produced by the last command, drained by the connection. */
    /** @var list<array<string,mixed>> */
    public array $events = [];

    public function __construct(RedisConfig $config, int $clientId = 1)
    {
        $this->clientId = $clientId;
        $this->store = new RedisDatastore($config->baseKeyspace());
        $this->lastSave = $config->now();
    }

    /** Aggregate bytes of the retained non-datastore session strings (spec §5 cap). */
    public function metadataBytes(): int
    {
        return strlen($this->clientName) + strlen($this->dir) + strlen($this->dbfilename) + strlen($this->replicaHost);
    }
}

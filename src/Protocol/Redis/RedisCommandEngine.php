<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

use Funnypot\Protocol\RespCommand;
use Funnypot\Protocol\RespReply;

/**
 * The pure Redis 6.2.24 command engine: an argv-plus-session → reply dispatcher with no socket,
 * datastore-I/O, filesystem, process, DNS or clock dependency of its own (the clock is injected via
 * {@see RedisConfig}). It mutates only the fictional session state and appends safe, structured
 * telemetry events to {@see RedisSession::$events}; it never writes a file, dials a host, loads a
 * module or executes anything.
 *
 * The exposed-Redis exploit journey (CONFIG SET dir/dbfilename → staged cron/ssh value → SAVE/BGSAVE,
 * plus REPLICAOF and MODULE LOAD) is modelled coherently and captured as intent, entirely inert.
 */
final class RedisCommandEngine
{
    /** Fixed CONFIG surface, canonical order, matched by CONFIG GET's glob. */
    private const CONFIG_ORDER = [
        'dir', 'dbfilename', 'appendonly', 'save', 'protected-mode', 'bind', 'port',
        'requirepass', 'replica-read-only', 'maxmemory', 'maxmemory-policy',
    ];

    /** Commands whose datastore mutation a read-only replica must reject. */
    private const WRITE_COMMANDS = [
        'SET' => true, 'MSET' => true, 'DEL' => true, 'EXPIRE' => true, 'PEXPIRE' => true,
        'PERSIST' => true, 'FLUSHDB' => true, 'FLUSHALL' => true,
    ];

    /** The implemented command surface, with [arity, flags, firstkey, lastkey, step] for COMMAND. */
    private const COMMAND_TABLE = [
        'PING' => [-1, ['stale', 'fast'], 0, 0, 0],
        'ECHO' => [2, ['fast'], 0, 0, 0],
        'QUIT' => [1, ['loading', 'stale', 'fast'], 0, 0, 0],
        'HELLO' => [-1, ['no-auth', 'loading', 'stale', 'fast'], 0, 0, 0],
        'AUTH' => [-2, ['no-auth', 'loading', 'stale', 'fast'], 0, 0, 0],
        'SELECT' => [2, ['loading', 'stale', 'fast'], 0, 0, 0],
        'CLIENT' => [-2, ['admin', 'noscript', 'loading', 'stale'], 0, 0, 0],
        'INFO' => [-1, ['loading', 'stale'], 0, 0, 0],
        'COMMAND' => [-1, ['loading', 'stale'], 0, 0, 0],
        'ROLE' => [1, ['loading', 'stale', 'fast'], 0, 0, 0],
        'TIME' => [1, ['loading', 'stale', 'fast'], 0, 0, 0],
        'DBSIZE' => [1, ['readonly', 'fast'], 0, 0, 0],
        'GET' => [2, ['readonly', 'fast'], 1, 1, 1],
        'SET' => [-3, ['write', 'denyoom'], 1, 1, 1],
        'MGET' => [-2, ['readonly', 'fast'], 1, -1, 1],
        'MSET' => [-3, ['write', 'denyoom'], 1, -1, 2],
        'DEL' => [-2, ['write'], 1, -1, 1],
        'EXISTS' => [-2, ['readonly', 'fast'], 1, -1, 1],
        'TYPE' => [2, ['readonly', 'fast'], 1, 1, 1],
        'TTL' => [2, ['readonly', 'fast'], 1, 1, 1],
        'PTTL' => [2, ['readonly', 'fast'], 1, 1, 1],
        'EXPIRE' => [-3, ['write', 'fast'], 1, 1, 1],
        'PEXPIRE' => [-3, ['write', 'fast'], 1, 1, 1],
        'PERSIST' => [2, ['write', 'fast'], 1, 1, 1],
        'KEYS' => [2, ['readonly', 'sort_for_script'], 0, 0, 0],
        'SCAN' => [-2, ['readonly'], 0, 0, 0],
        'FLUSHDB' => [-1, ['write'], 0, 0, 0],
        'FLUSHALL' => [-1, ['write'], 0, 0, 0],
        'CONFIG' => [-2, ['admin', 'noscript', 'loading', 'stale'], 0, 0, 0],
        'SAVE' => [1, ['admin', 'noscript'], 0, 0, 0],
        'BGSAVE' => [-1, ['admin', 'noscript'], 0, 0, 0],
        'LASTSAVE' => [1, ['loading', 'stale', 'fast'], 0, 0, 0],
        'REPLICAOF' => [3, ['admin', 'noscript', 'stale'], 0, 0, 0],
        'SLAVEOF' => [3, ['admin', 'noscript', 'stale'], 0, 0, 0],
        'MODULE' => [-2, ['admin', 'noscript'], 0, 0, 0],
    ];

    public function __construct(private RedisConfig $config)
    {
    }

    /** The number of milliseconds now, from the injected clock. */
    private function nowMs(): int
    {
        return $this->config->now() * 1000;
    }

    /**
     * Execute one command against the session, returning the reply and appending exactly one safe
     * telemetry event to $s->events (a routine command event by default; a higher-signal intent event
     * when the command warrants one).
     */
    public function execute(RespCommand $cmd, RedisSession $s): RespReply
    {
        $this->advanceBgsave($s);
        $s->commands++;
        $before = count($s->events);
        $reply = $this->dispatch($cmd, $s);
        if (count($s->events) === $before) {
            $this->emitCommand($s, $this->canonicalName($cmd));
        }

        return $reply;
    }

    private function dispatch(RespCommand $cmd, RedisSession $s): RespReply
    {
        $name = $cmd->name();
        if ($name === '') {
            return RespReply::error('ERR unknown command \'\', with args beginning with: ');
        }
        if (!isset(self::COMMAND_TABLE[$name])) {
            $this->emitUnknown($s, $cmd);

            return $this->unknownCommandError($cmd);
        }
        if (!$this->checkArity($name, $cmd->count())) {
            return RespReply::error("ERR wrong number of arguments for '" . strtolower($name) . "' command");
        }
        if (isset(self::WRITE_COMMANDS[$name]) && $s->role === 'slave') {
            return RespReply::error("READONLY You can't write against a read only replica.");
        }

        return match ($name) {
            'PING' => $this->cmdPing($cmd),
            'ECHO' => RespReply::bulk($cmd->arg(1)),
            'QUIT' => $this->cmdQuit($s),
            'HELLO' => $this->cmdHello($cmd, $s),
            'AUTH' => $this->cmdAuth($cmd, $s),
            'SELECT' => $this->cmdSelect($cmd, $s),
            'CLIENT' => $this->cmdClient($cmd, $s),
            'INFO' => $this->cmdInfo($cmd, $s),
            'COMMAND' => $this->cmdCommand($cmd, $s),
            'ROLE' => $this->cmdRole($s),
            'TIME' => $this->cmdTime(),
            'DBSIZE' => RespReply::int($s->store->dbsize($s->db, $this->nowMs())),
            'GET' => $this->cmdGet($cmd, $s),
            'SET' => $this->cmdSet($cmd, $s),
            'MGET' => $this->cmdMget($cmd, $s),
            'MSET' => $this->cmdMset($cmd, $s),
            'DEL' => $this->cmdDel($cmd, $s),
            'EXISTS' => $this->cmdExists($cmd, $s),
            'TYPE' => $this->cmdType($cmd, $s),
            'TTL' => $this->cmdTtl($cmd, $s, false),
            'PTTL' => $this->cmdTtl($cmd, $s, true),
            'EXPIRE' => $this->cmdExpire($cmd, $s, false),
            'PEXPIRE' => $this->cmdExpire($cmd, $s, true),
            'PERSIST' => $this->cmdPersist($cmd, $s),
            'KEYS' => $this->cmdKeys($cmd, $s),
            'SCAN' => $this->cmdScan($cmd, $s),
            'FLUSHDB' => $this->cmdFlush($s, false),
            'FLUSHALL' => $this->cmdFlush($s, true),
            'CONFIG' => $this->cmdConfig($cmd, $s),
            'SAVE' => $this->cmdSave($s, false),
            'BGSAVE' => $this->cmdSave($s, true),
            'LASTSAVE' => RespReply::int($s->lastSave),
            'REPLICAOF', 'SLAVEOF' => $this->cmdReplicaof($cmd, $s),
            'MODULE' => $this->cmdModule($cmd, $s),
            default => $this->unknownCommandError($cmd),
        };
    }

    // ---- connection ----------------------------------------------------------------------------

    private function cmdPing(RespCommand $cmd): RespReply
    {
        return $cmd->count() === 2 ? RespReply::bulk($cmd->arg(1)) : RespReply::simple('PONG');
    }

    private function cmdQuit(RedisSession $s): RespReply
    {
        $s->close = true;

        return RespReply::simple('OK');
    }

    private function cmdHello(RespCommand $cmd, RedisSession $s): RespReply
    {
        if ($cmd->count() >= 2) {
            $ver = $cmd->arg(1);
            if ($ver !== '2' && $ver !== '3') {
                return RespReply::error('NOPROTO unsupported protocol version');
            }
            $s->respVersion = (int) $ver;
            // Optional trailing AUTH/SETNAME clauses: record an auth attempt, honour SETNAME, ignore rest.
            $args = $cmd->args();
            for ($i = 2; $i < count($args); $i++) {
                $tok = strtoupper($args[$i]);
                if ($tok === 'AUTH' && isset($args[$i + 2])) {
                    $this->emitAuth($s, $args[$i + 1], $args[$i + 2]);
                    $i += 2;
                } elseif ($tok === 'SETNAME' && isset($args[$i + 1])) {
                    $this->trySetName($s, $args[$i + 1]);
                    $i += 1;
                }
            }
        }

        return RespReply::map([
            [RespReply::bulk('server'), RespReply::bulk('redis')],
            [RespReply::bulk('version'), RespReply::bulk(RedisConfig::VERSION)],
            [RespReply::bulk('proto'), RespReply::int($s->respVersion)],
            [RespReply::bulk('id'), RespReply::int($s->clientId)],
            [RespReply::bulk('mode'), RespReply::bulk('standalone')],
            [RespReply::bulk('role'), RespReply::bulk($s->role === 'master' ? 'master' : 'replica')],
            [RespReply::bulk('modules'), RespReply::array([])],
        ]);
    }

    private function cmdAuth(RespCommand $cmd, RedisSession $s): RespReply
    {
        $args = $cmd->args();
        if (count($args) === 2) {
            $this->emitAuth($s, null, $args[1]);
        } else {
            $this->emitAuth($s, $args[1], $args[2] ?? '');
        }

        // The persona is `on nopass`: Redis 6.2 answers AUTH with the no-password-configured error.
        return RespReply::error('ERR Client sent AUTH, but no password is set. Did you mean AUTH <username> <password>?');
    }

    private function cmdSelect(RespCommand $cmd, RedisSession $s): RespReply
    {
        $idx = $cmd->arg(1);
        if (preg_match('/^-?[0-9]+$/', $idx) !== 1) {
            return RespReply::error('ERR value is not an integer or out of range');
        }
        $n = (int) $idx;
        if ($n < 0 || $n >= RedisConfig::NUM_DBS) {
            return RespReply::error('ERR DB index is out of range');
        }
        $s->db = $n;

        return RespReply::simple('OK');
    }

    private function cmdClient(RespCommand $cmd, RedisSession $s): RespReply
    {
        switch ($cmd->sub()) {
            case 'ID':
                return RespReply::int($s->clientId);
            case 'GETNAME':
                return RespReply::bulk($s->clientName);
            case 'SETNAME':
                if ($cmd->count() !== 3) {
                    return RespReply::error("ERR wrong number of arguments for 'client|setname' command");
                }

                return $this->trySetName($s, $cmd->arg(2))
                    ? RespReply::simple('OK')
                    : RespReply::error('ERR Client names cannot contain spaces, newlines or special characters.');
            case 'INFO':
                return RespReply::verbatim($this->clientInfoLine($s), 'txt');
            case 'SETINFO':
                return RespReply::simple('OK');
            default:
                return RespReply::error("ERR Unknown subcommand or wrong number of arguments for '"
                    . strtolower($cmd->arg(1)) . "'. Try CLIENT HELP.");
        }
    }

    private function trySetName(RedisSession $s, string $name): bool
    {
        if (strlen($name) > RedisConfig::MAX_CLIENT_NAME || preg_match('/[\s\x00-\x1f\x7f]/', $name) === 1) {
            return false;
        }
        // Enforce the retained-metadata cap against the prospective replacement.
        if ($s->metadataBytes() - strlen($s->clientName) + strlen($name) > RedisConfig::MAX_META_BYTES) {
            return false;
        }
        $s->clientName = $name;

        return true;
    }

    private function clientInfoLine(RedisSession $s): string
    {
        return sprintf(
            'id=%d addr=%s:0 laddr=0.0.0.0:6379 fd=8 name=%s age=0 idle=0 flags=N db=%d sub=0 psub=0 '
            . 'ssub=0 multi=-1 watch=0 qbuf=26 qbuf-free=20448 argv-mem=10 multi-mem=0 tot-net-in=0 '
            . 'tot-net-out=0 rbs=1024 rbp=0 obl=0 oll=0 omem=0 tot-mem=0 events=r cmd=client|info user=default '
            . 'redir=-1 resp=%d lib-name= lib-ver=',
            $s->clientId,
            $s->peerIp !== '' ? $s->peerIp : '127.0.0.1',
            $s->clientName,
            $s->db,
            $s->respVersion
        );
    }

    private function cmdTime(): RespReply
    {
        return RespReply::array([RespReply::bulk((string) $this->config->now()), RespReply::bulk('0')]);
    }

    // ---- discovery -----------------------------------------------------------------------------

    private function cmdRole(RedisSession $s): RespReply
    {
        if ($s->role === 'master') {
            return RespReply::array([RespReply::bulk('master'), RespReply::int(0), RespReply::array([])]);
        }

        return RespReply::array([
            RespReply::bulk('slave'),
            RespReply::bulk($s->replicaHost),
            RespReply::int($s->replicaPort),
            RespReply::bulk($s->replicaLinkState === 'up' ? 'connected' : 'connect'),
            RespReply::int(-1),
        ]);
    }

    private function cmdCommand(RespCommand $cmd, RedisSession $s): RespReply
    {
        $sub = $cmd->sub();
        if ($cmd->count() === 1) {
            $items = [];
            foreach (self::COMMAND_TABLE as $n => $meta) {
                $items[] = $this->commandSpec($n, $meta, $s);
            }

            return RespReply::array($items);
        }
        if ($sub === 'COUNT') {
            return RespReply::int(count(self::COMMAND_TABLE));
        }
        if ($sub === 'INFO') {
            $items = [];
            $args = $cmd->args();
            for ($i = 2; $i < count($args); $i++) {
                $n = strtoupper($args[$i]);
                $items[] = isset(self::COMMAND_TABLE[$n])
                    ? $this->commandSpec($n, self::COMMAND_TABLE[$n], $s)
                    : RespReply::nullArray();
            }

            return RespReply::array($items);
        }
        if ($sub === 'DOCS') {
            return $s->respVersion >= 3 ? RespReply::map([]) : RespReply::array([]);
        }

        return RespReply::error('ERR Unknown COMMAND subcommand or wrong number of arguments. Try COMMAND HELP.');
    }

    /** @param array{0:int,1:list<string>,2:int,3:int,4:int} $meta */
    private function commandSpec(string $name, array $meta, RedisSession $s): RespReply
    {
        [$arity, $flags, $first, $last, $step] = $meta;
        $flagReplies = array_map(static fn (string $f): RespReply => RespReply::simple($f), $flags);

        return RespReply::array([
            RespReply::bulk(strtolower($name)),
            RespReply::int($arity),
            $s->respVersion >= 3 ? RespReply::set($flagReplies) : RespReply::array($flagReplies),
            RespReply::int($first),
            RespReply::int($last),
            RespReply::int($step),
            $s->respVersion >= 3 ? RespReply::set([]) : RespReply::array([]), // acl categories
            RespReply::array([]), // tips
            RespReply::array([]), // key specs
            RespReply::array([]), // subcommands
        ]);
    }

    private function cmdInfo(RespCommand $cmd, RedisSession $s): RespReply
    {
        $section = strtolower($cmd->arg(1) !== '' ? $cmd->arg(1) : 'default');

        return RespReply::verbatim($this->buildInfo($section, $s), 'txt');
    }

    // ---- strings -------------------------------------------------------------------------------

    private function cmdGet(RespCommand $cmd, RedisSession $s): RespReply
    {
        $v = $s->store->get($s->db, $cmd->arg(1), $this->nowMs());

        return $v === null ? RespReply::nullBulk() : RespReply::bulk($v);
    }

    private function cmdSet(RespCommand $cmd, RedisSession $s): RespReply
    {
        $args = $cmd->args();
        $key = $args[1];
        $value = $args[2];
        $nx = $xx = $keepTtl = $getOpt = false;
        $px = null;
        $nowMs = $this->nowMs();
        for ($i = 3; $i < count($args); $i++) {
            $opt = strtoupper($args[$i]);
            switch ($opt) {
                case 'NX': $nx = true; break;
                case 'XX': $xx = true; break;
                case 'KEEPTTL': $keepTtl = true; break;
                case 'GET': $getOpt = true; break;
                case 'EX':
                case 'PX':
                    if (!isset($args[$i + 1]) || preg_match('/^-?[0-9]+$/', $args[$i + 1]) !== 1) {
                        return RespReply::error('ERR value is not an integer or out of range');
                    }
                    $n = (int) $args[$i + 1];
                    if ($n <= 0) {
                        return RespReply::error("ERR invalid expire time in 'set' command");
                    }
                    $px = $nowMs + ($opt === 'EX' ? $n * 1000 : $n);
                    $i++;
                    break;
                default:
                    return RespReply::error('ERR syntax error');
            }
        }
        if ($nx && $xx) {
            return RespReply::error('ERR syntax error');
        }
        $exists = $s->store->exists($s->db, $key, $nowMs);
        $old = $getOpt ? $s->store->get($s->db, $key, $nowMs) : null;
        if (($nx && $exists) || ($xx && !$exists)) {
            return $getOpt ? ($old === null ? RespReply::nullBulk() : RespReply::bulk($old)) : RespReply::nullBulk();
        }
        if (!$s->store->set($s->db, $key, $value, $nowMs, $px, $keepTtl)) {
            return RespReply::error("OOM command not allowed when used memory > 'maxmemory'.");
        }
        $this->onMutation($s, [$value]);

        if ($getOpt) {
            return $old === null ? RespReply::nullBulk() : RespReply::bulk($old);
        }

        return RespReply::simple('OK');
    }

    private function cmdMget(RespCommand $cmd, RedisSession $s): RespReply
    {
        $args = $cmd->args();
        $items = [];
        $nowMs = $this->nowMs();
        for ($i = 1; $i < count($args); $i++) {
            $v = $s->store->get($s->db, $args[$i], $nowMs);
            $items[] = $v === null ? RespReply::nullBulk() : RespReply::bulk($v);
        }

        return RespReply::array($items);
    }

    private function cmdMset(RespCommand $cmd, RedisSession $s): RespReply
    {
        $args = $cmd->args();
        if ((count($args) - 1) % 2 !== 0) {
            return RespReply::error("ERR wrong number of arguments for 'mset' command");
        }
        $pairs = [];
        $values = [];
        for ($i = 1; $i < count($args); $i += 2) {
            $pairs[] = [$args[$i], $args[$i + 1]];
            $values[] = $args[$i + 1];
        }
        if (!$s->store->setManyIn($s->db, $pairs, $this->nowMs())) {
            return RespReply::error("OOM command not allowed when used memory > 'maxmemory'.");
        }
        $this->onMutation($s, $values);

        return RespReply::simple('OK');
    }

    private function cmdDel(RespCommand $cmd, RedisSession $s): RespReply
    {
        $args = $cmd->args();
        $n = 0;
        $nowMs = $this->nowMs();
        for ($i = 1; $i < count($args); $i++) {
            if ($s->store->del($s->db, $args[$i], $nowMs)) {
                $n++;
            }
        }

        return RespReply::int($n);
    }

    private function cmdExists(RespCommand $cmd, RedisSession $s): RespReply
    {
        $args = $cmd->args();
        $n = 0;
        $nowMs = $this->nowMs();
        for ($i = 1; $i < count($args); $i++) {
            if ($s->store->exists($s->db, $args[$i], $nowMs)) {
                $n++;
            }
        }

        return RespReply::int($n);
    }

    private function cmdType(RespCommand $cmd, RedisSession $s): RespReply
    {
        return RespReply::simple($s->store->exists($s->db, $cmd->arg(1), $this->nowMs()) ? 'string' : 'none');
    }

    private function cmdTtl(RespCommand $cmd, RedisSession $s, bool $ms): RespReply
    {
        $pttl = $s->store->pttl($s->db, $cmd->arg(1), $this->nowMs());
        if ($pttl === false) {
            return RespReply::int(-2); // no such key
        }
        if ($pttl === null) {
            return RespReply::int(-1); // no expiry
        }

        return RespReply::int($ms ? $pttl : (int) ceil($pttl / 1000));
    }

    private function cmdExpire(RespCommand $cmd, RedisSession $s, bool $ms): RespReply
    {
        $n = $cmd->arg(2);
        if (preg_match('/^-?[0-9]+$/', $n) !== 1) {
            return RespReply::error('ERR value is not an integer or out of range');
        }
        $nowMs = $this->nowMs();
        if (!$s->store->exists($s->db, $cmd->arg(1), $nowMs)) {
            return RespReply::int(0);
        }
        $delta = (int) $n;
        $px = $nowMs + ($ms ? $delta : $delta * 1000);
        if ($delta <= 0) {
            $s->store->del($s->db, $cmd->arg(1), $nowMs); // non-positive expiry deletes immediately
        } else {
            $s->store->setExpiry($s->db, $cmd->arg(1), $px, $nowMs);
        }

        return RespReply::int(1);
    }

    private function cmdPersist(RespCommand $cmd, RedisSession $s): RespReply
    {
        $nowMs = $this->nowMs();
        $pttl = $s->store->pttl($s->db, $cmd->arg(1), $nowMs);
        if ($pttl === false || $pttl === null) {
            return RespReply::int(0);
        }
        $s->store->setExpiry($s->db, $cmd->arg(1), null, $nowMs);

        return RespReply::int(1);
    }

    // ---- keys / scan ---------------------------------------------------------------------------

    private function cmdKeys(RespCommand $cmd, RedisSession $s): RespReply
    {
        $pattern = $cmd->arg(1);
        if (strlen($pattern) > RedisConfig::MAX_GLOB_BYTES) {
            return RespReply::error('ERR glob pattern too long');
        }
        $budget = RedisConfig::GLOB_BUDGET;
        $out = [];
        try {
            foreach ($s->store->sortedKeys($s->db, $this->nowMs()) as $key) {
                if (RedisGlob::match($pattern, $key, $budget)) {
                    $out[] = RespReply::bulk($key);
                }
            }
        } catch (GlobBudgetException $e) {
            return RespReply::error('ERR pattern too complex');
        }

        return RespReply::array($out);
    }

    private function cmdScan(RespCommand $cmd, RedisSession $s): RespReply
    {
        $args = $cmd->args();
        $cursorStr = $args[1];
        if (preg_match('/^[0-9]+$/', $cursorStr) !== 1) {
            return RespReply::error('ERR invalid cursor');
        }
        $cursor = (int) $cursorStr;
        $pattern = null;
        $count = 10;
        $typeFilter = null;
        for ($i = 2; $i < count($args); $i++) {
            $opt = strtoupper($args[$i]);
            if ($opt === 'MATCH' && isset($args[$i + 1]) && $pattern === null) {
                $pattern = $args[$i + 1];
                if (strlen($pattern) > RedisConfig::MAX_GLOB_BYTES) {
                    return RespReply::error('ERR glob pattern too long');
                }
                $i++;
            } elseif ($opt === 'COUNT' && isset($args[$i + 1])) {
                if (preg_match('/^-?[0-9]+$/', $args[$i + 1]) !== 1) {
                    return RespReply::error('ERR value is not an integer or out of range');
                }
                $count = (int) $args[$i + 1];
                if ($count < 1) {
                    return RespReply::error('ERR syntax error');
                }
                $i++;
            } elseif ($opt === 'TYPE' && isset($args[$i + 1]) && $typeFilter === null) {
                $typeFilter = strtolower($args[$i + 1]);
                $i++;
            } else {
                return RespReply::error('ERR syntax error');
            }
        }
        $count = max(1, min($count, RedisConfig::MAX_KEYS)); // hint, clamped
        $keys = $s->store->sortedKeys($s->db, $this->nowMs());
        $total = count($keys);
        $page = array_slice($keys, $cursor, $count);
        $next = ($cursor + $count) >= $total ? 0 : $cursor + $count;

        $out = [];
        $budget = RedisConfig::GLOB_BUDGET;
        try {
            foreach ($page as $key) {
                if ($typeFilter !== null && $typeFilter !== 'string') {
                    continue; // only string keys exist
                }
                if ($pattern === null || RedisGlob::match($pattern, $key, $budget)) {
                    $out[] = RespReply::bulk($key);
                }
            }
        } catch (GlobBudgetException $e) {
            return RespReply::error('ERR pattern too complex');
        }

        return RespReply::array([RespReply::bulk((string) $next), RespReply::array($out)]);
    }

    private function cmdFlush(RedisSession $s, bool $all): RespReply
    {
        if ($all) {
            $s->store->flushall();
        } else {
            $s->store->flushdb($s->db);
        }
        $s->generation++;

        return RespReply::simple('OK');
    }

    // ---- inert exploit journey -----------------------------------------------------------------

    private function cmdConfig(RespCommand $cmd, RedisSession $s): RespReply
    {
        switch ($cmd->sub()) {
            case 'GET':
                return $this->configGet($cmd, $s);
            case 'SET':
                return $this->configSet($cmd, $s);
            case 'RESETSTAT':
                return RespReply::simple('OK');
            case 'REWRITE':
                // Inert: never writes a config file. A server started without one says exactly this.
                return RespReply::error('ERR The server is running without a config file');
            default:
                return RespReply::error('ERR Unknown CONFIG subcommand or wrong number of arguments. Try CONFIG HELP.');
        }
    }

    private function configGet(RespCommand $cmd, RedisSession $s): RespReply
    {
        if ($cmd->count() < 3) {
            return RespReply::error("ERR wrong number of arguments for 'config|get' command");
        }
        $pattern = $cmd->arg(2);
        if (strlen($pattern) > RedisConfig::MAX_GLOB_BYTES) {
            return RespReply::error('ERR glob pattern too long');
        }
        $budget = RedisConfig::GLOB_BUDGET;
        $pairs = [];
        try {
            foreach (self::CONFIG_ORDER as $param) {
                if (RedisGlob::match($pattern, $param, $budget)) {
                    $pairs[] = [RespReply::bulk($param), RespReply::bulk($this->configValue($param, $s))];
                }
            }
        } catch (GlobBudgetException $e) {
            return RespReply::error('ERR pattern too complex');
        }

        return RespReply::map($pairs);
    }

    private function configValue(string $param, RedisSession $s): string
    {
        return match ($param) {
            'dir' => $s->dir,
            'dbfilename' => $s->dbfilename,
            'appendonly' => 'no',
            'save' => '3600 1 300 100 60 10000',
            'protected-mode' => 'no',
            'bind' => '* -::*',
            'port' => '6379',
            'requirepass' => '',
            'replica-read-only' => 'yes',
            'maxmemory' => '0',
            'maxmemory-policy' => 'noeviction',
            default => '',
        };
    }

    private function configSet(RespCommand $cmd, RedisSession $s): RespReply
    {
        if ($cmd->count() !== 4) {
            return RespReply::error("ERR wrong number of arguments for 'config|set' command");
        }
        $param = strtolower($cmd->arg(2));
        $value = $cmd->arg(3);
        if ($param !== 'dir' && $param !== 'dbfilename') {
            return RespReply::error("ERR Unknown option or number of arguments for CONFIG SET - '{$param}'");
        }
        $cap = $param === 'dir' ? RedisConfig::MAX_DIR : RedisConfig::MAX_DBFILENAME;
        $existing = $param === 'dir' ? $s->dir : $s->dbfilename;
        if (strlen($value) > $cap
            || $s->metadataBytes() - strlen($existing) + strlen($value) > RedisConfig::MAX_META_BYTES) {
            return RespReply::error("ERR Invalid argument '" . '(too long)' . "' for CONFIG SET '{$param}'");
        }
        if ($param === 'dir') {
            $s->dir = $value;
        } else {
            $s->dbfilename = $value;
        }
        $s->configDestClass = RedisExploitDetector::classifyConfigDest($s->dir, $s->dbfilename);
        if (in_array($s->configDestClass, ['cron', 'ssh', 'module'], true)) {
            $this->emitIntent($s, 'redis_dangerous_config', 'dangerous-config', 'high', [
                'dest' => $s->configDestClass,
                'param' => $param,
                'len' => strlen($value),
                'fp' => $this->config->fingerprint($value),
            ]);
        }

        return RespReply::simple('OK');
    }

    private function cmdSave(RedisSession $s, bool $background): RespReply
    {
        if ($background) {
            if ($s->bgsaveInProgress) {
                return RespReply::error('ERR Background save already in progress');
            }
            $s->bgsaveInProgress = true;
            $s->bgsaveDeadline = $this->config->now() + RedisConfig::BGSAVE_DEADLINE;
        } else {
            $s->lastSave = $this->config->now();
        }
        $s->rdbChangesSinceSave = 0;
        $this->classifyPersistenceJourney($s, $background);

        return $background ? RespReply::simple('Background saving started') : RespReply::simple('OK');
    }

    /** SAVE/BGSAVE with a dangerous dir/dbfilename and staged content is the exposed-Redis RCE trap. */
    private function classifyPersistenceJourney(RedisSession $s, bool $background): void
    {
        if ($s->configDestClass === 'cron' && $s->stagedCron) {
            $this->emitIntent($s, 'redis_cron_rce_attempt', 'cron-rce', 'critical', [
                'via' => $background ? 'bgsave' : 'save',
                'dir_fp' => $this->config->fingerprint($s->dir . '/' . $s->dbfilename),
            ]);
        } elseif ($s->configDestClass === 'ssh' && $s->stagedSsh) {
            $this->emitIntent($s, 'redis_ssh_key_injection', 'ssh-key', 'critical', [
                'via' => $background ? 'bgsave' : 'save',
                'dir_fp' => $this->config->fingerprint($s->dir . '/' . $s->dbfilename),
            ]);
        }
    }

    private function cmdReplicaof(RespCommand $cmd, RedisSession $s): RespReply
    {
        $host = $cmd->arg(1);
        $port = $cmd->arg(2);
        if (strtoupper($host) === 'NO' && strtoupper($port) === 'ONE') {
            $s->role = 'master';
            $s->replicaHost = '';
            $s->replicaPort = 0;

            return RespReply::simple('OK');
        }
        if (preg_match('/^[0-9]+$/', $port) !== 1 || (int) $port < 1 || (int) $port > 65535) {
            return RespReply::error('ERR Invalid master port');
        }
        // Bounded fiction only — never resolved or dialled.
        $s->role = 'slave';
        $s->replicaHost = substr($host, 0, RedisConfig::MAX_REPLICA_HOST);
        $s->replicaPort = (int) $port;
        $s->replicaLinkState = 'connect';
        $this->emitIntent($s, 'redis_replicaof_attempt', 'replicaof', 'high', [
            'host_kind' => RedisExploitDetector::classifyReplicaHost($host),
            'port_class' => RedisExploitDetector::classifyPort((int) $port),
            'target_fp' => $this->config->fingerprint($host . ':' . $port),
        ]);

        return RespReply::simple('OK');
    }

    private function cmdModule(RespCommand $cmd, RedisSession $s): RespReply
    {
        switch ($cmd->sub()) {
            case 'LIST':
                return RespReply::array([]);
            case 'LOAD':
            case 'LOADEX':
                $path = $cmd->arg(2);
                $this->emitIntent($s, 'redis_module_load_attempt', 'module-load', 'high', [
                    'ext' => RedisExploitDetector::moduleExtension($path),
                    'len' => strlen($path),
                    'path_fp' => $this->config->fingerprint($path),
                ]);

                // Inert: never stat/open/include the path.
                return RespReply::error('ERR Error loading the extension. Please check the server logs.');
            case 'UNLOAD':
                return RespReply::error('ERR Error unloading module: no such module with that name');
            default:
                return RespReply::error('ERR Unknown MODULE subcommand or wrong number of arguments. Try MODULE HELP.');
        }
    }

    // ---- mutation / bgsave bookkeeping ---------------------------------------------------------

    /** @param list<string> $values */
    private function onMutation(RedisSession $s, array $values): void
    {
        $s->generation++;
        $s->rdbChangesSinceSave++;
        foreach ($values as $v) {
            $class = RedisExploitDetector::classifyValue($v);
            if ($class === 'cron') {
                $s->stagedCron = true;
            } elseif ($class === 'ssh') {
                $s->stagedSsh = true;
            }
        }
    }

    /** Complete an in-progress background save once its injected-clock deadline has passed. */
    private function advanceBgsave(RedisSession $s): void
    {
        if ($s->bgsaveInProgress && $this->config->now() >= $s->bgsaveDeadline) {
            $s->bgsaveInProgress = false;
            $s->lastSave = $s->bgsaveDeadline;
        }
    }

    // ---- INFO builder --------------------------------------------------------------------------

    private function buildInfo(string $section, RedisSession $s): string
    {
        $all = $section === 'all' || $section === 'everything' || $section === 'default';
        $out = '';
        if ($all || $section === 'server') {
            $out .= "# Server\r\n"
                . 'redis_version:' . RedisConfig::VERSION . "\r\n"
                . "redis_git_sha1:00000000\r\n"
                . "redis_git_dirty:0\r\n"
                . 'redis_build_id:' . $this->config->buildId() . "\r\n"
                . "redis_mode:standalone\r\n"
                . 'os:' . $this->config->osString() . "\r\n"
                . "arch_bits:64\r\n"
                . "multiplexing_api:epoll\r\n"
                . 'process_id:' . $this->config->processId() . "\r\n"
                . 'run_id:' . $this->config->runId() . "\r\n"
                . "tcp_port:6379\r\n"
                . 'uptime_in_seconds:' . $this->config->uptimeSeconds() . "\r\n"
                . 'uptime_in_days:' . intdiv($this->config->uptimeSeconds(), 86400) . "\r\n"
                . "config_file:\r\n\r\n";
        }
        if ($all || $section === 'clients') {
            $out .= "# Clients\r\nconnected_clients:1\r\nblocked_clients:0\r\nmaxclients:10000\r\n\r\n";
        }
        if ($all || $section === 'memory') {
            $mem = $this->config->usedMemoryBytes();
            $out .= "# Memory\r\n"
                . 'used_memory:' . $mem . "\r\n"
                . 'used_memory_human:' . sprintf('%.2fM', $mem / 1048576) . "\r\n"
                . "maxmemory:0\r\n"
                . "maxmemory_human:0B\r\n"
                . "maxmemory_policy:noeviction\r\n"
                . "mem_fragmentation_ratio:1.10\r\n\r\n";
        }
        if ($all || $section === 'persistence') {
            $out .= "# Persistence\r\n"
                . "loading:0\r\n"
                . 'rdb_changes_since_last_save:' . $s->rdbChangesSinceSave . "\r\n"
                . 'rdb_bgsave_in_progress:' . ($s->bgsaveInProgress ? 1 : 0) . "\r\n"
                . 'rdb_last_save_time:' . $s->lastSave . "\r\n"
                . "rdb_last_bgsave_status:ok\r\n"
                . "aof_enabled:0\r\n"
                . "aof_last_bgrewrite_status:ok\r\n\r\n";
        }
        if ($all || $section === 'stats') {
            $out .= "# Stats\r\ntotal_connections_received:1\r\ntotal_commands_processed:"
                . $s->commands . "\r\nexpired_keys:0\r\nkeyspace_hits:0\r\nkeyspace_misses:0\r\n\r\n";
        }
        if ($all || $section === 'replication') {
            $out .= $this->replicationSection($s);
        }
        if ($all || $section === 'cpu') {
            $out .= "# CPU\r\nused_cpu_sys:0.10\r\nused_cpu_user:0.20\r\n\r\n";
        }
        if ($all || $section === 'keyspace') {
            $out .= $this->keyspaceSection($s);
        }

        return rtrim($out, "\r\n") . "\r\n";
    }

    private function replicationSection(RedisSession $s): string
    {
        if ($s->role === 'master') {
            return "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n"
                . 'master_failover_state:no-failover' . "\r\n"
                . "master_replid:" . $this->config->runId() . "\r\nmaster_repl_offset:0\r\n\r\n";
        }

        return "# Replication\r\nrole:slave\r\n"
            . 'master_host:' . $s->replicaHost . "\r\n"
            . 'master_port:' . $s->replicaPort . "\r\n"
            . 'master_link_status:' . ($s->replicaLinkState === 'up' ? 'up' : 'down') . "\r\n"
            . "master_sync_in_progress:0\r\nslave_read_only:1\r\nconnected_slaves:0\r\n\r\n";
    }

    private function keyspaceSection(RedisSession $s): string
    {
        $out = "# Keyspace\r\n";
        $nowMs = $this->nowMs();
        for ($i = 0; $i < RedisConfig::NUM_DBS; $i++) {
            $n = $s->store->dbsize($i, $nowMs);
            if ($n > 0) {
                $out .= "db{$i}:keys={$n},expires=0,avg_ttl=0\r\n";
            }
        }

        return $out . "\r\n";
    }

    // ---- errors + telemetry --------------------------------------------------------------------

    private function checkArity(string $name, int $argc): bool
    {
        $arity = self::COMMAND_TABLE[$name][0];

        return $arity >= 0 ? $argc === $arity : $argc >= -$arity;
    }

    private function unknownCommandError(RespCommand $cmd): RespReply
    {
        $args = $cmd->args();
        $name = substr($args[0], 0, 128); // bounded reflection — never an amplification vector
        $argStr = '';
        for ($i = 1; $i < count($args) && strlen($argStr) < 128; $i++) {
            $argStr .= "'" . substr($args[$i], 0, 128 - strlen($argStr)) . "', ";
        }

        return RespReply::error("ERR unknown command '{$name}', with args beginning with: {$argStr}");
    }

    private function canonicalName(RespCommand $cmd): string
    {
        $name = $cmd->name();

        return isset(self::COMMAND_TABLE[$name]) ? $name : 'unknown';
    }

    private function emitCommand(RedisSession $s, string $name): void
    {
        $s->events[] = [
            'event' => 'redis_command',
            'name' => $name,
            'path' => '/redis/command/' . $name,
            'reportable' => false,
            'severity' => 'medium',
        ];
    }

    private function emitUnknown(RedisSession $s, RespCommand $cmd): void
    {
        $raw = $cmd->arg(0);
        $s->events[] = [
            'event' => 'redis_command',
            'name' => 'unknown',
            'path' => '/redis/command/unknown',
            'reportable' => false,
            'severity' => 'low',
            'body' => json_encode(['event' => 'unknown_command', 'len' => strlen($raw), 'fp' => $this->config->fingerprint($raw)]),
        ];
    }

    private function emitAuth(RedisSession $s, ?string $user, string $pass): void
    {
        // Captured locally only (credential harvest); never externally reported, never retained raw.
        $s->events[] = [
            'event' => 'redis_auth_attempt',
            'path' => '/redis/intent/auth',
            'reportable' => false,
            'severity' => 'medium',
            'body' => json_encode([
                'event' => 'redis_auth_attempt',
                'has_user' => $user !== null && $user !== '',
                'len' => strlen($pass),
                'fp' => $this->config->fingerprint($pass),
            ]),
        ];
    }

    /**
     * Emit a high-signal intent event. The first occurrence of each event type in a session is
     * externally reportable; later ones are local-only, so one journey consumes the report slot once.
     *
     * @param array<string,string|int> $params allowlisted class/length/32-hex-fingerprint parameters
     */
    private function emitIntent(RedisSession $s, string $event, string $route, string $severity, array $params): void
    {
        $reportable = !isset($s->reportedIntents[$event]);
        $s->reportedIntents[$event] = true;

        $pathParams = '';
        foreach ($params as $k => $v) {
            $pathParams .= ' ' . $k . '=' . $v;
        }
        $s->events[] = [
            'event' => $event,
            'path' => '/redis/intent/' . $route . $pathParams,
            'reportable' => $reportable,
            'severity' => $severity,
            'body' => json_encode(['event' => $event] + $params),
        ];
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Engagement\Confidence;
use Funnypot\App\Engagement\EngagementAnalytics;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EpisodeKey;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\IdentityBasis;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\Stage;
use LogicException;
use PDO;
use Throwable;

/**
 * Engagement episodes + events in their OWN engagement.sqlite (one file per concern,
 * docs/DATA-LAYER-DECISION.md): the hit writers queue up to 3 s on their WAL lock, while this store
 * must never queue at all, so sharing a file would put a 5 ms writer behind a 3000 ms one.
 *
 * Three tables:
 *   - engagement_episodes  one row per episode: the keyed evidence digest it groups on, basis +
 *                          confidence, started_at / last_seen (INTEGER epoch from the injected
 *                          clock), and additive counters so summaries never re-scan events;
 *   - engagement_events    one row per typed event ({@see EngagementEvent}); nullable LLM columns
 *                          persist NULL, never 0, when usage was unavailable;
 *   - engagement_state     fixed-name saturating counters and the row/byte gauges the inline caps read.
 *
 * resolveAndRecord() follows {@see TarpitBudget::acquire()}: one raw `BEGIN IMMEDIATE`, read the
 * gauges + the current episode under the write lock, decide new-vs-continue, cap-check, insert,
 * COMMIT — or ROLLBACK to a no-op on any fault. The busy timeout is clamped to 5 ms AFTER the shared
 * {@see Sqlite::open()} (which sets 3000 ms): an observer sheds on contention, it never waits on a
 * request's critical path. The caller is the one deciding responses; nothing here can change one.
 *
 * Global ceilings are enforced from O(1) gauges kept in engagement_state (a COUNT(*) over 250k rows
 * on every write would eat the latency budget). The retention pass recounts them after bulk deletes.
 *
 * Identity caveats are part of the data, not a footnote: NAT/shared proxies merge unrelated clients
 * into one network-basis episode, address/UA rotation splits one client across several, and a copied
 * artifact links reuse events without saying who holds it — hence basis + confidence on every row.
 */
final class SqliteEngagementStore implements EngagementStore, EngagementAnalytics
{
    public const BUSY_TIMEOUT_MS = 5;

    /** Logical retained-byte accounting per row; the caps meter these, not on-disk pages. */
    public const EVENT_ROW_BYTES = 256;
    public const EPISODE_ROW_BYTES = 192;

    public const RECENT_LIMIT_MAX = 50;

    /** Saturation ceiling for every counter: 2^53-1, exact in JSON. */
    private const COUNTER_MAX = 9007199254740991;

    /** Every fixed-name counter/gauge, so health() reads a closed set. */
    private const COUNTERS = [
        'event_rows', 'bytes_total', 'shed_episode_cap', 'shed_global_rows', 'shed_global_bytes', 'clock_rollback', 'fault',
    ];

    private const RETAIN_CHUNK = 2000;

    private ?PDO $db = null;

    /** @var callable():int */
    private $clock;

    /** @var callable(string,string):string */
    private $id;

    /** @var array<string,\PDOStatement> */
    private array $stmt = [];

    /**
     * @param callable(string,string):string|null $idFactory mints stored ids (domain, material) — the
     *        install-local {@see \Funnypot\App\Engagement\AnalyticsKey::id()}; null opens a
     *        maintenance/read instance that can prune and summarise but can never record
     * @param callable():int|null $clock shared integer UTC-epoch clock (defaults to time()); the SAME
     *        clock the recorder uses, so cross-worker episode boundaries agree
     */
    public function __construct(
        private string $dbPath,
        private EngagementCaps $caps,
        ?callable $idFactory = null,
        ?callable $clock = null
    ) {
        $this->id = $idFactory ?? static function (string $domain, string $material): string {
            throw new LogicException('engagement store opened without an id factory (maintenance instance)');
        };
        $this->clock = $clock ?? static fn (): int => time();
    }

    /** The conventional engagement.sqlite path beside the hit db — derived in ONE place. */
    public static function defaultPath(string $hitDbPath): string
    {
        return \dirname($hitDbPath) . '/engagement.sqlite';
    }

    public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string
    {
        $db = null;
        try {
            $db = $this->db();
            $now = ($this->clock)();
            $hasArtifact = $event->artifactId !== null ? 1 : 0;

            $db->exec('BEGIN IMMEDIATE');

            $gauges = $this->gauges();
            if ($gauges['event_rows'] >= $this->caps->globalMaxRows) {
                $this->bump('shed_global_rows');
                $db->exec('COMMIT');

                return self::SHED;
            }
            if ($gauges['bytes_total'] + self::EVENT_ROW_BYTES + self::EPISODE_ROW_BYTES > $this->caps->globalMaxBytes) {
                $this->bump('shed_global_bytes');
                $db->exec('COMMIT');

                return self::SHED;
            }

            $ep = $this->currentEpisode($key->digest);
            $fresh = $ep === null;
            $rollback = false;
            if ($ep !== null) {
                if ($now < $ep['last_seen']) {
                    // Clock went backwards: never lengthen an episode — start a bounded new one.
                    $fresh = true;
                    $rollback = true;
                } elseif ($now - $ep['last_seen'] > $this->caps->idleGapS || $now - $ep['started_at'] >= $this->caps->lifetimeS) {
                    $fresh = true;
                }
            }

            if (!$fresh) {
                if ($ep['event_count'] >= $this->caps->maxEventsPerEpisode
                    || $ep['bytes_accum'] + self::EVENT_ROW_BYTES > $this->caps->maxBytesPerEpisode
                    || ($hasArtifact === 1 && $ep['artifact_count'] >= $this->caps->maxArtifactsPerEpisode)) {
                    $this->bump('shed_episode_cap');
                    $db->exec('COMMIT');

                    return self::SHED;
                }
            }

            $counters = [
                ':art' => $hasArtifact,
                ':bo' => $event->bytesOut,
                ':wall' => $event->serverWallMs,
                ':lk' => $event->serverLlmUsageAvailable ? 1 : 0,
                ':lc' => $event->serverLlmCalls ?? 0,
                ':lt' => $event->serverLlmTokens ?? 0,
                ':ru' => $event->attackerRequestUnits,
                ':tt' => $event->attackerToolTurns,
                ':poll' => $event->eventKind === EventKind::JOB_POLLED ? 1 : 0,
                ':reuse' => $event->eventKind === EventKind::ARTIFACT_REUSED ? 1 : 0,
                ':rank' => Stage::rank($event->stage),
            ];

            // PDO binds every execute() value as TEXT. Comparison operators apply the column's
            // INTEGER affinity to a bound text, but functions (MAX) do not — so any bound value
            // used inside a function must be CAST, or TEXT would always compare above INTEGER.
            if ($fresh) {
                // A fresh episode id: keyed over the digest + start + a nonce, so a rollback-forced
                // split within one second cannot collide with the episode it replaces.
                $episodeId = ($this->id)('episode', $key->digest . '|' . $now . '|' . bin2hex(random_bytes(8)));
                $this->prepared(
                    'insert_episode',
                    'INSERT INTO engagement_episodes (episode_id, evidence_digest, identity_basis, identity_confidence,
                        started_at, last_seen, event_count, artifact_count, bytes_accum, bytes_out, server_wall_ms,
                        llm_known_events, server_llm_calls, server_llm_tokens, request_units, tool_turns, polls,
                        reuse_count, max_stage_rank, active_span_s)
                     VALUES (:id, :d, :b, :c, :now, :now, 1, :art, :rb, :bo, :wall, :lk, :lc, :lt, :ru, :tt, :poll, :reuse, :rank, 0)'
                )->execute($counters + [
                    ':id' => $episodeId, ':d' => $key->digest, ':b' => $key->basis, ':c' => $key->confidence,
                    ':now' => $now, ':rb' => self::EVENT_ROW_BYTES,
                ]);
                if ($rollback) {
                    $this->bump('clock_rollback');
                }
            } else {
                $episodeId = $ep['episode_id'];
                // The gap is ≤ idleGapS by construction (a larger one started a fresh episode), so
                // active_span_s is the "active span with capped idle gaps" the summaries expose.
                $this->prepared(
                    'update_episode',
                    'UPDATE engagement_episodes SET last_seen = :now, event_count = event_count + 1,
                        artifact_count = artifact_count + :art, bytes_accum = bytes_accum + :rb,
                        bytes_out = bytes_out + :bo, server_wall_ms = server_wall_ms + :wall,
                        llm_known_events = llm_known_events + :lk, server_llm_calls = server_llm_calls + :lc,
                        server_llm_tokens = server_llm_tokens + :lt, request_units = request_units + :ru,
                        tool_turns = tool_turns + :tt, polls = polls + :poll, reuse_count = reuse_count + :reuse,
                        max_stage_rank = MAX(max_stage_rank, CAST(:rank AS INTEGER)), active_span_s = active_span_s + :gap
                     WHERE episode_id = :id'
                )->execute($counters + [
                    ':id' => $episodeId, ':now' => $now, ':rb' => self::EVENT_ROW_BYTES, ':gap' => $now - $ep['last_seen'],
                ]);
            }

            $this->prepared(
                'insert_event',
                'INSERT INTO engagement_events (ts, episode_id, identity_basis, identity_confidence, lure_id, artifact_id,
                    stage, event_kind, bytes_out, server_wall_ms, server_llm_usage_available, server_llm_calls,
                    server_llm_tokens, attacker_request_units, attacker_tool_turns, estimated_context_tokens)
                 VALUES (:ts, :ep, :b, :c, :lure, :artifact, :stage, :kind, :bo, :wall, :avail, :calls, :tokens, :ru, :tt, :est)'
            )->execute([
                ':ts' => $now, ':ep' => $episodeId, ':b' => $key->basis, ':c' => $key->confidence,
                ':lure' => $event->lureId, ':artifact' => $event->artifactId,
                ':stage' => $event->stage, ':kind' => $event->eventKind,
                ':bo' => $event->bytesOut, ':wall' => $event->serverWallMs,
                ':avail' => $event->serverLlmUsageAvailable ? 1 : 0,
                ':calls' => $event->serverLlmCalls, ':tokens' => $event->serverLlmTokens,
                ':ru' => $event->attackerRequestUnits, ':tt' => $event->attackerToolTurns,
                ':est' => $event->estimatedContextTokens(),
            ]);

            $this->bump('event_rows');
            $this->bump('bytes_total', self::EVENT_ROW_BYTES + ($fresh ? self::EPISODE_ROW_BYTES : 0));
            $db->exec('COMMIT');

            return self::RECORDED;
        } catch (Throwable $e) {
            if ($db !== null) {
                try {
                    $db->exec('ROLLBACK');
                } catch (Throwable $e2) {
                    // no active transaction to roll back
                }
                try {
                    $this->bump('fault'); // best-effort; a locked db just loses this count
                } catch (Throwable $e3) {
                    // the counter is health telemetry, never a reason to surface anything
                }
            }

            return self::FAULT;
        }
    }

    // --- operator reads ----------------------------------------------------------------------------

    public function summary(int $sinceEpoch): array
    {
        $db = $this->db();
        $agg = $this->one(
            'SELECT COUNT(*) episodes, COALESCE(SUM(event_count),0) events, COUNT(DISTINCT evidence_digest) keys,
                COALESCE(SUM(active_span_s),0) span, COALESCE(MAX(active_span_s),0) max_span,
                COALESCE(SUM(bytes_out),0) bytes_out, COALESCE(SUM(server_wall_ms),0) wall,
                COALESCE(SUM(request_units),0) ru, COALESCE(SUM(tool_turns),0) tt, COALESCE(SUM(polls),0) polls,
                COALESCE(SUM(reuse_count),0) reuse, COALESCE(SUM(artifact_count),0) artifacts,
                COALESCE(SUM(CASE WHEN llm_known_events = event_count THEN 1 ELSE 0 END),0) llm_known_eps,
                COALESCE(SUM(CASE WHEN llm_known_events = event_count THEN server_llm_calls ELSE 0 END),0) llm_calls,
                COALESCE(SUM(CASE WHEN llm_known_events = event_count THEN server_llm_tokens ELSE 0 END),0) llm_tokens
             FROM engagement_episodes WHERE started_at >= :s',
            [':s' => $sinceEpoch]
        );
        $episodes = (int) $agg['episodes'];
        $keys = (int) $agg['keys'];
        $wall = (int) $agg['wall'];

        $returning = (int) $this->scalar(
            'SELECT COUNT(*) FROM (SELECT evidence_digest FROM engagement_episodes WHERE started_at >= :s
              GROUP BY evidence_digest HAVING COUNT(*) >= 2)',
            [':s' => $sinceEpoch]
        );

        $deepest = array_fill_keys(Stage::all(), 0);
        $st = $db->prepare('SELECT max_stage_rank r, COUNT(*) n FROM engagement_episodes WHERE started_at >= :s GROUP BY max_stage_rank');
        $st->execute([':s' => $sinceEpoch]);
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $name = Stage::fromRank((int) $row['r']);
            if ($name !== null) {
                $deepest[$name] = (int) $row['n'];
            }
        }

        $identity = [];
        foreach (IdentityBasis::all() as $basis) {
            $identity[] = ['basis' => $basis, 'confidence' => IdentityBasis::confidenceOf($basis), 'episodes' => 0];
        }
        $st = $db->prepare('SELECT identity_basis b, COUNT(*) n FROM engagement_episodes WHERE started_at >= :s GROUP BY identity_basis');
        $st->execute([':s' => $sinceEpoch]);
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
            foreach ($identity as $i => $mix) {
                if ($mix['basis'] === $row['b']) {
                    $identity[$i]['episodes'] = (int) $row['n'];
                }
            }
        }

        // Event-level sums are windowed by the SAME episode set (not by event ts), so every number
        // in one summary describes the same episodes.
        $inWindow = '(SELECT episode_id FROM engagement_episodes WHERE started_at >= :s)';
        $lures = array_fill_keys(LureId::all(), 0);
        $st = $db->prepare("SELECT lure_id l, COUNT(*) n FROM engagement_events WHERE lure_id IS NOT NULL AND episode_id IN {$inWindow} GROUP BY lure_id");
        $st->execute([':s' => $sinceEpoch]);
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
            if (array_key_exists($row['l'], $lures)) {
                $lures[$row['l']] = (int) $row['n'];
            }
        }
        $distinctLures = count(array_filter($lures));
        $distinctArtifacts = (int) $this->scalar(
            "SELECT COUNT(DISTINCT artifact_id) FROM engagement_events WHERE artifact_id IS NOT NULL AND episode_id IN {$inWindow}",
            [':s' => $sinceEpoch]
        );
        $est = (int) $this->scalar(
            "SELECT COALESCE(SUM(estimated_context_tokens),0) FROM engagement_events WHERE episode_id IN {$inWindow}",
            [':s' => $sinceEpoch]
        );
        $llmKnown = (int) $agg['llm_known_eps'];

        // Zero-denominator rule: a ratio with nothing under it is null, never 0 — the UI shows a dash.
        return [
            'enabled' => true,
            'episodes' => $episodes,
            'events' => (int) $agg['events'],
            'evidence_keys' => $keys,
            'returning_keys' => $returning,
            'continuation_ratio' => $keys > 0 ? round($returning / $keys, 3) : null,
            'events_per_episode' => $episodes > 0 ? round(((int) $agg['events']) / $episodes, 2) : null,
            'avg_active_span_s' => $episodes > 0 ? intdiv((int) $agg['span'], $episodes) : null,
            'max_active_span_s' => (int) $agg['max_span'],
            'deepest_stage' => $deepest,
            'identity' => $identity,
            'lures' => $lures,
            'distinct_lures' => $distinctLures,
            'distinct_artifacts' => $distinctArtifacts,
            'artifacts' => (int) $agg['artifacts'],
            'artifact_reuse' => (int) $agg['reuse'],
            'polls' => (int) $agg['polls'],
            'tool_turns' => (int) $agg['tt'],
            'request_units' => (int) $agg['ru'],
            'bytes_out' => (int) $agg['bytes_out'],
            'server_wall_ms' => $wall,
            'llm' => [
                'episodes_known' => $llmKnown,
                'episodes_unknown' => $episodes - $llmKnown,
                'calls' => $llmKnown > 0 ? (int) $agg['llm_calls'] : null,
                'tokens' => $llmKnown > 0 ? (int) $agg['llm_tokens'] : null,
            ],
            // Everything under `estimated` is derived (bytes/4), not measured — labelled as such wherever shown.
            'estimated' => [
                'context_tokens' => $est,
                'context_tokens_per_server_ms' => $wall > 0 ? round($est / $wall, 2) : null,
            ],
            'health' => $this->health(),
        ];
    }

    public function recent(int $sinceEpoch, int $limit): array
    {
        $limit = max(1, min(self::RECENT_LIMIT_MAX, $limit));
        $st = $this->db()->prepare(
            'SELECT p.episode_id, p.identity_basis, p.identity_confidence, p.started_at, p.last_seen, p.active_span_s,
                p.event_count, p.artifact_count, p.bytes_out, p.server_wall_ms, p.request_units, p.tool_turns, p.polls,
                p.reuse_count, p.max_stage_rank, p.llm_known_events, p.server_llm_calls, p.server_llm_tokens,
                (SELECT COUNT(DISTINCT lure_id) FROM engagement_events e WHERE e.episode_id = p.episode_id AND e.lure_id IS NOT NULL) lures,
                (SELECT COALESCE(SUM(estimated_context_tokens),0) FROM engagement_events e WHERE e.episode_id = p.episode_id) est
             FROM engagement_episodes p WHERE p.started_at >= :s ORDER BY p.last_seen DESC LIMIT ' . $limit
        );
        $st->execute([':s' => $sinceEpoch]);
        $out = [];
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $known = (int) $r['llm_known_events'] === (int) $r['event_count'] && (int) $r['event_count'] > 0;
            $out[] = [
                'id_short' => substr((string) $r['episode_id'], 0, 12),
                'basis' => (string) $r['identity_basis'],
                'confidence' => (string) $r['identity_confidence'],
                'started_at' => (int) $r['started_at'],
                'last_seen' => (int) $r['last_seen'],
                'active_span_s' => (int) $r['active_span_s'],
                'events' => (int) $r['event_count'],
                'lures' => (int) $r['lures'],
                'artifacts' => (int) $r['artifact_count'],
                'artifact_reuse' => (int) $r['reuse_count'],
                'polls' => (int) $r['polls'],
                'tool_turns' => (int) $r['tool_turns'],
                'request_units' => (int) $r['request_units'],
                'deepest_stage' => Stage::fromRank((int) $r['max_stage_rank']) ?? Stage::DISCOVER,
                'bytes_out' => (int) $r['bytes_out'],
                'server_wall_ms' => (int) $r['server_wall_ms'],
                'llm_calls' => $known ? (int) $r['server_llm_calls'] : null,
                'llm_tokens' => $known ? (int) $r['server_llm_tokens'] : null,
                'estimated_context_tokens' => (int) $r['est'],
            ];
        }

        return $out;
    }

    public function health(): array
    {
        $out = ['enabled' => true, 'busy_timeout_ms' => self::BUSY_TIMEOUT_MS];
        foreach (self::COUNTERS as $k) {
            $out[$k] = 0;
        }
        try {
            $st = $this->db()->query('SELECT k, v FROM engagement_state');
            foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
                if (in_array($row['k'], self::COUNTERS, true)) {
                    $out[$row['k']] = (int) $row['v'];
                }
            }
            $out['db_bytes'] = $this->sizeBytes();
        } catch (Throwable $e) {
            $out['db_bytes'] = 0;
        }

        return $out;
    }

    // --- retention (the timer's pass; never called from a request) ---------------------------------

    /** Drop events/episodes older than $days (integer-epoch compare). Rows removed. */
    public function retainDays(int $days): int
    {
        if ($days <= 0) {
            return 0;
        }
        $db = $this->db();
        $cutoff = ($this->clock)() - $days * 86400;
        $st = $db->prepare('DELETE FROM engagement_events WHERE ts < :c');
        $st->execute([':c' => $cutoff]);
        $n = $st->rowCount();
        $st = $db->prepare('DELETE FROM engagement_episodes WHERE last_seen < :c');
        $st->execute([':c' => $cutoff]);
        $n += $st->rowCount();
        $this->recount();
        if ($n > 0) {
            $db->exec('PRAGMA incremental_vacuum');
        }

        return $n;
    }

    /**
     * Cap the on-disk footprint: checkpoint, then delete the oldest events in chunks until the
     * wal-inclusive size is under $maxBytes or nothing is left; episodes left without events go too.
     */
    public function retainBytes(int $maxBytes): int
    {
        if ($maxBytes <= 0) {
            return 0;
        }
        $this->checkpointWal();
        if ($this->sizeBytes() <= $maxBytes) {
            return 0;
        }
        $db = $this->db();
        $removed = 0;
        while (true) {
            $this->checkpointWal();
            if ($this->sizeBytes() <= $maxBytes) {
                break;
            }
            // A pinned wal cannot truncate; once the main file alone is under cap, further deletes
            // would only grow the wal — stop and let a later pass finish (the RawCapture guard).
            if ($this->mainSizeBytes() <= $maxBytes) {
                break;
            }
            $affected = (int) $db->exec(
                'DELETE FROM engagement_events WHERE id IN (SELECT id FROM engagement_events ORDER BY id ASC LIMIT ' . self::RETAIN_CHUNK . ')'
            );
            if ($affected === 0) {
                break;
            }
            $removed += $affected;
            $db->exec('PRAGMA incremental_vacuum');
        }
        if ($removed > 0) {
            $db->exec('DELETE FROM engagement_episodes WHERE episode_id NOT IN (SELECT DISTINCT episode_id FROM engagement_events)');
            $this->recount();
        }

        return $removed;
    }

    /** Refresh the O(1) gauges the inline caps read from the real row counts (after bulk deletes). */
    public function recount(): void
    {
        $events = (int) $this->scalar('SELECT COUNT(*) FROM engagement_events');
        $episodes = (int) $this->scalar('SELECT COUNT(*) FROM engagement_episodes');
        $this->stateSet('event_rows', $events);
        $this->stateSet('bytes_total', $events * self::EVENT_ROW_BYTES + $episodes * self::EPISODE_ROW_BYTES);
    }

    public function sizeBytes(): int
    {
        return $this->mainSizeBytes() + $this->walBytes();
    }

    public function checkpointWal(): void
    {
        try {
            $this->db()->exec('PRAGMA wal_checkpoint(TRUNCATE)');
        } catch (Throwable $e) {
            // best-effort: a concurrent reader can make this busy; the next pass retries
        }
    }

    // --- plumbing ----------------------------------------------------------------------------------

    /** @return array{episode_id:string,started_at:int,last_seen:int,event_count:int,artifact_count:int,bytes_accum:int}|null */
    private function currentEpisode(string $digest): ?array
    {
        $st = $this->prepared(
            'current_episode',
            'SELECT episode_id, started_at, last_seen, event_count, artifact_count, bytes_accum
             FROM engagement_episodes WHERE evidence_digest = :d ORDER BY started_at DESC, rowid DESC LIMIT 1'
        );
        $st->execute([':d' => $digest]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        $st->closeCursor();
        if ($row === false) {
            return null;
        }

        return [
            'episode_id' => (string) $row['episode_id'],
            'started_at' => (int) $row['started_at'],
            'last_seen' => (int) $row['last_seen'],
            'event_count' => (int) $row['event_count'],
            'artifact_count' => (int) $row['artifact_count'],
            'bytes_accum' => (int) $row['bytes_accum'],
        ];
    }

    /** @return array{event_rows:int,bytes_total:int} */
    private function gauges(): array
    {
        $out = ['event_rows' => 0, 'bytes_total' => 0];
        $st = $this->prepared('gauges', "SELECT k, v FROM engagement_state WHERE k IN ('event_rows', 'bytes_total')");
        $st->execute();
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $out[$row['k']] = (int) $row['v'];
        }

        return $out;
    }

    /** Add $n to a fixed-name counter in ONE saturating UPSERT (no read-modify-write race). */
    private function bump(string $k, int $n = 1): void
    {
        if ($n <= 0) {
            return;
        }
        $this->prepared(
            'bump',
            'INSERT INTO engagement_state (k, v) VALUES (:k, CAST(:n AS TEXT))
             ON CONFLICT(k) DO UPDATE SET v = CAST(MIN(CAST(v AS INTEGER) + CAST(excluded.v AS INTEGER), ' . self::COUNTER_MAX . ') AS TEXT)'
        )->execute([':k' => $k, ':n' => $n]);
    }

    private function stateSet(string $k, int $v): void
    {
        $this->db()->prepare('INSERT INTO engagement_state (k, v) VALUES (:k, :v) ON CONFLICT(k) DO UPDATE SET v = excluded.v')
            ->execute([':k' => $k, ':v' => (string) $v]);
    }

    private function prepared(string $name, string $sql): \PDOStatement
    {
        return $this->stmt[$name] ??= $this->db()->prepare($sql);
    }

    /** @param array<string,int|string> $params */
    private function scalar(string $sql, array $params = []): string
    {
        $st = $this->db()->prepare($sql);
        $st->execute($params);
        $v = $st->fetchColumn();

        return $v === false ? '0' : (string) $v;
    }

    /**
     * @param array<string,int|string> $params
     * @return array<string,mixed>
     */
    private function one(string $sql, array $params = []): array
    {
        $st = $this->db()->prepare($sql);
        $st->execute($params);

        return $st->fetch(PDO::FETCH_ASSOC) ?: [];
    }

    private function mainSizeBytes(): int
    {
        $db = $this->db();

        return (int) $db->query('PRAGMA page_count')->fetchColumn() * (int) $db->query('PRAGMA page_size')->fetchColumn();
    }

    private function walBytes(): int
    {
        clearstatcache(true, $this->dbPath . '-wal');

        return (int) @filesize($this->dbPath . '-wal');
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $db = Sqlite::open($this->dbPath);
        // The shared seam sets 3000 ms so hit writers queue through a burst. An observer must do the
        // opposite: shed on contention immediately rather than hold a request worker.
        $db->exec('PRAGMA busy_timeout=' . self::BUSY_TIMEOUT_MS);
        $db->exec(
            'CREATE TABLE IF NOT EXISTS engagement_episodes (
                episode_id TEXT PRIMARY KEY,
                evidence_digest TEXT NOT NULL,
                identity_basis TEXT NOT NULL,
                identity_confidence TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                artifact_count INTEGER NOT NULL DEFAULT 0,
                bytes_accum INTEGER NOT NULL DEFAULT 0,
                bytes_out INTEGER NOT NULL DEFAULT 0,
                server_wall_ms INTEGER NOT NULL DEFAULT 0,
                llm_known_events INTEGER NOT NULL DEFAULT 0,
                server_llm_calls INTEGER NOT NULL DEFAULT 0,
                server_llm_tokens INTEGER NOT NULL DEFAULT 0,
                request_units INTEGER NOT NULL DEFAULT 0,
                tool_turns INTEGER NOT NULL DEFAULT 0,
                polls INTEGER NOT NULL DEFAULT 0,
                reuse_count INTEGER NOT NULL DEFAULT 0,
                max_stage_rank INTEGER NOT NULL DEFAULT 0,
                active_span_s INTEGER NOT NULL DEFAULT 0
            )'
        );
        $db->exec('CREATE INDEX IF NOT EXISTS idx_eng_ep_digest ON engagement_episodes(evidence_digest, started_at)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_eng_ep_started ON engagement_episodes(started_at)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_eng_ep_last ON engagement_episodes(last_seen)');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS engagement_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                episode_id TEXT NOT NULL,
                identity_basis TEXT NOT NULL,
                identity_confidence TEXT NOT NULL,
                lure_id TEXT NULL,
                artifact_id TEXT NULL,
                stage TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                bytes_out INTEGER NOT NULL DEFAULT 0,
                server_wall_ms INTEGER NOT NULL DEFAULT 0,
                server_llm_usage_available INTEGER NOT NULL DEFAULT 0,
                server_llm_calls INTEGER NULL,
                server_llm_tokens INTEGER NULL,
                attacker_request_units INTEGER NOT NULL DEFAULT 0,
                attacker_tool_turns INTEGER NOT NULL DEFAULT 0,
                estimated_context_tokens INTEGER NOT NULL DEFAULT 0
            )'
        );
        $db->exec('CREATE INDEX IF NOT EXISTS idx_eng_ev_episode ON engagement_events(episode_id)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_eng_ev_ts ON engagement_events(ts)');
        $db->exec('CREATE TABLE IF NOT EXISTS engagement_state (k TEXT PRIMARY KEY, v TEXT NOT NULL)');

        return $this->db = $db;
    }
}

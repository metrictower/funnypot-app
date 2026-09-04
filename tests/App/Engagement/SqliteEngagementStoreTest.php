<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\Confidence;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EpisodeKey;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\IdentityBasis;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Storage\SqliteEngagementStore;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The transactional episode store: deterministic grouping, idle-gap / lifetime / clock-rollback
 * splits, per-episode and global caps that shed with a fixed-name counter, NULL-preserving LLM
 * usage, a schema with no raw request fields, fail-closed no-op on faults and lock contention (the
 * 5 ms busy clamp), age/size retention with gauge recount, and the operator aggregates' rules.
 */
final class SqliteEngagementStoreTest extends TestCase
{
    private const T0 = 1_700_000_000;

    /** @var string[] */
    private array $tmp = [];

    private int $now = self::T0;

    private AnalyticsKey $key;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->now = self::T0;
        $this->key = AnalyticsKey::fromRaw(str_repeat('k', 32));
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function path(): string
    {
        $p = sys_get_temp_dir() . '/fp_eng_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function store(?EngagementCaps $caps = null, ?string $path = null): SqliteEngagementStore
    {
        return new SqliteEngagementStore($path ?? $this->path(), $caps ?? new EngagementCaps(), [$this->key, 'id'], function (): int {
            return $this->now;
        });
    }

    private function key(string $material = 'peer-a'): EpisodeKey
    {
        return new EpisodeKey(IdentityBasis::NETWORK_FALLBACK, Confidence::LOW, $this->key->id('episode-evidence', $material));
    }

    private function event(string $stage = Stage::DISCOVER, int $bytes = 4000, ?string $artifact = null, string $kind = EventKind::LURE_FOLLOWED, bool $llmKnown = true): EngagementEvent
    {
        return new EngagementEvent($stage, $kind, $bytes, 7, LureId::LABYRINTH, $artifact, $llmKnown, $llmKnown ? 0 : null, $llmKnown ? 0 : null);
    }

    private function raw(string $path): PDO
    {
        return new PDO('sqlite:' . $path);
    }

    // --- grouping + boundaries ---------------------------------------------------------------------

    public function test_same_key_within_the_idle_gap_is_one_episode(): void
    {
        $s = $this->store();
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()));
        $this->now += 100;
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event(Stage::ENUMERATE)));
        $this->now += 500; // exactly at the 600 s gap — still the same episode (split is strictly greater)
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()));

        $sum = $s->summary(0);
        self::assertSame(1, $sum['episodes']);
        self::assertSame(3, $sum['events']);
        self::assertSame(600, $sum['max_active_span_s'], 'active span sums the (gap-capped) inter-event gaps');
        self::assertSame(1, $sum['deepest_stage'][Stage::ENUMERATE], 'the deepest stage sticks even after a shallower event');
        self::assertSame(2, $s->summary(0)['episodes'] + 1, 'sanity: summary is idempotent');
    }

    public function test_idle_gap_and_different_keys_split_episodes(): void
    {
        $s = $this->store();
        $s->resolveAndRecord($this->key(), $this->event());
        $this->now += 601;
        $s->resolveAndRecord($this->key(), $this->event());
        $s->resolveAndRecord($this->key('peer-b'), $this->event());

        $sum = $s->summary(0);
        self::assertSame(3, $sum['episodes']);
        self::assertSame(2, $sum['evidence_keys']);
        self::assertSame(1, $sum['returning_keys'], 'peer-a came back after idling out');
        self::assertSame(0.5, $sum['continuation_ratio']);
    }

    public function test_absolute_lifetime_splits_an_episode_that_never_idles(): void
    {
        $s = $this->store(new EngagementCaps(idleGapS: 600, lifetimeS: 600));
        for ($i = 0; $i < 7; $i++) {
            self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()));
            $this->now += 100; // never idle, but 600 s of age is the wall
        }
        self::assertSame(2, $s->summary(0)['episodes'], '7 events at 100 s ⇒ ages 0..600 ⇒ split once at the lifetime');
    }

    public function test_clock_rollback_starts_a_new_bounded_episode_and_counts_once(): void
    {
        $s = $this->store();
        $s->resolveAndRecord($this->key(), $this->event());
        $this->now -= 10;
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()));

        $sum = $s->summary(0);
        self::assertSame(2, $sum['episodes'], 'now < last_seen never lengthens an episode');
        self::assertSame(1, $sum['health']['clock_rollback']);
    }

    // --- caps --------------------------------------------------------------------------------------

    public function test_per_episode_event_cap_sheds_and_a_later_episode_records_again(): void
    {
        $s = $this->store(new EngagementCaps(maxEventsPerEpisode: 3));
        for ($i = 0; $i < 3; $i++) {
            self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()));
        }
        self::assertSame(EngagementStore::SHED, $s->resolveAndRecord($this->key(), $this->event()));
        self::assertSame(EngagementStore::SHED, $s->resolveAndRecord($this->key(), $this->event()));
        $sum = $s->summary(0);
        self::assertSame(3, $sum['events']);
        self::assertSame(2, $sum['health']['shed_episode_cap']);

        $this->now += 601;
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()), 'a fresh episode has a fresh cap');
    }

    public function test_per_episode_artifact_cap_sheds_only_artifact_events(): void
    {
        $s = $this->store(new EngagementCaps(maxArtifactsPerEpisode: 1));
        $art = str_repeat('a', 32);
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event(Stage::COLLECT, 10, $art, EventKind::ARTIFACT_FETCHED)));
        self::assertSame(EngagementStore::SHED, $s->resolveAndRecord($this->key(), $this->event(Stage::COLLECT, 10, str_repeat('b', 32), EventKind::ARTIFACT_FETCHED)));
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()), 'a plain event is not subject to the artifact cap');
    }

    public function test_global_row_ceiling_sheds_with_its_own_counter(): void
    {
        $s = $this->store(new EngagementCaps(globalMaxRows: 1000, maxEventsPerEpisode: 100000));
        for ($i = 0; $i < 1000; $i++) {
            self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()));
        }
        self::assertSame(EngagementStore::SHED, $s->resolveAndRecord($this->key(), $this->event()));
        self::assertSame(EngagementStore::SHED, $s->resolveAndRecord($this->key('peer-b'), $this->event()), 'the ceiling is global, not per key');
        $h = $s->health();
        self::assertSame(1000, $h['event_rows']);
        self::assertSame(2, $h['shed_global_rows']);
    }

    public function test_global_byte_ceiling_sheds_with_its_own_counter(): void
    {
        $s = $this->store(new EngagementCaps(globalMaxBytes: 64 * 1024, maxEventsPerEpisode: 100000));
        $recorded = 0;
        for ($i = 0; $i < 1000; $i++) {
            if ($s->resolveAndRecord($this->key(), $this->event()) !== EngagementStore::RECORDED) {
                break;
            }
            $recorded++;
        }
        self::assertLessThan(300, $recorded, '64 KiB / 256 B per event row');
        self::assertGreaterThan(200, $recorded);
        $h = $s->health();
        self::assertSame(1, $h['shed_global_bytes']);
        self::assertLessThanOrEqual(64 * 1024, $h['bytes_total']);
    }

    // --- schema + nullability ----------------------------------------------------------------------

    public function test_unknown_llm_usage_persists_null_and_observed_zero_persists_zero(): void
    {
        $p = $this->path();
        $s = $this->store(null, $p);
        $s->resolveAndRecord($this->key(), $this->event(Stage::DISCOVER, 10, null, EventKind::LURE_FOLLOWED, false));
        $s->resolveAndRecord($this->key(), $this->event(Stage::DISCOVER, 10, null, EventKind::LURE_FOLLOWED, true));

        $rows = $this->raw($p)->query('SELECT server_llm_usage_available a, server_llm_calls c, server_llm_tokens t FROM engagement_events ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        self::assertSame('0', (string) $rows[0]['a']);
        self::assertNull($rows[0]['c'], 'unknown is NULL, never 0');
        self::assertNull($rows[0]['t']);
        self::assertSame('1', (string) $rows[1]['a']);
        self::assertSame('0', (string) $rows[1]['c']);
    }

    public function test_schema_and_rows_carry_no_raw_request_fields(): void
    {
        $p = $this->path();
        $s = $this->store(null, $p);
        $s->resolveAndRecord($this->key('network|r1|203.0.113.9|library'), $this->event());

        $db = $this->raw($p);
        foreach (['engagement_episodes', 'engagement_events', 'engagement_state'] as $table) {
            $cols = $db->query("PRAGMA table_info({$table})")->fetchAll(PDO::FETCH_COLUMN, 1);
            foreach ($cols as $c) {
                self::assertDoesNotMatchRegularExpression(
                    '/^(ip|ua|user_agent|path|body|header|headers|cookie|token|prompt|handle|query|credential)/i',
                    (string) $c,
                    "{$table}.{$c} looks like a raw request field"
                );
            }
        }
        $dump = json_encode($db->query('SELECT * FROM engagement_events')->fetchAll(PDO::FETCH_ASSOC))
            . json_encode($db->query('SELECT * FROM engagement_episodes')->fetchAll(PDO::FETCH_ASSOC));
        self::assertStringNotContainsString('203.0.113.9', $dump, 'the peer address never lands in the store, even inside a key');
        self::assertStringNotContainsString('library', $dump);
        self::assertStringNotContainsString('/admin', $dump);
    }

    public function test_every_stored_id_keeps_at_least_128_bits(): void
    {
        $p = $this->path();
        $s = $this->store(null, $p);
        $s->resolveAndRecord($this->key(), $this->event());
        $row = $this->raw($p)->query('SELECT episode_id, evidence_digest FROM engagement_episodes')->fetch(PDO::FETCH_ASSOC);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32,64}$/', (string) $row['episode_id']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32,64}$/', (string) $row['evidence_digest']);
    }

    // --- faults + contention -----------------------------------------------------------------------

    public function test_storage_fault_is_a_no_op_never_a_throw(): void
    {
        $blocker = sys_get_temp_dir() . '/fp_eng_block_' . bin2hex(random_bytes(6));
        file_put_contents($blocker, 'x');
        $this->tmp[] = $blocker;
        $s = new SqliteEngagementStore($blocker . '/nope/x.sqlite', new EngagementCaps(), [$this->key, 'id']);

        self::assertSame(EngagementStore::FAULT, $s->resolveAndRecord($this->key(), $this->event()));
    }

    public function test_lock_contention_sheds_within_the_5ms_clamp_not_the_3s_default(): void
    {
        $p = $this->path();
        $s = $this->store(null, $p);
        $s->resolveAndRecord($this->key(), $this->event()); // creates the schema

        $holder = $this->raw($p);
        $holder->exec('PRAGMA busy_timeout=0');
        $holder->exec('BEGIN IMMEDIATE'); // another worker holds the write lock

        $t = hrtime(true);
        $status = $s->resolveAndRecord($this->key(), $this->event());
        $ms = (hrtime(true) - $t) / 1_000_000;
        $holder->exec('ROLLBACK');

        self::assertSame(EngagementStore::FAULT, $status, 'a locked db is a no-op, never a wait or a throw');
        self::assertLessThan(500, $ms, 'the observer shed fast — the shared 3000 ms busy_timeout was overridden');
        self::assertSame(EngagementStore::RECORDED, $s->resolveAndRecord($this->key(), $this->event()), 'recovers once the lock is gone');
    }

    /**
     * Two workers = two connections on one file sharing one clock. Interleaved writes must agree on
     * ONE episode (no split, no double-start) and honour ONE cap between them — the write lock, not
     * per-process state, defines the boundary.
     */
    public function test_two_connections_share_one_episode_and_one_cap(): void
    {
        $p = $this->path();
        $caps = new EngagementCaps(maxEventsPerEpisode: 6);
        $a = $this->store($caps, $p);
        $b = $this->store($caps, $p);

        $recorded = 0;
        for ($i = 0; $i < 8; $i++) {
            $this->now += 30;
            $status = ($i % 2 === 0 ? $a : $b)->resolveAndRecord($this->key(), $this->event());
            $recorded += $status === EngagementStore::RECORDED ? 1 : 0;
        }

        self::assertSame(6, $recorded, 'the cap is one ceiling across both workers');
        $sum = $a->summary(0);
        self::assertSame(1, $sum['episodes'], 'both workers appended to the SAME episode');
        self::assertSame(6, $sum['events']);
        self::assertSame(2, $sum['health']['shed_episode_cap']);
        self::assertSame(1, $b->summary(0)['episodes'], 'the other connection reads the same state');

        // After the idle gap, whichever worker arrives first opens the next episode; the other joins it.
        $this->now += 601;
        self::assertSame(EngagementStore::RECORDED, $b->resolveAndRecord($this->key(), $this->event()));
        $this->now += 1;
        self::assertSame(EngagementStore::RECORDED, $a->resolveAndRecord($this->key(), $this->event()));
        self::assertSame(2, $a->summary(0)['episodes']);
    }

    public function test_a_maintenance_instance_cannot_record(): void
    {
        $p = $this->path();
        $s = new SqliteEngagementStore($p, new EngagementCaps());
        self::assertSame(EngagementStore::FAULT, $s->resolveAndRecord($this->key(), $this->event()));
        self::assertSame(0, $s->summary(0)['events']);
    }

    // --- retention ---------------------------------------------------------------------------------

    public function test_retain_days_drops_old_rows_and_recounts_gauges(): void
    {
        $s = $this->store();
        $s->resolveAndRecord($this->key(), $this->event());
        $this->now += 3 * 86400;
        $s->resolveAndRecord($this->key(), $this->event());

        self::assertSame(2, $s->retainDays(1), 'one old event + its episode');
        $h = $s->health();
        self::assertSame(1, $h['event_rows']);
        self::assertSame(SqliteEngagementStore::EVENT_ROW_BYTES + SqliteEngagementStore::EPISODE_ROW_BYTES, $h['bytes_total']);
        self::assertSame(1, $s->summary(0)['episodes']);
        self::assertSame(0, $s->retainDays(0), '0 = no age pruning');
    }

    public function test_retain_bytes_drains_oldest_first_and_orphaned_episodes(): void
    {
        $s = $this->store(new EngagementCaps(maxEventsPerEpisode: 100000));
        for ($i = 0; $i < 300; $i++) {
            $s->resolveAndRecord($this->key(), $this->event());
        }
        self::assertGreaterThan(0, $s->retainBytes(1));
        self::assertSame(0, $s->summary(0)['events']);
        self::assertSame(0, $s->summary(0)['episodes'], 'an episode with no events left is removed too');
        self::assertSame(0, $s->health()['event_rows']);
    }

    // --- operator aggregates -----------------------------------------------------------------------

    public function test_empty_store_reports_null_ratios_not_zero_or_errors(): void
    {
        $sum = $this->store()->summary(0);
        self::assertTrue($sum['enabled']);
        self::assertSame(0, $sum['episodes']);
        self::assertNull($sum['continuation_ratio']);
        self::assertNull($sum['events_per_episode']);
        self::assertNull($sum['avg_active_span_s']);
        self::assertNull($sum['estimated']['context_tokens_per_server_ms']);
        self::assertNull($sum['llm']['calls'], 'nothing observed ⇒ unknown, not 0');
        self::assertSame(array_fill_keys(Stage::all(), 0), $sum['deepest_stage']);
        self::assertSame([], $this->store()->recent(0, 20));
    }

    public function test_unknown_llm_usage_stays_unknown_through_aggregation(): void
    {
        $s = $this->store();
        $s->resolveAndRecord($this->key(), $this->event(Stage::DISCOVER, 10, null, EventKind::LURE_FOLLOWED, true));
        $s->resolveAndRecord($this->key(), $this->event(Stage::DISCOVER, 10, null, EventKind::LURE_FOLLOWED, false));
        $s->resolveAndRecord($this->key('peer-b'), $this->event(Stage::DISCOVER, 10, null, EventKind::LURE_FOLLOWED, true));

        $sum = $s->summary(0);
        self::assertSame(1, $sum['llm']['episodes_known']);
        self::assertSame(1, $sum['llm']['episodes_unknown'], 'one unavailable event makes the whole episode unknown');
        self::assertSame(0, $sum['llm']['calls'], 'the known episode observed zero');
        $recent = $s->recent(0, 5);
        $byBasis = [];
        foreach ($recent as $r) {
            $byBasis[$r['events']] = $r;
        }
        self::assertNull($byBasis[2]['llm_calls'], 'the mixed episode reports unknown');
        self::assertSame(0, $byBasis[1]['llm_calls']);
    }

    public function test_artifact_reuse_links_events_without_promoting_identity(): void
    {
        $s = $this->store();
        $art = $this->key->id('artifact', 'issued-object-1');
        $s->resolveAndRecord($this->key(), $this->event(Stage::COLLECT, 100, $art, EventKind::ARTIFACT_FETCHED));
        $this->now += 700; // new episode, same peer
        $s->resolveAndRecord($this->key(), $this->event(Stage::COLLECT, 100, $art, EventKind::ARTIFACT_REUSED));
        $s->resolveAndRecord($this->key('peer-b'), $this->event(Stage::COLLECT, 100, $art, EventKind::ARTIFACT_REUSED));

        $sum = $s->summary(0);
        self::assertSame(3, $sum['episodes']);
        self::assertSame(1, $sum['distinct_artifacts'], 'one issued object seen across three episodes');
        self::assertSame(2, $sum['artifact_reuse']);
        foreach ($sum['identity'] as $mix) {
            if ($mix['basis'] === IdentityBasis::NETWORK_FALLBACK) {
                self::assertSame(3, $mix['episodes'], 'every episode stays network/low — reuse proves nothing about who');
            } else {
                self::assertSame(0, $mix['episodes']);
            }
        }
    }

    public function test_summary_counts_lures_polls_tool_turns_and_estimates(): void
    {
        $s = $this->store();
        $s->resolveAndRecord($this->key(), new EngagementEvent(Stage::COLLECT, EventKind::LURE_FOLLOWED, 4000, 10, LureId::POLLUTER_LOG, null, true, 0, 0));
        $s->resolveAndRecord($this->key(), new EngagementEvent(Stage::COLLECT, EventKind::JOB_POLLED, 400, 5, null, null, true, 0, 0, 1, 0));
        $s->resolveAndRecord($this->key(), new EngagementEvent(Stage::EXECUTE_ATTEMPT, EventKind::TOOL_TURN, 800, 20, null, null, true, 1, 250, 1, 3));

        $sum = $s->summary(0);
        self::assertSame(1, $sum['lures'][LureId::POLLUTER_LOG]);
        self::assertSame(0, $sum['lures'][LureId::LABYRINTH]);
        self::assertSame(1, $sum['distinct_lures']);
        self::assertSame(1, $sum['polls']);
        self::assertSame(3, $sum['tool_turns']);
        self::assertSame(3, $sum['request_units']);
        self::assertSame(5200, $sum['bytes_out']);
        self::assertSame(35, $sum['server_wall_ms']);
        self::assertSame(1, $sum['llm']['calls']);
        self::assertSame(250, $sum['llm']['tokens']);
        self::assertSame(1300, $sum['estimated']['context_tokens'], 'ceil(4000/4)+ceil(400/4)+ceil(800/4)');
        self::assertSame(round(1300 / 35, 2), $sum['estimated']['context_tokens_per_server_ms']);
        self::assertSame(1, $sum['deepest_stage'][Stage::EXECUTE_ATTEMPT]);
        $r = $s->recent(0, 5)[0];
        self::assertSame(Stage::EXECUTE_ATTEMPT, $r['deepest_stage']);
        self::assertSame(12, strlen($r['id_short']), 'only a short label of the episode id is exposed');
        self::assertArrayNotHasKey('episode_id', $r);
        self::assertArrayNotHasKey('evidence_digest', $r);
    }

    public function test_recent_is_bounded_and_windowed(): void
    {
        $s = $this->store();
        for ($i = 0; $i < 60; $i++) {
            $s->resolveAndRecord($this->key('peer-' . $i), $this->event());
        }
        self::assertCount(SqliteEngagementStore::RECENT_LIMIT_MAX, $s->recent(0, 10000));
        self::assertCount(3, $s->recent(0, 3));
        self::assertSame([], $s->recent($this->now + 1, 10));
    }

    public function test_default_path_sits_beside_the_hit_db(): void
    {
        self::assertSame('/data/engagement.sqlite', SqliteEngagementStore::defaultPath('/data/funnypot.sqlite'));
    }
}

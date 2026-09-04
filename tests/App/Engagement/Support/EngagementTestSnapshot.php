<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement\Support;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EpisodeResolver;
use Funnypot\App\Engagement\SignedHandle;
use Funnypot\App\Storage\SqliteEngagementStore;

/**
 * Test-support only: one isolated synthetic engagement namespace (its own temp SQLite file, its own
 * random analytics key, its own controllable clock) with a bounded aggregate snapshot and a reset.
 * This is the in-process seam a local replay/experiment bootstrap injects; it lives under tests/,
 * is autoloaded only by autoload-dev, and is referenced by nothing in src/ or demo/ — production
 * cannot construct or expose it.
 *
 * snapshot() returns ONLY the closed aggregate fields listed in FIELDS: counts, stages, bytes,
 * usage-availability, labelled estimates and separately labelled measured timing. Never raw hits,
 * episode/evidence ids, paths, bodies, headers, tokens, cookies, prompts or tool schemas.
 */
final class EngagementTestSnapshot
{
    /** The whole snapshot vocabulary. A key outside this list never leaves the seam. */
    public const FIELDS = [
        'episodes', 'events', 'evidence_keys', 'returning_keys', 'continuation_ratio', 'events_per_episode',
        'avg_active_span_s', 'max_active_span_s', 'deepest_stage', 'identity', 'lures', 'distinct_lures',
        'distinct_artifacts', 'artifacts', 'artifact_reuse', 'polls', 'tool_turns', 'request_units', 'bytes_out',
        'server_wall_ms', 'llm', 'estimated', 'health', 'timing',
    ];

    private string $dbPath;
    private AnalyticsKey $key;
    private EngagementCaps $caps;
    private int $now;
    private SqliteEngagementStore $store;
    private EngagementRecorder $recorder;

    /** @var list<float> record() wall times in ms, measured outside the store */
    private array $timings = [];

    private function __construct(EngagementCaps $caps, int $startEpoch)
    {
        $this->caps = $caps;
        $this->now = $startEpoch;
        $this->key = AnalyticsKey::fromRaw(random_bytes(32));
        $this->dbPath = sys_get_temp_dir() . '/fp_eng_ns_' . bin2hex(random_bytes(8)) . '.sqlite';
        $this->open();
    }

    public static function create(?EngagementCaps $caps = null, int $startEpoch = 1_700_000_000): self
    {
        return new self($caps ?? new EngagementCaps(), $startEpoch);
    }

    public function recorder(): EngagementRecorder
    {
        return $this->recorder;
    }

    /** The namespace's own key — for minting synthetic handles in a test. Never a production key. */
    public function key(): AnalyticsKey
    {
        return $this->key;
    }

    public function now(): int
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }

    public function record(string $peerIp, string $userAgent, EngagementEvent $event, ?string $episodeHandle = null): string
    {
        $status = $this->recorder->record($peerIp, $userAgent, $event, $episodeHandle);
        $this->timings[] = $this->recorder->lastCallMs();

        return $status;
    }

    /** @return array<string,mixed> the closed aggregate DTO (FIELDS only) */
    public function snapshot(): array
    {
        $s = $this->store->summary(0);
        unset($s['enabled']);
        if (isset($s['health']) && is_array($s['health'])) {
            unset($s['health']['enabled']);
        }
        $n = count($this->timings);
        $s['timing'] = [
            'measured' => true,
            'samples' => $n,
            'p50_ms' => $n > 0 ? self::percentile($this->timings, 0.50) : null,
            'p95_ms' => $n > 0 ? self::percentile($this->timings, 0.95) : null,
            'p99_ms' => $n > 0 ? self::percentile($this->timings, 0.99) : null,
        ];

        return array_intersect_key($s, array_flip(self::FIELDS));
    }

    /** Wipe THIS namespace only (its own file) and start fresh under the same key and clock. */
    public function reset(): void
    {
        $this->destroy();
        $this->open();
    }

    public function destroy(): void
    {
        unset($this->store, $this->recorder);
        foreach (['', '-wal', '-shm'] as $s) {
            @unlink($this->dbPath . $s);
        }
        $this->timings = [];
    }

    /** @param list<float> $xs */
    public static function percentile(array $xs, float $p): float
    {
        sort($xs);
        $i = (int) ceil($p * count($xs)) - 1;

        return round($xs[max(0, min(count($xs) - 1, $i))], 3);
    }

    private function open(): void
    {
        $clock = function (): int {
            return $this->now;
        };
        $this->store = new SqliteEngagementStore($this->dbPath, $this->caps, [$this->key, 'id'], $clock);
        $this->recorder = new EngagementRecorder(
            $this->store,
            new EpisodeResolver($this->key, new SignedHandle($this->key)),
            $clock
        );
    }
}

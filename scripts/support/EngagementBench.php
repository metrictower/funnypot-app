<?php

declare(strict_types=1);

namespace Funnypot\App\Bench;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EpisodeResolver;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\SignedHandle;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Storage\SqliteEngagementStore;
use InvalidArgumentException;
use PDO;
use ReflectionProperty;
use RuntimeException;

/** Script-only seam: no benchmark hooks belong in the production store interface. */
interface BenchConnection
{
    public function record(int $index): string;

    public function metadata(): array;
}

final class SqliteBenchConnection implements BenchConnection
{
    private SqliteEngagementStore $store;
    private EngagementRecorder $recorder;
    private array $lures;

    public function __construct(string $path, EngagementCaps $caps, AnalyticsKey $key, callable $clock, private int $keys)
    {
        $this->store = new SqliteEngagementStore($path, $caps, [$key, 'id'], $clock);
        $this->recorder = new EngagementRecorder($this->store, new EpisodeResolver($key, new SignedHandle($key)), $clock);
        $this->lures = LureId::all();
    }

    public function record(int $index): string
    {
        $stages = [Stage::DISCOVER, Stage::ENUMERATE, Stage::COLLECT];
        $event = new EngagementEvent(
            $stages[$index % 3], EventKind::LURE_FOLLOWED, 4096 + ($index % 7) * 1024,
            3 + ($index % 5), $this->lures[$index % count($this->lures)], null, true, 0, 0,
        );
        return $this->recorder->record('198.51.100.' . ($index % $this->keys), 'curl/8.0', $event);
    }

    public function metadata(): array
    {
        // Inspect the connection actually measured, after timing; a new PDO would report its own defaults.
        $db = (new ReflectionProperty(SqliteEngagementStore::class, 'db'))->getValue($this->store);
        if (!$db instanceof PDO) {
            return [];
        }
        return [
            'journal_mode' => (string) $db->query('PRAGMA journal_mode')->fetchColumn(),
            'synchronous' => (string) $db->query('PRAGMA synchronous')->fetchColumn(),
            'busy_timeout_ms' => (int) $db->query('PRAGMA busy_timeout')->fetchColumn(),
            'sqlite' => (string) $db->query('SELECT sqlite_version()')->fetchColumn(),
        ];
    }
}

final class EngagementBench
{
    public const WARMUP = 200;
    public const STATUSES = [EngagementStore::RECORDED, EngagementStore::SHED, EngagementStore::FAULT, EngagementStore::DISABLED];

    /** Arguments exclude the script name. This validation performs no filesystem work. */
    public static function parseArguments(array $args): array
    {
        $cold = $args !== [] && end($args) === '--cold';
        if ($cold) {
            array_pop($args);
        }
        if (count($args) > 2) {
            throw new InvalidArgumentException('Expected [events] [keys] [--cold].');
        }
        foreach ($args as $arg) {
            if (!is_string($arg) || preg_match('/^[1-9][0-9]{0,5}$/D', $arg) !== 1) {
                throw new InvalidArgumentException('Expected bounded positive decimal integers.');
            }
        }
        $events = (int) ($args[0] ?? 2000);
        $keys = (int) ($args[1] ?? 50);
        self::checkCounts($events, $keys);
        return ['events' => $events, 'keys' => $keys, 'cold' => $cold];
    }

    /** The factory must return a newly owned connection; it must not retain store/PDO references. */
    public static function measure(int $events, int $keys, bool $cold, callable $factory, callable $advance, ?callable $timer = null): array
    {
        self::checkCounts($events, $keys);
        $timer ??= static fn (): int => hrtime(true);
        $constructions = 0;
        $fresh = static function () use ($factory, &$constructions): BenchConnection {
            $constructions++;
            return $factory();
        };
        $statuses = $warmupStatuses = array_fill_keys(self::STATUSES, 0);
        $ms = [];
        $metadata = [];
        try {
            $connection = $fresh();
            for ($i = 0; $i < self::WARMUP; $i++) {
                self::countStatus($warmupStatuses, $connection->record($i));
            }
            if ($cold) {
                unset($connection);
            }
            for ($i = 0; $i < $events; $i++) {
                $advance($i);
                $start = $timer();
                if ($cold) {
                    $connection = $fresh();
                }
                $status = $connection->record($i);
                $end = $timer();
                if ((!is_int($start) && !is_float($start)) || (!is_int($end) && !is_float($end))
                    || !is_finite((float) $start) || !is_finite((float) $end) || $end < $start) {
                    throw new RuntimeException('Invalid monotonic clock sample.');
                }
                $ms[] = ($end - $start) / 1e6;
                self::countStatus($statuses, $status);
                if ($i === 0) {
                    $metadata = $connection->metadata();
                }
                // Connection/statement destruction is outside timing, before the next construction.
                if ($cold) {
                    unset($connection);
                }
            }
        } finally {
            unset($connection);
        }
        sort($ms, SORT_NUMERIC);
        $percentile = static fn (float $p): float => $ms[max(0, (int) ceil($p * count($ms)) - 1)];
        $drops = $events - $statuses[EngagementStore::RECORDED];
        $withinBudget = $percentile(0.95) <= 5.0; // Never use rounded display values for acceptance.
        $healthy = $drops === 0;
        return [
            'events' => $events, 'evidence_keys' => $keys,
            'mode' => $cold ? 'connection-cold-existing-db' : 'warm',
            'warmup_count' => self::WARMUP, 'measured_count' => count($ms),
            'connection_constructions' => $constructions,
            'warmup_statuses' => $warmupStatuses, 'statuses' => $statuses,
            'p50_ms' => round($percentile(0.50), 3), 'p95_ms' => round($percentile(0.95), 3),
            'p99_ms' => round($percentile(0.99), 3), 'max_ms' => round(end($ms), 3), 'drops' => $drops,
            'journal_mode' => $metadata['journal_mode'] ?? null,
            'synchronous' => $metadata['synchronous'] ?? null,
            'busy_timeout_ms' => $metadata['busy_timeout_ms'] ?? null,
            'sqlite' => $metadata['sqlite'] ?? null,
            'connection_metadata_scope' => 'first measured connection, after timing; null if unavailable',
            'php' => PHP_VERSION,
            'platform' => php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m'),
            'storage' => 'exclusively owned temporary directory',
            'budget_p95_ms' => 5, 'within_budget' => $withinBudget, 'healthy' => $healthy,
            'success' => $withinBudget && $healthy, 'exit_code' => $withinBudget && $healthy ? 0 : 1,
        ];
    }

    private static function checkCounts(int $events, int $keys): void
    {
        if ($events < 1000 || $events > 100000 || $keys < 1 || $keys > 254) {
            throw new InvalidArgumentException('Events must be 1000..100000 and keys 1..254.');
        }
    }

    private static function countStatus(array &$counts, string $status): void
    {
        if (!array_key_exists($status, $counts)) {
            throw new RuntimeException('Unknown engagement status.');
        }
        $counts[$status]++;
    }
}

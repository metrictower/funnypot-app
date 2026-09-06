<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\ReportGate;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Protocol\Redis\RedisConfig;
use Funnypot\Protocol\Redis\RedisSession;
use PHPUnit\Framework\TestCase;

/**
 * The privacy boundary, proven through the REAL persistence + reporting wiring (SqliteHitStore +
 * ReportGate + reporters on temp SQLite, exactly as demo/listen.php wires them): distinct sentinels
 * placed in AUTH, a written value, a replica target, a module path and an unknown argv[0] never reach
 * the hit store or either reporter queue; routine connects/commands queue nothing; only the completed
 * high-signal intents are externally reportable.
 */
final class RedisTelemetryTest extends TestCase
{
    use RedisTestFrames;

    /** @var list<string> */
    private array $tmp = [];

    private const SENTINELS = [
        'SENTINEL_AUTH_ZZ1',
        'SENTINEL_VALUE_ZZ2',
        'sentinelhost-zz3.example.com',
        'SENTINEL_MOD_ZZ4',
        'SENTINELCMD_ZZ5',
    ];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
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

    private function tmpDb(): string
    {
        $p = sys_get_temp_dir() . '/fp_redis_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    public function test_no_raw_sentinel_reaches_sqlite_or_reporters(): void
    {
        $hitsDb = $this->tmpDb();
        $intelDb = $this->tmpDb();
        $store = new SqliteHitStore($hitsDb);
        $abuse = new AbuseIpdb('KEY', $intelDb, ['203.0.113.9']);
        $ti = new ThreatIntelReporter('https://ti.example', 'KEY', $intelDb, ['203.0.113.9']);

        // The exact fail-closed log closure demo/listen.php builds.
        $log = static function (array $entry) use ($store, $abuse, $ti): void {
            $store->append($entry);
            if (ReportGate::shouldReport($entry)) {
                ReportGate::maybeReport($entry, $abuse, $ti, 'redis', 6379, '14,15,18');
            }
        };

        $config = $this->redisConfig(42);
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $s->peerIp = '45.9.148.7';

        $journey = [
            ['AUTH', self::SENTINELS[0]],
            ['SET', 'k', "\n* * * * * bash -c '" . self::SENTINELS[1] . "'\n"],
            ['CONFIG', 'SET', 'dir', '/var/spool/cron'],
            ['CONFIG', 'SET', 'dbfilename', 'root'],
            ['SAVE'],
            ['REPLICAOF', self::SENTINELS[2], '6379'],
            ['MODULE', 'LOAD', '/tmp/' . self::SENTINELS[3] . '.so'],
            [self::SENTINELS[4], 'arg'],
            ['PING'],
        ];
        foreach ($journey as $argv) {
            $this->cmd($e, $s, $argv);
        }
        // Stamp + emit each event exactly as RedisServer would (envelope + ip/port).
        foreach ($s->events as $event) {
            $event['ip'] = $s->peerIp;
            $event['port'] = 6379;
            $event['method'] = 'REDIS';
            $event['proto'] = 'redis';
            $event['matched'] = 1;
            $event['served'] = 1;
            $event['reportable'] ??= false;
            $log($event);
        }

        // 1. No raw sentinel anywhere in the hits table.
        $hitsDump = $this->dumpTable($hitsDb, 'hits');
        foreach (self::SENTINELS as $sentinel) {
            self::assertStringNotContainsString($sentinel, $hitsDump, "sentinel {$sentinel} leaked into the hit store");
        }

        // 2. No raw sentinel in either reporter queue (comment / signals).
        $queueDump = $this->dumpTable($intelDb, 'abuse_queue') . $this->dumpTable($intelDb, 'ti_queue');
        foreach (self::SENTINELS as $sentinel) {
            self::assertStringNotContainsString($sentinel, $queueDump, "sentinel {$sentinel} leaked into a reporter queue");
        }

        // 3. Routine connect/command/AUTH never consume the report slot; the RCE intents do report.
        self::assertGreaterThanOrEqual(1, $abuse->queueCount(), 'a completed high-signal intent must report');
        self::assertGreaterThanOrEqual(1, $ti->queueCount());

        // 4. The safe fingerprint IS present (proof the intel was captured, just not raw).
        $fp = $config->fingerprint('/var/spool/cron/root');
        self::assertStringContainsString($fp, $hitsDump, 'the keyed fingerprint of the write target is retained');
    }

    public function test_routine_only_traffic_reports_nothing(): void
    {
        $intelDb = $this->tmpDb();
        $abuse = new AbuseIpdb('KEY', $intelDb, []);
        $ti = new ThreatIntelReporter('https://ti.example', 'KEY', $intelDb, []);
        $log = static function (array $entry) use ($abuse, $ti): void {
            if (ReportGate::shouldReport($entry)) {
                ReportGate::maybeReport($entry, $abuse, $ti, 'redis', 6379, '14');
            }
        };

        $config = $this->redisConfig(42);
        $e = $this->engine($config);
        $s = new RedisSession($config, 1);
        $s->peerIp = '45.9.148.7';
        foreach ([['PING'], ['GET', 'k'], ['INFO'], ['DBSIZE']] as $argv) {
            $this->cmd($e, $s, $argv);
        }
        foreach ($s->events as $event) {
            $event['ip'] = $s->peerIp;
            $event['reportable'] ??= false;
            $log($event);
        }
        self::assertSame(0, $abuse->queueCount(), 'routine commands are never externally reported');
        self::assertSame(0, $ti->queueCount());
    }

    private function dumpTable(string $dbPath, string $table): string
    {
        $pdo = new \PDO('sqlite:' . $dbPath);
        $out = '';
        $stmt = $pdo->query("SELECT * FROM {$table}");
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $out .= implode('|', array_map(static fn ($v): string => (string) $v, $row)) . "\n";
        }

        return $out;
    }
}

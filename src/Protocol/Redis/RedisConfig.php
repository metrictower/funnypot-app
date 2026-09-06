<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

use Funnypot\App\Identity\RedisIdentity;

/**
 * The fixed contract for the interactive Redis honeypot: one deliberately misconfigured Redis 6.2.24
 * standalone primary (protected-mode off, default user `on nopass`, public 6379), every resource
 * limit clamped, an injectable clock, and the deploy identity that seeds the stable run id / base
 * keyspace and keys the safe telemetry fingerprints.
 *
 * The major/minor is pinned deliberately. Redis 7 protects the file-writing CONFIG/module commands by
 * default; advertising 7.x while accepting them would be a manual-analysis tell, so the persona that
 * accepts the exposed-Redis exploit journey advertises the version where those defaults are open.
 *
 * Every persona value is a pure function of the persona seed, so a re-scan from the same deploy sees
 * one stable host. No value is keyed by attacker IP, day or request order.
 */
final class RedisConfig
{
    /** Pinned advertised persona version. */
    public const VERSION = '6.2.24';

    // Hard resource limits (spec §5). Clamped here so no caller can widen them.
    public const MAX_CONNS = 128;            // global concurrent connections
    public const PER_IP_CONNS = 10;          // per normalized source
    public const IDLE_TIMEOUT = 90;          // seconds
    public const MAX_FRAME = 65536;          // one complete inbound frame (bytes)
    public const MAX_ARGV = 128;             // arguments per command
    public const MAX_KEY_BYTES = 256;
    public const MAX_VALUE_BYTES = 16384;    // 16 KiB
    public const MAX_KEYS = 128;             // per connection, across all DBs
    public const MAX_AGGREGATE_BYTES = 262144; // 256 KiB key+value bytes per connection
    public const MAX_CLIENT_NAME = 128;
    public const MAX_DIR = 512;
    public const MAX_DBFILENAME = 255;
    public const MAX_REPLICA_HOST = 253;
    public const MAX_META_BYTES = 1024;      // retained non-datastore session strings, aggregate
    public const MAX_GLOB_BYTES = 128;
    public const GLOB_BUDGET = 65536;        // state transitions per glob command
    public const MAX_COMMANDS = 500;         // per connection
    public const OUTPUT_HIGH_WATER = 131072; // 128 KiB queued output high-water
    public const OUTPUT_LOW_WATER = 65536;   // 64 KiB resume-pump mark
    public const MAX_REPLY_BYTES = 32768;    // 32 KiB per encoded reply
    public const MAX_COMMANDS_PER_TICK = 16;
    public const DRAIN_DEADLINE = 10;        // seconds a peer's queue may fail to drain
    public const BGSAVE_DEADLINE = 2;        // injected-clock seconds a background save "takes"
    public const NUM_DBS = 16;

    /** @var callable():int */
    private $clock;

    public function __construct(
        public int $personaSeed = 0,
        public string $fingerprintKey = '',
        ?callable $clock = null
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    public static function fromIdentity(RedisIdentity $identity, ?callable $clock = null): self
    {
        return new self($identity->personaSeed(), $identity->redisTelemetryFingerprintKey(), $clock);
    }

    /** Current wall-clock second (injected — the engine never sleeps or reads the clock directly). */
    public function now(): int
    {
        return ($this->clock)();
    }

    /** The stable 40-hex server run id, derived from the persona seed. */
    public function runId(): string
    {
        return substr(hash('sha256', $this->personaSeed . '|redis|run_id'), 0, 40);
    }

    /** A stable 16-hex build id for the INFO Server section. */
    public function buildId(): string
    {
        return substr(hash('sha256', $this->personaSeed . '|redis|build_id'), 0, 16);
    }

    /** Stable process id shown in INFO — a container primary looks like pid 1. */
    public function processId(): int
    {
        return 1;
    }

    /** A stable, plausible kernel/os string for the INFO Server section. */
    public function osString(): string
    {
        $kernels = ['5.4.0-169-generic', '5.15.0-91-generic', '5.10.0-27-amd64', '4.19.0-25-amd64'];
        $idx = (int) (hexdec(substr(hash('sha256', $this->personaSeed . '|redis|kernel'), 0, 8)) % count($kernels));

        return 'Linux ' . $kernels[$idx] . ' x86_64';
    }

    /** Stable server uptime seconds — bounded well below any bare 6-digit 9xxxxx fingerprint token. */
    public function uptimeSeconds(): int
    {
        return 100000 + (int) (hexdec(substr(hash('sha256', $this->personaSeed . '|redis|uptime'), 0, 8)) % 700000);
    }

    /** A stable used-memory byte figure for INFO — plausible for a small cache. */
    public function usedMemoryBytes(): int
    {
        return 900000 + (int) (hexdec(substr(hash('sha256', $this->personaSeed . '|redis|mem'), 0, 8)) % 500000);
    }

    /**
     * The immutable DB 0 base keyspace: a handful of plausible application cache keys, deterministic
     * per deploy. Every new connection starts from a fresh copy of this map (spec §5); DBs 1-15 are
     * empty. Values are short and generic — never a secret, a fingerprint tell or an own-vocabulary term.
     *
     * @return array<string,string>
     */
    public function baseKeyspace(): array
    {
        $seed = $this->personaSeed;
        $pick = static function (array $pool, string $field) use ($seed): string {
            $idx = (int) (hexdec(substr(hash('sha256', $seed . '|redis|' . $field), 0, 8)) % count($pool));

            return $pool[$idx];
        };
        $app = $pick(['app', 'web', 'api', 'site', 'svc'], 'appslug');
        $n = 1000 + (int) (hexdec(substr(hash('sha256', $seed . '|redis|uid'), 0, 6)) % 8000);

        return [
            $app . ':config:version' => '3',
            $app . ':cache:homepage' => 'cached',
            'session:' . substr(hash('sha256', $seed . '|redis|sess'), 0, 24) => 'active',
            'rate_limit:' . $n => '5',
            'queue:jobs:count' => '0',
        ];
    }

    /** HMAC-keyed 32-hex fingerprint of an attacker-controlled value — never the raw bytes. */
    public function fingerprint(string $value): string
    {
        return substr(hash_hmac('sha256', $value, $this->fingerprintKey), 0, 32);
    }
}

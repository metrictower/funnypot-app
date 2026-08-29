<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

use Funnypot\Shell\Host\HostFacts;
use Funnypot\Shell\Host\HostIdentity;

/**
 * A deterministic fleet of seeded Linux hosts for the server control panel. Each host reuses the same
 * generators as the shell (HostIdentity for name/OS, ServerProfile for hardware/gauges, HostFacts for the
 * process/service list), so the fleet row, the detail view, and that host's web terminal all describe ONE
 * coherent box. Host index 0 is "this box" (seeded by the deploy persona seed) so it matches the System
 * panel; the rest are peers seeded off it. All inert — no real host is contacted.
 */
final class Fleet
{
    use SeededInstanceCache;

    private const DATACENTERS = ['fra1', 'iad1', 'lon1', 'ams2', 'sin1', 'nyc3', 'sfo2', 'syd1'];

    private function __construct(private int $seed, private int $count)
    {
    }

    public static function fromSeed(int $seed, int $count = 24): self
    {
        return self::seededInstance(
            $seed . '|' . max(1, $count),
            static function () use ($seed, $count): self {
                return new self($seed, max(1, $count));
            }
        );
    }

    /** Host 0 is the persona box; peers derive from it deterministically. */
    private function serverSeed(int $i): int
    {
        return $i === 0 ? $this->seed : (int) (crc32('fleet|' . $this->seed . '|' . $i) & 0x7fffffff);
    }

    private function status(int $ss): string
    {
        $r = crc32('status|' . $ss) % 100;

        return $r < 82 ? 'running' : ($r < 90 ? 'degraded' : ($r < 96 ? 'stopped' : 'offline'));
    }

    /** Role word from the hostname's leading token (the crc32 scheme's role flavor). */
    private function role(string $host): string
    {
        $t = strtolower((string) (preg_split('/[-0-9]/', $host)[0] ?? $host));

        return $t !== '' ? $t : 'host';
    }

    /**
     * @return list<array{host:string,seed:int,os:string,role:string,status:string,cpuPct:int,memPct:int,memGib:float,diskPct:int,uptimeDays:int,ip:string,dc:string,live:bool}>
     */
    public function servers(): array
    {
        $out = [];
        $seen = [];
        // Skip any peer whose hostname collides with one already taken: hostnames must be unique across
        // the fleet or detail()/the web console would resolve a name to the wrong box (name != seed).
        for ($i = 0; count($out) < $this->count && $i < $this->count * 8; $i++) {
            $ss = $this->serverSeed($i);
            $id = HostIdentity::fromSeed($ss);
            if (isset($seen[$id->hostname()])) {
                continue;
            }
            $seen[$id->hostname()] = true;
            $sp = ServerProfile::fromSeed($ss);
            $status = $i === 0 ? 'running' : $this->status($ss); // host 0 is "this box" — always up
            $live = $status === 'running' || $status === 'degraded';
            $stats = $sp->liveStats();
            $mem = $sp->memory();
            $memPct = (int) round(($stats['memUsedGib'] / max(0.1, $mem['totalGib'])) * 100);
            $out[] = [
                'host' => $id->hostname(),
                'seed' => $ss,
                'os' => $id->distroPretty(),
                'role' => $this->role($id->hostname()),
                'status' => $status,
                'cpuPct' => $live ? (int) $stats['cpuPct'] : 0,
                'memPct' => $live ? $memPct : 0,
                'memGib' => $mem['totalGib'],
                'diskPct' => $sp->storage()['usedPct'],
                'uptimeDays' => $live ? $sp->uptimeDays() : 0,
                'ip' => $sp->primaryIp(),
                'dc' => self::DATACENTERS[crc32('dc|' . $ss) % count(self::DATACENTERS)],
                'live' => $live,
            ];
        }

        return $out;
    }

    /** @return array{summary:array{host:string,...},facts:HostFacts}|null */
    public function detail(string $host): ?array
    {
        foreach ($this->servers() as $s) {
            if (strcasecmp($s['host'], $host) === 0) {
                return ['summary' => $s, 'facts' => new HostFacts($s['seed'])];
            }
        }

        return null;
    }

    /** @return array{total:int,running:int,degraded:int,stopped:int,offline:int} */
    public function aggregate(): array
    {
        $agg = ['total' => 0, 'running' => 0, 'degraded' => 0, 'stopped' => 0, 'offline' => 0];
        foreach ($this->servers() as $s) {
            $agg['total']++;
            $agg[$s['status']]++;
        }

        return $agg;
    }
}

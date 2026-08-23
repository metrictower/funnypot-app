<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT observability-fleet data for a Grafana/Prometheus panel — the internal map an
 * attacker mines for lateral pivots (job/port pairs, down targets naming a host+port to hit next).
 *
 * Design rules (fake-data research + adversarial critique, docs/research/2026-08-23-*):
 *  - Every value is a pure function of the seed: no time()/rand(), stable across cache regenerations so
 *    a scanner re-reading /targets sees the same fleet (a shifting fleet is itself a tell).
 *  - SAFE: every instance address and every down-row error target is RFC1918 (10.x) only — never real
 *    routable space (critique T5/S1). The point of a leaked internal host is that it is internal.
 *  - The job<->port map mirrors real exporter defaults (node 9100, mysqld 9104, ...) so the port an
 *    attacker reads is the port they expect; the value is realism, the addresses are fake.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format), matching ServerProfile so it can promote
 *    into the shared Fake namespace once generators consolidate.
 *
 * Returns plain data only — the skins render and escape it.
 */
final class FakeInfra
{
    /** @var int */
    private $seed;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|infra|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    /** An RFC1918 10.x host — the fleet never advertises real routable space (critique T5/S1). */
    private function privateIp(string $salt): string
    {
        return '10.' . $this->intIn(0, 30, $salt . '|a')
            . '.' . $this->intIn(0, 250, $salt . '|b')
            . '.' . $this->intIn(2, 250, $salt . '|c');
    }

    /**
     * Prometheus scrape targets — 30-120 rows from the exporter job<->port map, ~12% of them down and
     * carrying a `connection refused` error that names an internal host+port to pivot to (all RFC1918).
     *
     * @return list<array{job:string,instance:string,state:string,lastScrape:string,error:string}>
     */
    public function targets(): array
    {
        // job => default exporter port (real exporter defaults; realism, not a signature).
        $jobs = [
            ['node', 9100], ['windows', 9182], ['cadvisor', 8080], ['blackbox', 9115],
            ['mysqld', 9104], ['postgres', 9187], ['redis', 9121], ['mongodb', 9216],
            ['rabbitmq', 15692], ['nginx', 9113], ['haproxy', 9101], ['kafka', 9308],
            ['snmp', 9116], ['pushgateway', 9091], ['prometheus', 9090],
            ['alertmanager', 9093], ['grafana', 3000],
        ];
        $count = $this->intIn(30, 120, 'tgtcount');
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $j = $jobs[$this->h('tgtjob' . $i) % count($jobs)];
            $port = $j[1];
            $instance = $this->privateIp('tgtip' . $i) . ':' . $port;
            $down = ($this->h('tgtstate' . $i) % 100) < 12;      // ~12% down
            $out[] = [
                'job' => $j[0],
                'instance' => $instance,
                'state' => $down ? 'down' : 'up',
                // Prometheus shows "Last Scrape" as an age; down rows scraped longer ago.
                'lastScrape' => $down
                    ? sprintf('%dm %ds ago', $this->intIn(1, 14, 'tgtsc' . $i), $this->intIn(0, 59, 'tgtsc2' . $i))
                    : sprintf('%d.%03ds ago', $this->intIn(1, 29, 'tgtsc' . $i), $this->intIn(0, 999, 'tgtsc3' . $i)),
                // Down-row error names the internal target's own address+port — RFC1918 only.
                'error' => $down
                    ? sprintf('dial tcp %s: connect: connection refused', $instance)
                    : '',
            ];
        }
        return $out;
    }

    /**
     * Fleet inventory — 12-30 distinct hosts drawn from the standard fleet-hostname vocab, each with a
     * role and coarse cpu/mem load. Distinct by construction (pool sorted by a per-host key, then sliced)
     * so no duplicate hostname appears (a duplicate in a fleet table is a tell).
     *
     * @return list<array{host:string,role:string,cpu:string,mem:string,status:string}>
     */
    public function fleet(): array
    {
        // [prefix, count, role]; hostnames are prefix-NN, matching the fleet vocab.
        $groups = [
            ['web-prod', 12, 'Web (nginx)'],
            ['api', 8, 'API service'],
            ['db-master', 1, 'PostgreSQL primary'],
            ['db-replica', 3, 'PostgreSQL replica'],
            ['cache-redis', 4, 'Redis cache'],
            ['worker', 20, 'Async worker'],
            ['k8s-node', 30, 'Kubernetes node'],
            ['lb', 2, 'Load balancer'],
            ['es-data', 6, 'Elasticsearch data'],
            ['kafka', 5, 'Kafka broker'],
        ];
        $pool = [];
        foreach ($groups as $g) {
            for ($n = 1; $n <= $g[1]; $n++) {
                $host = sprintf('%s-%02d', $g[0], $n);
                $pool[] = ['host' => $host, 'role' => $g[2], 'key' => $this->h('flpick|' . $host)];
            }
        }
        // Deterministic order from the per-host key, then take the first N — stable, no duplicates.
        usort($pool, function (array $a, array $b): int {
            if ($a['key'] === $b['key']) {
                return strcmp($a['host'], $b['host']);
            }
            return $a['key'] < $b['key'] ? -1 : 1;
        });
        $take = $this->intIn(12, 30, 'flcount');
        $pool = array_slice($pool, 0, $take);
        $states = ['up', 'up', 'up', 'up', 'up', 'up', 'warn', 'down'];   // ~75% up / ~12% warn / ~12% down
        $out = [];
        foreach ($pool as $p) {
            $host = $p['host'];
            $out[] = [
                'host' => $host,
                'role' => $p['role'],
                'cpu' => number_format($this->intIn(20, 970, 'flcpu|' . $host) / 10, 1) . '%',
                'mem' => number_format($this->intIn(150, 960, 'flmem|' . $host) / 10, 1) . '%',
                'status' => $this->pick($states, 'flstat|' . $host),
            ];
        }
        return $out;
    }

    /**
     * Headline stat-tile metrics for the dashboard top row (all frozen per seed).
     *
     * @return array{reqRate:string,errRate:string,p95:string,cpuPct:string,memPct:string}
     */
    public function metrics(): array
    {
        $rps = $this->intIn(500, 45000, 'reqrate');
        return [
            'reqRate' => $rps >= 1000 ? number_format($rps / 1000, 2) . 'k' : (string) $rps,
            'errRate' => number_format($this->intIn(2, 480, 'errrate') / 100, 2) . '%',
            'p95' => $this->intIn(42, 620, 'p95') . ' ms',
            'cpuPct' => number_format($this->intIn(60, 880, 'cpupct') / 10, 1) . '%',
            'memPct' => number_format($this->intIn(310, 910, 'mempct') / 10, 1) . '%',
        ];
    }
}

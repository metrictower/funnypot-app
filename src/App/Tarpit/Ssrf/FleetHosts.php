<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Render\Fake\Fleet;

/**
 * The 24 servers of the fleet web console, by bare hostname and by their 10.0.x.y address, answering
 * as the console reports them: a running or degraded server has SSH on 22 and its role's port open; a
 * stopped one refuses; an offline one has no route, as the console's own "No route to host" says.
 */
final class FleetHosts implements HostDirectory
{
    /** @var array<string,array{host:string,ip:string,role:string,status:string}>|null */
    private ?array $byHost = null;

    public function __construct(private int $personaSeed)
    {
    }

    /** @return array<string,array{host:string,ip:string,role:string,status:string}> */
    private function roster(): array
    {
        if ($this->byHost === null) {
            $this->byHost = [];
            foreach (Fleet::fromSeed($this->personaSeed)->servers() as $s) {
                $row = ['host' => strtolower((string) $s['host']), 'ip' => (string) $s['ip'], 'role' => (string) $s['role'], 'status' => (string) $s['status']];
                $this->byHost[$row['host']] = $row;
                $this->byHost[$row['ip']] ??= $row;
            }
        }

        return $this->byHost;
    }

    /** @return array{0:string,1:int} the kind and port a role serves */
    public static function roleService(string $role): array
    {
        $r = strtolower($role);
        foreach ([
            ['db', 5432], ['sql', 5432], ['pg', 5432], ['mongo', 5432], ['data', 5432],
        ] as [$w, $p]) {
            if (str_contains($r, $w)) {
                return ['db', $p];
            }
        }
        foreach (['cache' => ['cache', 6379], 'redis' => ['cache', 6379], 'web' => ['admin_ui', 80], 'www' => ['admin_ui', 80],
            'proxy' => ['admin_ui', 80], 'edge' => ['admin_ui', 80], 'mon' => ['metrics', 9100], 'metric' => ['metrics', 9100],
            'build' => ['registry', 5000], 'ci' => ['registry', 5000]] as $w => $svc) {
            if (str_contains($r, $w)) {
                return $svc;
            }
        }

        return ['http_api', 8080];
    }

    public function lookup(string $host): ?NetNode
    {
        $s = $this->roster()[$host] ?? null;
        if ($s === null) {
            return null;
        }
        [$kind, $port] = self::roleService($s['role']);
        $key = 'fl:' . $s['host'];

        return match ($s['status']) {
            'running', 'degraded' => new NetNode($key, $kind, $host, array_values(array_unique([22, $port]))),
            'stopped' => new NetNode($key, $kind, $host, [], 'refused'),
            default => new NetNode($key, $kind, $host, [], 'no_route'),
        };
    }

    public function sample(string $label, int $n): array
    {
        $hosts = array_values(array_filter($this->roster(), static fn (array $s): bool => !str_contains($s['host'], '.')));
        if ($hosts === [] || $n < 1) {
            return [];
        }
        $out = [];
        $start = (int) (hexdec(substr(hash('sha256', 'fleet|' . $label), 0, 7)) % count($hosts));
        for ($i = 0; $i < min($n, 2); $i++) {
            $s = $hosts[($start + $i * 5) % count($hosts)];
            [, $port] = self::roleService($s['role']);
            $out[] = $s['host'] . ':' . $port;
        }

        return $out;
    }
}

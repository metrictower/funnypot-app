<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * The infra wiki's service catalog as hosts on the fake network: a live service answers as its
 * category's archetype on its port, an archived one times out. Built from the wiki's services() array
 * so the two surfaces always agree; the composition root adds it once the wiki is on the same branch.
 */
final class InfraWikiHosts implements HostDirectory
{
    /** @param array<string,array{kind:string,port:int,live:bool}> $hosts */
    private function __construct(private array $hosts)
    {
    }

    /** @param list<array<string,mixed>> $services each with host, port, name, category and status */
    public static function fromServices(array $services): self
    {
        $hosts = [];
        foreach ($services as $s) {
            $host = strtolower(is_string($s['host'] ?? null) ? $s['host'] : '');
            $port = is_int($s['port'] ?? null) ? $s['port'] : 0;
            if ($host === '' || $port < 1 || $port > 65535) {
                continue;
            }
            $hosts[$host] = [
                'kind' => self::kindFor(is_string($s['category'] ?? null) ? $s['category'] : ''),
                'port' => $port,
                'live' => ($s['status'] ?? '') !== 'archived',
            ];
        }

        return new self($hosts);
    }

    public static function kindFor(string $category): string
    {
        $c = strtolower($category);
        foreach (['data' => 'db', 'database' => 'db', 'storage' => 'db', 'cache' => 'cache', 'queue' => 'cache', 'monitor' => 'metrics',
            'observ' => 'metrics', 'registry' => 'registry', 'build' => 'registry', 'admin' => 'admin_ui', 'portal' => 'admin_ui'] as $w => $kind) {
            if (str_contains($c, $w)) {
                return $kind;
            }
        }

        return 'http_api';
    }

    public function lookup(string $host): ?NetNode
    {
        $h = $this->hosts[$host] ?? null;
        if ($h === null) {
            return null;
        }

        return $h['live']
            ? new NetNode('wk:' . $host, $h['kind'], $host, [$h['port']])
            : new NetNode('wk:' . $host, $h['kind'], $host, [], 'timeout');
    }

    public function sample(string $label, int $n): array
    {
        $live = array_keys(array_filter($this->hosts, static fn (array $h): bool => $h['live']));
        if ($live === [] || $n < 1) {
            return [];
        }
        $i = (int) (hexdec(substr(hash('sha256', 'wiki|' . $label), 0, 7)) % count($live));

        return [$live[$i] . ':' . $this->hosts[$live[$i]]['port']];
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\InertSecret;

/**
 * The generated part of the fake internal network: one persona subnet, 10.A.0.0/16 with A in
 * [20, 239], where about 30% of addresses hold a host. Each live host has a kind, one to three open
 * ports and a name `<stem>-<tag>.<zone>.<region>.internal` whose tag only this deploy can produce
 * (NameCodec). Everything is a pure function of the deploy's keys and the index, so every visitor sees
 * the same network and no lookup is ever stored.
 *
 * A dead address times out, as an address with no host does on a routed subnet.
 */
final class InternalNet implements HostDirectory
{
    public const LIVE_PERCENT = 30;

    /** kind => [weight, base port, stems] */
    private const KINDS = [
        'http_api' => [30, 8080, ['billing', 'orders', 'ledger', 'catalog', 'search', 'notify', 'invoice', 'profile', 'pricing', 'quotes']],
        'admin_ui' => [12, 80, ['backoffice', 'support', 'opsdesk', 'reports']],
        'metrics' => [12, 9100, ['exporter', 'telemetry', 'statsd']],
        'registry' => [8, 5000, ['registry', 'artifacts', 'mirror']],
        'db' => [14, 5432, ['pgsql', 'ordersdb', 'reportdb', 'warehouse']],
        'cache' => [12, 6379, ['redis', 'sessions', 'kvstore']],
        'ssh' => [12, 22, ['bastion', 'jump', 'buildbox', 'batch', 'deploy']],
    ];

    private const ZONES = ['http_api' => 'svc', 'admin_ui' => 'svc', 'registry' => 'svc', 'db' => 'data', 'cache' => 'data', 'metrics' => 'ops', 'ssh' => 'ops'];

    private NameCodec $codec;

    public function __construct(private string $netKey, private int $octet, private string $region)
    {
        $this->codec = new NameCodec($netKey);
    }

    /** The persona subnet's second octet, off 10.0/16 (the fleet, Docker and the metadata fakes). */
    public static function octet(string $subnetKey): int
    {
        return 20 + ((int) unpack('N', substr($subnetKey, 0, 4))[1] % 220);
    }

    public function subnetOctet(): int
    {
        return $this->octet;
    }

    public function region(): string
    {
        return $this->region;
    }

    /** @return array{kind:string,stem:string,zone:string,ports:list<int>}|null null when the index holds no host */
    public function profile(int $index): ?array
    {
        if ($index < 0 || $index >= NameCodec::INDEXES || ($index & 255) === 0 || ($index & 255) === 255) {
            return null;
        }
        $h = hash_hmac('sha256', 'node|' . $index, $this->netKey, true);
        if (ord($h[0]) % 100 >= self::LIVE_PERCENT) {
            return null;
        }
        $roll = ord($h[1]) % 100;
        $kind = 'http_api';
        foreach (self::KINDS as $k => [$weight]) {
            if ($roll < $weight) {
                $kind = $k;
                break;
            }
            $roll -= $weight;
        }
        [, $port, $stems] = self::KINDS[$kind];
        $ports = [$port];
        if ($kind === 'http_api' && ord($h[3]) % 3 === 0) {
            $ports[] = 8443;
        }
        if ($kind === 'admin_ui') {
            $ports[] = 443;
        }
        if ($kind !== 'ssh' && ord($h[4]) % 5 < 2) {
            $ports[] = 22;
        }
        $profile = ['kind' => $kind, 'stem' => $stems[ord($h[2]) % count($stems)], 'zone' => self::ZONES[$kind], 'ports' => array_slice($ports, 0, 3)];
        if (!InertSecret::isClean('"' . $this->nameFor($index, $profile) . '"')) {
            return null;
        }

        return $profile;
    }

    /** @param array{kind:string,stem:string,zone:string,ports:list<int>} $profile */
    private function nameFor(int $index, array $profile): string
    {
        return $profile['stem'] . '-' . $this->codec->tag($index) . '.' . $profile['zone'] . '.' . $this->region . '.internal';
    }

    public function name(int $index): ?string
    {
        $p = $this->profile($index);

        return $p === null ? null : $this->nameFor($index, $p);
    }

    public function ip(int $index): string
    {
        return '10.' . $this->octet . '.' . ($index >> 8) . '.' . ($index & 255);
    }

    public function node(int $index): ?NetNode
    {
        $p = $this->profile($index);

        return $p === null ? null : new NetNode('g' . $index, $p['kind'], $this->nameFor($index, $p), $p['ports']);
    }

    public function inSubnet(int $ip): bool
    {
        return ($ip >> 16) === ((10 << 8) | $this->octet);
    }

    public function lookup(string $host): ?NetNode
    {
        if (preg_match('/\A10\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/', $host, $m) === 1) {
            if ((int) $m[1] !== $this->octet || (int) $m[2] > 255 || (int) $m[3] > 255) {
                return null;
            }
            $index = ((int) $m[2] << 8) | (int) $m[3];

            return $this->node($index) ?? new NetNode('gd' . $index, 'http_api', $host, [], 'timeout');
        }
        $suffix = '.' . $this->region . '.internal';
        if (!str_ends_with($host, $suffix) || preg_match('/\A([a-z]{3,12})-([0-9a-z]{6})\.([a-z]{3,4})\z/', substr($host, 0, -strlen($suffix)), $m) !== 1) {
            return null;
        }
        $index = $this->codec->index($m[2]);
        if ($index === null) {
            return null;
        }
        $p = $this->profile($index);
        if ($p === null || $p['stem'] !== $m[1] || $p['zone'] !== $m[3]) {
            return null;
        }

        return new NetNode('g' . $index, $p['kind'], $host, $p['ports']);
    }

    /** Generated live hosts a listing names, chosen by $label. */
    public function sample(string $label, int $n): array
    {
        $out = [];
        $start = (int) unpack('N', hash_hmac('sha256', 'sample|' . $label, $this->netKey, true))[1] % NameCodec::INDEXES;
        for ($i = 0, $steps = 0; count($out) < $n && $steps < 64 * max(1, $n); $steps++) {
            $index = ($start + $steps * 7919) % NameCodec::INDEXES;
            $node = $this->node($index);
            if ($node !== null) {
                $out[] = $node->host . ':' . $node->primaryPort();
                $i++;
            }
        }

        return $out;
    }
}

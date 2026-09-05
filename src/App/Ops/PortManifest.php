<?php

declare(strict_types=1);

namespace Funnypot\App\Ops;

use InvalidArgumentException;

/**
 * The one port inventory: demo/ports.json, one endpoint per bound or published (transport, port) — who
 * binds it inside the container (nginx or which listener process), how each deploy target publishes
 * it, and which host-port aliases forward to it. nginx `listen`s, entrypoint spawns, Dockerfile
 * EXPOSE, deploy publish flags and compose ports are all VIEWS of this file: PortDrift proves they
 * agree and scripts/check-ports.php is the CI/operator entry point. Never read on a request path.
 *
 * Validation is exact rather than lenient: schema and enums, unique ids, one owner per container
 * (transport, port), one publisher per (target, transport, host port), forwards naming an existing
 * same-transport bind, canonical web fixed at tcp/80 + tcp/443, and the file bytes equal to the
 * canonical rendering (sorted, one endpoint per line) so any diff is one line per port.
 */
final class PortManifest
{
    public const SCHEMA = 'funnypot-ports/v1';
    public const TARGETS = ['deploy', 'compose'];
    public const OWNER_KINDS = ['canonical-web', 'nginx-alias', 'listener', 'media-capability'];
    public const TRANSPORTS = ['tcp', 'udp'];

    /** Fixed key order of one serialized endpoint; a missing or unknown key is a schema error. */
    private const KEYS = [
        'endpoint_id', 'service_id', 'process_id', 'owner_kind', 'transport', 'container_port', 'host_port',
        'forward_target_endpoint_id', 'spawn', 'tls', 'targets', 'deploy_opt_in', 'scanner_exposed',
        'runtime_toggleable', 'notes',
    ];

    /**
     * @param array<string,mixed>              $meta      every top-level key except `endpoints`
     * @param list<array<string,mixed>>        $endpoints
     */
    private function __construct(private array $meta, private array $endpoints)
    {
    }

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new InvalidArgumentException("cannot read {$path}");
        }

        return self::fromJson($raw);
    }

    public static function fromJson(string $json): self
    {
        $doc = json_decode($json, true);
        if (!is_array($doc)) {
            throw new InvalidArgumentException('ports manifest is not a JSON object: ' . json_last_error_msg());
        }

        return self::fromArray($doc);
    }

    /**
     * Structural load only — shape problems are reported by validate(), not thrown here, so a checker
     * can list every problem at once.
     *
     * @param array<string,mixed> $doc
     */
    public static function fromArray(array $doc): self
    {
        $endpoints = $doc['endpoints'] ?? [];
        unset($doc['endpoints']);

        return new self($doc, is_array($endpoints) ? array_values($endpoints) : []);
    }

    /** @return list<array<string,mixed>> */
    public function endpoints(): array
    {
        return $this->endpoints;
    }

    /** @return array<string,mixed> */
    public function meta(): array
    {
        return $this->meta;
    }

    /** @param array<string,mixed> $e */
    public static function isBind(array $e): bool
    {
        return ($e['forward_target_endpoint_id'] ?? null) === null;
    }

    /** @param array<string,mixed> $e */
    public static function isNginx(array $e): bool
    {
        return in_array($e['owner_kind'] ?? '', ['canonical-web', 'nginx-alias'], true);
    }

    /**
     * Every problem with the document, as exact human-readable lines; empty means valid.
     *
     * @return list<string>
     */
    public function validate(): array
    {
        $p = [];
        if (($this->meta['schema'] ?? null) !== self::SCHEMA) {
            $p[] = 'schema: expected "' . self::SCHEMA . '"';
        }
        if ($this->endpoints === []) {
            $p[] = 'endpoints: none declared';

            return $p;
        }

        $byId = [];
        $bindOwner = [];      // "tcp/80" => endpoint_id
        $external = [];       // "deploy tcp/80" => endpoint_id
        $spawnByProcess = []; // process_id => "proto bind"
        foreach ($this->endpoints as $i => $e) {
            $where = 'endpoint #' . $i . (isset($e['endpoint_id']) && is_string($e['endpoint_id']) ? ' (' . $e['endpoint_id'] . ')' : '');
            if (!is_array($e)) {
                $p[] = "{$where}: not an object";
                continue;
            }
            $missing = array_diff(self::KEYS, array_keys($e));
            $unknown = array_diff(array_keys($e), self::KEYS);
            if ($missing !== []) {
                $p[] = "{$where}: missing key(s) " . implode(', ', $missing);
            }
            if ($unknown !== []) {
                $p[] = "{$where}: unknown key(s) " . implode(', ', $unknown);
            }
            if ($missing !== [] || $unknown !== []) {
                continue;
            }
            $id = $e['endpoint_id'];
            if (!is_string($id) || preg_match('/^[a-z0-9][a-z0-9-]*$/', $id) !== 1) {
                $p[] = "{$where}: endpoint_id must match ^[a-z0-9][a-z0-9-]*$";
                continue;
            }
            if (isset($byId[$id])) {
                $p[] = "{$where}: duplicate endpoint_id";
                continue;
            }
            $byId[$id] = $e;
            if (!is_string($e['service_id']) || $e['service_id'] === '') {
                $p[] = "{$where}: service_id must be a non-empty string";
            }
            if (!in_array($e['owner_kind'], self::OWNER_KINDS, true)) {
                $p[] = "{$where}: owner_kind must be one of " . implode('|', self::OWNER_KINDS);
            }
            if (!in_array($e['transport'], self::TRANSPORTS, true)) {
                $p[] = "{$where}: transport must be tcp|udp";
            }
            foreach (['container_port', 'host_port'] as $k) {
                if (!is_int($e[$k]) || $e[$k] < 1 || $e[$k] > 65535) {
                    $p[] = "{$where}: {$k} must be an integer 1..65535";
                }
            }
            foreach (['tls', 'scanner_exposed', 'runtime_toggleable'] as $k) {
                if (!is_bool($e[$k])) {
                    $p[] = "{$where}: {$k} must be a boolean";
                }
            }
            if (!is_string($e['notes'])) {
                $p[] = "{$where}: notes must be a string";
            }
            if ($e['process_id'] !== null && (!is_string($e['process_id']) || $e['process_id'] === '')) {
                $p[] = "{$where}: process_id must be null or a non-empty string";
            }
            if (!is_array($e['targets']) || $e['targets'] !== array_values(array_intersect(self::TARGETS, $e['targets']))) {
                $p[] = "{$where}: targets must be a subset of [" . implode(', ', self::TARGETS) . '] in that order';
            }
            if ($e['deploy_opt_in'] !== null) {
                if (!is_string($e['deploy_opt_in']) || preg_match('/^[A-Z][A-Z0-9_]*$/', $e['deploy_opt_in']) !== 1) {
                    $p[] = "{$where}: deploy_opt_in must be null or an env var name";
                } elseif (!is_array($e['targets']) || !in_array('deploy', $e['targets'], true)) {
                    $p[] = "{$where}: deploy_opt_in set but deploy is not a target";
                }
            }
            $spawn = $e['spawn'];
            if ($spawn !== null) {
                $okSpawn = is_array($spawn) && array_keys($spawn) === ['proto', 'bind']
                    && is_string($spawn['proto']) && preg_match('/^[a-z0-9-]+$/', $spawn['proto']) === 1
                    && is_string($spawn['bind']) && preg_match('/^0\.0\.0\.0:(\d{1,5})$/', $spawn['bind'], $bm) === 1;
                if (!$okSpawn) {
                    $p[] = "{$where}: spawn must be null or {proto, bind: 0.0.0.0:<port>}";
                } elseif (is_int($e['container_port']) && (int) $bm[1] !== $e['container_port']) {
                    $p[] = "{$where}: spawn bind port differs from container_port";
                }
            }

            $nginx = self::isNginx($e);
            if ($nginx && ($e['process_id'] !== null || $spawn !== null)) {
                $p[] = "{$where}: an nginx-owned endpoint has no process_id and no spawn";
            }
            if ($nginx && $e['transport'] !== 'tcp') {
                $p[] = "{$where}: nginx endpoints are tcp";
            }
            if (!$nginx && $e['process_id'] === null) {
                $p[] = "{$where}: a listener/media endpoint names its process_id";
            }
            if (!$nginx && $e['tls'] === true) {
                $p[] = "{$where}: tls is an nginx property";
            }
            if ($e['owner_kind'] === 'listener' && self::isBind($e) && $spawn === null) {
                $p[] = "{$where}: a listener bind names its spawn line";
            }
            if ($e['owner_kind'] === 'media-capability' && $spawn !== null) {
                $p[] = "{$where}: a media capability rides another process and has no spawn of its own";
            }
            if (!self::isBind($e) && $spawn !== null) {
                $p[] = "{$where}: a forward has no spawn";
            }

            if (is_string($e['transport']) && is_int($e['container_port'])) {
                if (self::isBind($e)) {
                    $key = $e['transport'] . '/' . $e['container_port'];
                    if (isset($bindOwner[$key])) {
                        $p[] = "{$where}: {$key} is already bound by {$bindOwner[$key]}";
                    } else {
                        $bindOwner[$key] = $id;
                    }
                    if ($e['host_port'] !== $e['container_port']) {
                        $p[] = "{$where}: a bind publishes on its own port (host_port == container_port)";
                    }
                }
                if (is_array($e['targets']) && is_int($e['host_port'])) {
                    foreach ($e['targets'] as $t) {
                        $key = $t . ' ' . $e['transport'] . '/' . $e['host_port'];
                        if (isset($external[$key])) {
                            $p[] = "{$where}: {$key} is already published by {$external[$key]}";
                        } else {
                            $external[$key] = $id;
                        }
                    }
                }
            }
            if ($spawn !== null && is_array($spawn) && is_string($e['process_id'])) {
                $line = ($spawn['proto'] ?? '') . ' ' . ($spawn['bind'] ?? '');
                if (isset($spawnByProcess[$e['process_id']]) && $spawnByProcess[$e['process_id']] !== $line) {
                    $p[] = "{$where}: process {$e['process_id']} has two different spawn lines";
                }
                $spawnByProcess[$e['process_id']] = $line;
            }
        }

        // Forwards: must name an existing bind of the same transport and container port, and inherit
        // its ownership (a forward is the same service reached on another host port).
        foreach ($byId as $id => $e) {
            if (self::isBind($e)) {
                continue;
            }
            $tid = $e['forward_target_endpoint_id'];
            $t = is_string($tid) ? ($byId[$tid] ?? null) : null;
            if ($t === null) {
                $p[] = "endpoint {$id}: forward target " . json_encode($tid) . ' does not exist';
                continue;
            }
            if (!self::isBind($t)) {
                $p[] = "endpoint {$id}: forward target {$tid} is itself a forward";
            }
            if ($t['transport'] !== $e['transport'] || $t['container_port'] !== $e['container_port']) {
                $p[] = "endpoint {$id}: forward must keep its target's transport and container_port";
            }
            if ($t['owner_kind'] !== $e['owner_kind'] || $t['process_id'] !== $e['process_id'] || $t['service_id'] !== $e['service_id']) {
                $p[] = "endpoint {$id}: forward must keep its target's owner_kind, process_id and service_id";
            }
            if ($e['host_port'] === $e['container_port']) {
                $p[] = "endpoint {$id}: a forward publishes on a different host port";
            }
        }

        // Canonical web is exactly tcp/80 + tcp/443 and nothing else claims that kind.
        $canon = [];
        foreach ($byId as $id => $e) {
            if ($e['owner_kind'] === 'canonical-web' && self::isBind($e)) {
                $canon[] = $e['transport'] . '/' . $e['container_port'];
            }
        }
        sort($canon);
        if ($canon !== ['tcp/443', 'tcp/80']) {
            $p[] = 'canonical-web must be exactly tcp/80 and tcp/443 (have: ' . implode(', ', $canon) . ')';
        }

        if ($p === []) {
            $sorted = $this->endpoints;
            usort($sorted, [self::class, 'compare']);
            if (array_column($sorted, 'endpoint_id') !== array_column($this->endpoints, 'endpoint_id')) {
                $p[] = 'endpoints are not in canonical order (transport, container_port, host_port, endpoint_id) — run scripts/check-ports.php --format';
            }
        }

        return $p;
    }

    /**
     * The canonical rendering: metadata pretty-printed, then one endpoint per line in canonical order
     * with the fixed key order. The committed file must equal this byte for byte.
     */
    public function canonicalJson(): string
    {
        $meta = $this->meta;
        $out = "{\n";
        foreach ($meta as $k => $v) {
            $out .= '  ' . json_encode((string) $k) . ': ' . self::indent((string) json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . ",\n";
        }
        $sorted = $this->endpoints;
        usort($sorted, [self::class, 'compare']);
        $lines = [];
        foreach ($sorted as $e) {
            $ordered = [];
            foreach (self::KEYS as $k) {
                if (array_key_exists($k, $e)) {
                    $ordered[$k] = $e[$k];
                }
            }
            $lines[] = '    ' . json_encode($ordered, JSON_UNESCAPED_SLASHES);
        }
        $out .= "  \"endpoints\": [\n" . implode(",\n", $lines) . "\n  ]\n}\n";

        return $out;
    }

    // ---- derived views ---------------------------------------------------------------------------

    /**
     * nginx `listen` lines as "port" / "port ssl", sorted.
     *
     * @return list<string>
     */
    public function nginxListens(): array
    {
        $out = [];
        foreach ($this->endpoints as $e) {
            if (self::isBind($e) && self::isNginx($e)) {
                $out[] = $e['container_port'] . ($e['tls'] ? ' ssl' : '');
            }
        }

        return self::sortedUnique($out);
    }

    /**
     * Entrypoint spawn lines as "proto 0.0.0.0:port", one per process, in file order.
     *
     * @return list<string>
     */
    public function spawns(): array
    {
        $out = [];
        foreach ($this->endpoints as $e) {
            if (is_array($e['spawn'] ?? null)) {
                $out[$e['spawn']['proto'] . ' ' . $e['spawn']['bind']] = true;
            }
        }

        return array_keys($out);
    }

    /**
     * Dockerfile EXPOSE tokens ("80", "161/udp"): every container bind, aliases excluded (they are
     * host-side publish mappings, not container ports).
     *
     * @return list<string>
     */
    public function exposes(): array
    {
        $out = [];
        foreach ($this->endpoints as $e) {
            if (self::isBind($e)) {
                $out[] = $e['container_port'] . ($e['transport'] === 'udp' ? '/udp' : '');
            }
        }

        return self::sortedUnique($out);
    }

    /**
     * Publish mappings for one target as "host:container[/udp]" (opt-in ones excluded), sorted.
     *
     * @return list<string>
     */
    public function publishes(string $target): array
    {
        $out = [];
        foreach ($this->endpoints as $e) {
            if (in_array($target, $e['targets'] ?? [], true) && ($e['deploy_opt_in'] ?? null) === null) {
                $out[] = self::mapping($e);
            }
        }

        return self::sortedUnique($out);
    }

    /**
     * Opt-in publish mappings for one target, grouped by the env var that enables them.
     *
     * @return array<string,list<string>>
     */
    public function optInPublishes(string $target): array
    {
        $out = [];
        foreach ($this->endpoints as $e) {
            if (in_array($target, $e['targets'] ?? [], true) && ($e['deploy_opt_in'] ?? null) !== null) {
                $out[(string) $e['deploy_opt_in']][] = self::mapping($e);
            }
        }
        ksort($out);
        foreach ($out as &$list) {
            $list = self::sortedUnique($list);
        }

        return $out;
    }

    /**
     * What the host firewall / security group must admit for the deploy target: one row per
     * (transport, host port), opt-ins flagged. A read-only readback for the operator to diff.
     *
     * @return list<array{transport:string, port:int, endpoint_id:string, opt_in:?string}>
     */
    public function securityGroupRows(): array
    {
        $rows = [];
        foreach ($this->endpoints as $e) {
            if (in_array('deploy', $e['targets'] ?? [], true)) {
                $rows[] = ['transport' => $e['transport'], 'port' => $e['host_port'], 'endpoint_id' => $e['endpoint_id'], 'opt_in' => $e['deploy_opt_in']];
            }
        }
        usort($rows, static fn (array $a, array $b): int => [$a['transport'], $a['port']] <=> [$b['transport'], $b['port']]);

        return $rows;
    }

    /** @param array<string,mixed> $e */
    private static function mapping(array $e): string
    {
        return $e['host_port'] . ':' . $e['container_port'] . ($e['transport'] === 'udp' ? '/udp' : '');
    }

    /**
     * @param array<string,mixed> $a
     * @param array<string,mixed> $b
     */
    private static function compare(array $a, array $b): int
    {
        return [$a['transport'] ?? '', $a['container_port'] ?? 0, $a['host_port'] ?? 0, $a['endpoint_id'] ?? '']
            <=> [$b['transport'] ?? '', $b['container_port'] ?? 0, $b['host_port'] ?? 0, $b['endpoint_id'] ?? ''];
    }

    /**
     * @param list<string> $items
     * @return list<string>
     */
    public static function sortedUnique(array $items): array
    {
        $items = array_values(array_unique($items));
        sort($items, SORT_NATURAL);

        return $items;
    }

    /** PRETTY_PRINT's 4-space steps become 2-space steps, nested one level under the root. */
    private static function indent(string $json): string
    {
        $json = (string) preg_replace_callback('/^(?: {4})+/m', static fn (array $m): string => str_repeat('  ', intdiv(strlen($m[0]), 4)), $json);

        return str_replace("\n", "\n  ", $json);
    }
}

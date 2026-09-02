<?php

declare(strict_types=1);

namespace Funnypot\App\Docker;

use Funnypot\App\Storage\FakePersistenceStore;

/**
 * Cross-request coherence for the fake Docker daemon, WITHOUT any real state or process. A typed
 * façade over a second instance of {@see FakePersistenceStore} (its own `docker.sqlite`, so it never
 * contends with or shares the panel's 5000-row global cap), it remembers just enough about a
 * "created" phantom container that a bot's create → start → inspect → logs → exec chain reads
 * coherently — while nothing is ever created, started, or run.
 *
 * NOTHING here executes, connects, or touches the host: it is pure record-keeping over the app's own
 * bounded, TTL'd SQLite. A phantom evaporates after the TTL (default 1 h), which reads like a real
 * host after cleanup: a returning bot then gets a truthful 404.
 *
 * Storage model (working within the composed store's semantics):
 *  - The container SPEC lives under the id-keyed view `c:<id>` with ip='docker' (NOT the attacker IP),
 *    so a create from IP A and a start from IP B still cohere (the id is the shared secret handle).
 *    Complex fields (cmd/env/binds/…) are JSON-encoded into single values. There is no update API, so
 *    the `started` flag is set by RE-recording the full spec (read() returns newest-first, so the
 *    newest record wins); an absent `started` key means false ((string)false is empty, so the store
 *    drops it — never stored as a literal "0").
 *  - The per-attacker view `ps` holds one record per phantom id (not a CSV — the store caps a single
 *    value at a few hundred bytes and a 10×65-byte id list overflows it), `pulled` one per canonical
 *    ref, `hide` one per fleet id/name this IP stopped or removed. read()'s newest-N cap bounds each.
 */
final class PhantomStore
{
    private const IP_SPEC = 'docker';   // specs are id-keyed, shared across attacker IPs
    private FakePersistenceStore $store;

    /** @var callable():int */
    private $clock;

    public function __construct(string $dbPath, private int $seed, ?callable $clock = null, int $ttl = 3600)
    {
        // Wider field/value caps than the panel default: a container spec carries ~16 fields and a
        // JSON-encoded env/cmd list is longer than a note. 4000 B/value comfortably holds a realistic
        // env (a handful of KEY=value pairs) and command intact on the inspect echo; a pathologically
        // over-stuffed env (EscapeIntent caps it at 32×256 ≈ 8 KB JSON) still exceeds this and is
        // truncated — which fails SAFE: json_decode returns [] and inspect echoes an empty Env, while
        // the FULL intel is captured separately on the export line + raw body (review A#6 / B S4). Own
        // file, own TTL — never shares the panel store's global row cap. (Kept bounded, not unbounded.)
        $this->store = new FakePersistenceStore($dbPath, $clock, $ttl, 24, 4000);
        $this->clock = $clock ?? 'time';
    }

    /**
     * Record a freshly "created" (not started) phantom.
     *
     * @param array<string,mixed> $spec
     */
    public function createContainer(string $ip, string $id, array $spec): void
    {
        $this->store->record(self::IP_SPEC, $this->seed, 'c:' . $id, $this->encodeSpec($id, $spec, false));
        $this->store->record($ip, $this->seed, 'ps', ['id' => $id]);
    }

    /**
     * Mark a phantom started. Returns true if the caller's start is the FIRST (so respond 204); false
     * if it was already started (respond 304) or the phantom is unknown (caller 404s separately).
     */
    public function markStarted(string $id): bool
    {
        $spec = $this->spec($id);
        if ($spec === null) {
            return false;
        }
        if ($spec['started'] ?? false) {
            return false;   // already running
        }
        $this->store->record(self::IP_SPEC, $this->seed, 'c:' . $id, $this->encodeSpec($id, $spec, true));

        return true;
    }

    /**
     * The spec of a phantom by exact id, or null. Decodes the JSON sub-fields back to arrays.
     *
     * @return array<string,mixed>|null
     */
    public function spec(string $id): ?array
    {
        $items = $this->store->read(self::IP_SPEC, $this->seed, 'c:' . $id);
        if ($items === []) {
            return null;
        }

        return $this->decodeSpec($items[0]);
    }

    /**
     * Resolve an attacker's container target (exact 64-hex id, a 12+-hex prefix, or a ?name=) to a
     * phantom spec belonging to this IP, or null.
     *
     * @return array<string,mixed>|null
     */
    public function resolve(string $ip, string $target): ?array
    {
        if ($target === '') {
            return null;
        }
        // Fast path: the id create returned is used verbatim by start/inspect/…
        $direct = $this->spec($target);
        if ($direct !== null && $this->ownedBy($ip, (string) $direct['id'])) {
            return $direct;
        }
        $needle = ltrim($target, '/');
        foreach ($this->phantomIds($ip) as $id) {
            if ($id === $needle || (strlen($needle) >= 12 && strpos($id, $needle) === 0)) {
                $spec = $this->spec($id);
                if ($spec !== null) {
                    return $spec;
                }
            }
            $spec = $this->spec($id);
            if ($spec !== null && $spec['name'] !== '' && ltrim((string) $spec['name'], '/') === $needle) {
                return $spec;
            }
        }

        return null;
    }

    /** @return list<string> this IP's phantom ids, newest first, that still have a live spec. */
    public function phantomIds(string $ip): array
    {
        $out = [];
        foreach ($this->store->read($ip, $this->seed, 'ps') as $item) {
            $id = (string) ($item['id'] ?? '');
            if ($id !== '' && !in_array($id, $out, true) && $this->spec($id) !== null) {
                $out[] = $id;
            }
        }

        return $out;
    }

    /**
     * This IP's phantom specs. $running=null → all; true → started only; false → created-but-not-started.
     *
     * @return list<array<string,mixed>>
     */
    public function phantoms(string $ip, ?bool $running = null): array
    {
        $out = [];
        foreach ($this->phantomIds($ip) as $id) {
            $spec = $this->spec($id);
            if ($spec === null) {
                continue;
            }
            if ($running !== null && (bool) ($spec['started'] ?? false) !== $running) {
                continue;
            }
            $out[] = $spec;
        }

        return $out;
    }

    public function recordPull(string $ip, string $canonical): void
    {
        if ($canonical !== '') {
            $this->store->record($ip, $this->seed, 'pulled', ['ref' => $canonical]);
        }
    }

    /** @return list<string> canonical refs this IP has pulled (newest first, deduped). */
    public function pulled(string $ip): array
    {
        $out = [];
        foreach ($this->store->read($ip, $this->seed, 'pulled') as $item) {
            $ref = (string) ($item['ref'] ?? '');
            if ($ref !== '' && !in_array($ref, $out, true)) {
                $out[] = $ref;
            }
        }

        return $out;
    }

    public function hide(string $ip, string $idOrName): void
    {
        if ($idOrName !== '') {
            $this->store->record($ip, $this->seed, 'hide', ['id' => $idOrName]);
        }
    }

    /** @return list<string> fleet ids/names this IP stopped or removed. */
    public function hidden(string $ip): array
    {
        $out = [];
        foreach ($this->store->read($ip, $this->seed, 'hide') as $item) {
            $id = (string) ($item['id'] ?? '');
            if ($id !== '' && !in_array($id, $out, true)) {
                $out[] = $id;
            }
        }

        return $out;
    }

    /** @param array<string,mixed> $rec */
    public function recordExec(string $execId, array $rec): void
    {
        $this->store->record(self::IP_SPEC, $this->seed, 'e:' . $execId, [
            'command' => (string) ($rec['command'] ?? ''),
            'user' => (string) ($rec['user'] ?? ''),
            'container' => (string) ($rec['container'] ?? ''),
        ]);
    }

    /** @return array<string,string>|null */
    public function execRecord(string $execId): ?array
    {
        $items = $this->store->read(self::IP_SPEC, $this->seed, 'e:' . $execId);

        return $items === [] ? null : $items[0];
    }

    // --- encode/decode ---

    private function ownedBy(string $ip, string $id): bool
    {
        return in_array($id, $this->phantomIds($ip), true);
    }

    /**
     * @param array<string,mixed> $spec
     * @return array<string,string> flat, store-friendly field map (empties dropped by the store)
     */
    private function encodeSpec(string $id, array $spec, bool $started): array
    {
        $flat = [
            'id' => $id,
            'image' => (string) ($spec['image'] ?? ''),
            'command' => (string) ($spec['command'] ?? ''),
            'name' => (string) ($spec['name'] ?? ''),
            'created' => (string) ($spec['created'] ?? ($this->clock)()),
            'user' => (string) ($spec['user'] ?? ''),
            'hostname' => (string) ($spec['hostname'] ?? ''),
            'pid_mode' => (string) ($spec['pid_mode'] ?? ''),
            'network_mode' => (string) ($spec['network_mode'] ?? ''),
            'entrypoint_json' => $this->enc($spec['entrypoint'] ?? []),
            'cmd_json' => $this->enc($spec['cmd'] ?? []),
            'env_json' => $this->enc($spec['env'] ?? []),
            'binds_json' => $this->enc($spec['binds'] ?? []),
            'mounts_json' => $this->enc($spec['mounts'] ?? []),
        ];
        if (($spec['privileged'] ?? false)) {
            $flat['privileged'] = '1';
        }
        if (($spec['tty'] ?? false)) {
            $flat['tty'] = '1';
        }
        if ($started) {
            $flat['started'] = '1';
        }

        return $flat;
    }

    /**
     * @param array<string,string> $item
     * @return array<string,mixed>
     */
    private function decodeSpec(array $item): array
    {
        return [
            'id' => (string) ($item['id'] ?? ''),
            'image' => (string) ($item['image'] ?? ''),
            'command' => (string) ($item['command'] ?? ''),
            'name' => (string) ($item['name'] ?? ''),
            'created' => (int) ($item['created'] ?? 0),
            'user' => (string) ($item['user'] ?? ''),
            'hostname' => (string) ($item['hostname'] ?? ''),
            'pid_mode' => (string) ($item['pid_mode'] ?? ''),
            'network_mode' => (string) ($item['network_mode'] ?? ''),
            'entrypoint' => $this->dec($item['entrypoint_json'] ?? ''),
            'cmd' => $this->dec($item['cmd_json'] ?? ''),
            'env' => $this->dec($item['env_json'] ?? ''),
            'binds' => $this->dec($item['binds_json'] ?? ''),
            'mounts' => $this->dec($item['mounts_json'] ?? ''),
            'privileged' => isset($item['privileged']),
            'tty' => isset($item['tty']),
            'started' => isset($item['started']),
        ];
    }

    /** @param mixed $v */
    private function enc($v): string
    {
        return (string) json_encode(is_array($v) ? array_values($v) : [], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /** @return list<mixed> */
    private function dec(string $json): array
    {
        if ($json === '') {
            return [];
        }
        $d = json_decode($json, true, 8);

        return is_array($d) ? array_values($d) : [];
    }
}

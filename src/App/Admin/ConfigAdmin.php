<?php

declare(strict_types=1);

namespace Funnypot\App\Admin;

use Funnypot\App\Config\ConfigStore;
use RuntimeException;

/**
 * The config-admin panel's view/controller helper (FP-0242b). A thin, framework-free layer over
 * {@see ConfigStore}: it turns the registry + the stored overrides into the JSON the admin UI renders,
 * and turns a validated config-set/config-reset into a store write. It is NOT a front controller — the
 * {@see \Funnypot\App\Http\DashboardController} calls it from behind the AdminAuth session gate.
 *
 * Two invariants it enforces on top of the store:
 *   - a secret knob's VALUE is never emitted (shown as set/unset only) — none are registered today,
 *     but the guard is here so a future secret key cannot leak through this surface;
 *   - config-set rejects an empty value (delegated to ConfigStore::set, review nit fable#3): an empty
 *     override would silently mask a set env var, so clearing is the distinct reset() operation.
 */
final class ConfigAdmin
{
    public function __construct(private ConfigStore $store)
    {
    }

    /**
     * The full config listing for the panel: every registry key, grouped, with its resolved value, the
     * source that value came from (stored / env / default), and the live/restart + secret metadata.
     * Secret values are redacted to a set/unset flag.
     *
     * @return array{ok:bool,groups:array<string,list<array<string,mixed>>>}
     */
    public function listPayload(): array
    {
        $registry = $this->store->registry();
        $stored = $this->store->stored();               // key => raw stored override (fail-safe [])
        $groups = [];
        foreach ($registry->entries() as $key => $e) {
            $env = (string) ($e['env'] ?? '');
            $isSecret = (bool) ($e['secret'] ?? false);
            $hasStored = array_key_exists($key, $stored);
            $envVal = $env !== '' ? getenv($env) : false;
            if ($hasStored) {
                $source = 'stored';
            } elseif ($envVal !== false && $envVal !== '') {
                $source = 'env';
            } else {
                $source = 'default';
            }
            $resolved = $this->store->get($key, $env, (string) ($e['default'] ?? ''));

            $row = [
                'key' => $key,
                'group' => (string) ($e['group'] ?? 'Other'),
                'type' => (string) ($e['type'] ?? 'string'),
                'live' => (bool) ($e['live'] ?? false),
                'secret' => $isSecret,
                'source' => $source,
                'env' => $env,
                'default' => (string) ($e['default'] ?? ''),
            ];
            if (isset($e['enum'])) {
                $row['enum'] = array_values((array) $e['enum']);
            }
            if (isset($e['min'])) {
                $row['min'] = (int) $e['min'];
            }
            if (isset($e['max'])) {
                $row['max'] = (int) $e['max'];
            }
            // Redact secret VALUES — the UI only learns whether one is set, never what it is.
            if ($isSecret) {
                $row['value'] = null;
                $row['is_set'] = $hasStored || ($envVal !== false && $envVal !== '');
            } else {
                $row['value'] = $resolved;
            }
            $groups[$row['group']][] = $row;
        }

        return ['ok' => true, 'groups' => $groups];
    }

    /**
     * Apply a config-set. Validation + clamps + the empty-value rejection all live in ConfigStore/
     * ConfigRegistry (one validation path for env and stored values); this just forwards the actor +
     * source IP. Returns a JSON-able result; a validation/write error is reported (fail-closed for the
     * admin), never thrown out to the caller as a 500.
     *
     * @return array{ok:bool,key:string,error?:string}
     */
    public function set(string $key, string $value, string $actor, string $sourceIp): array
    {
        try {
            $this->store->set($key, $value, $actor, $sourceIp);

            return ['ok' => true, 'key' => $key];
        } catch (RuntimeException $e) {
            return ['ok' => false, 'key' => $key, 'error' => $e->getMessage()];
        }
    }

    /** @return array{ok:bool,key:string,error?:string} */
    public function reset(string $key, string $actor, string $sourceIp): array
    {
        if (!$this->store->registry()->has($key)) {
            return ['ok' => false, 'key' => $key, 'error' => "unknown config key: {$key}"];
        }
        try {
            $this->store->reset($key, $actor, $sourceIp);

            return ['ok' => true, 'key' => $key];
        } catch (RuntimeException $e) {
            return ['ok' => false, 'key' => $key, 'error' => $e->getMessage()];
        }
    }

    /**
     * The change audit log. A secret knob's old/new VALUES are redacted here too (to set/unset),
     * mirroring listPayload(): the invariant is "never emit a secret in the list, the audit, OR the
     * JSON". Harmless today (no knob is registered secret) but the guard stays true for a future one.
     *
     * @return array{ok:bool,audit:list<array<string,mixed>>}
     */
    public function auditPayload(int $limit = 200): array
    {
        $registry = $this->store->registry();
        $audit = [];
        foreach ($this->store->audits($limit) as $row) {
            $entry = $registry->get((string) ($row['key'] ?? ''));
            if ($entry !== null && ($entry['secret'] ?? false)) {
                $row['old_value'] = $row['old_value'] === null ? null : 'set';
                $row['new_value'] = $row['new_value'] === null ? null : 'set';
            }
            $audit[] = $row;
        }

        return ['ok' => true, 'audit' => $audit];
    }
}

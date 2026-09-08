<?php

declare(strict_types=1);

namespace Funnypot\App\Runtime;

use Funnypot\App\Service\CanonicalJson;

final class RuntimePolicy
{
    public const SCHEMA = 'funnypot-runtime-roles/v1';
    public const HASH_DOMAIN = 'funnypot/runtime-policy-hash/v1';
    private const IDS = ['prepare', 'edge', 'web', 'protocols', 'worker', 'egress'];
    private const FIELDS = ['role_id', 'uid', 'gid', 'supplemental_gids', 'long_lived'];

    /** @param array<string,RuntimeRole> $roles */
    private function __construct(private array $roles)
    {
    }

    public static function fromPackage(?string $path = null): self
    {
        $path ??= dirname(__DIR__, 3) . '/resources/runtime/roles.php';
        $raw = require $path;

        return self::fromArray(is_array($raw) ? $raw : []);
    }

    /** @param array<string,mixed> $raw */
    public static function fromArray(array $raw): self
    {
        if (array_keys($raw) !== ['schema', 'roles'] || ($raw['schema'] ?? null) !== self::SCHEMA || !is_array($raw['roles'])) {
            throw new RuntimePolicyException('runtime policy: invalid resource envelope');
        }
        $roles = [];
        $numeric = [];
        foreach ($raw['roles'] as $row) {
            if (!is_array($row) || array_keys($row) !== self::FIELDS) {
                throw new RuntimePolicyException('runtime policy: role fields do not match the closed schema');
            }
            $id = $row['role_id'] ?? null;
            if (!is_string($id) || !in_array($id, self::IDS, true) || isset($roles[$id])) {
                throw new RuntimePolicyException('runtime policy: unknown or duplicate role id');
            }
            if (!is_int($row['uid']) || $row['uid'] < 0 || !is_int($row['gid']) || $row['gid'] < 0 || !is_bool($row['long_lived'])) {
                throw new RuntimePolicyException('runtime policy: invalid role scalar');
            }
            $pair = $row['uid'] . ':' . $row['gid'];
            if (isset($numeric[$pair])) {
                throw new RuntimePolicyException('runtime policy: duplicate numeric ownership');
            }
            if (!is_array($row['supplemental_gids']) || !array_is_list($row['supplemental_gids'])) {
                throw new RuntimePolicyException('runtime policy: supplemental gids must be a list');
            }
            $gids = [];
            foreach ($row['supplemental_gids'] as $gid) {
                if (!is_int($gid) || $gid < 0 || in_array($gid, $gids, true)) {
                    throw new RuntimePolicyException('runtime policy: invalid supplemental gid');
                }
                $gids[] = $gid;
            }
            $numeric[$pair] = true;
            $roles[$id] = new RuntimeRole($id, $row['uid'], $row['gid'], $gids, $row['long_lived']);
        }
        if (array_keys($roles) !== self::IDS) {
            throw new RuntimePolicyException('runtime policy: roles are missing or out of order');
        }

        return new self($roles);
    }

    public function role(string $id): ?RuntimeRole
    {
        return $this->roles[$id] ?? null;
    }

    /** @return list<RuntimeRole> */
    public function roles(): array
    {
        return array_values($this->roles);
    }

    /** @return array{schema:string,roles:list<array{role_id:string,uid:int,gid:int,supplemental_gids:list<int>,long_lived:bool}>} */
    public function toArray(): array
    {
        return ['schema' => self::SCHEMA, 'roles' => array_map(static fn (RuntimeRole $r): array => $r->toArray(), $this->roles())];
    }

    public function policyHash(): string
    {
        return CanonicalJson::digest(self::HASH_DOMAIN, $this->toArray());
    }
}

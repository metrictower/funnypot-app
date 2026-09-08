<?php

declare(strict_types=1);

namespace Funnypot\App\Runtime;

final class RuntimeRole
{
    /** @param list<int> $supplementalGids */
    public function __construct(
        public readonly string $roleId,
        public readonly int $uid,
        public readonly int $gid,
        public readonly array $supplementalGids,
        public readonly bool $longLived,
    ) {
    }

    /** @return array{role_id:string,uid:int,gid:int,supplemental_gids:list<int>,long_lived:bool} */
    public function toArray(): array
    {
        return [
            'role_id' => $this->roleId,
            'uid' => $this->uid,
            'gid' => $this->gid,
            'supplemental_gids' => $this->supplementalGids,
            'long_lived' => $this->longLived,
        ];
    }
}

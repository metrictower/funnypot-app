<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Cmdi;

use Funnypot\App\Storage\CmdiShellStore;
use Funnypot\App\Tarpit\Cmdi\SourceState;
use RuntimeException;

/** In-memory console history that records every write; can be told to throw. */
final class SpyCmdiStore implements CmdiShellStore
{
    /** @var array<string,SourceState> */
    public array $states = [];
    /** @var list<array<string,scalar|null>> */
    public array $writes = [];
    public bool $throw = false;

    public function load(string $ip): SourceState
    {
        if ($this->throw) {
            throw new RuntimeException('store down');
        }

        return $this->states[$ip] ?? SourceState::empty();
    }

    public function save(string $ip, array $delta, array $turn): bool
    {
        if ($this->throw) {
            throw new RuntimeException('store down');
        }
        $this->states[$ip] = ($this->states[$ip] ?? SourceState::empty())->apply($delta);
        $this->writes[] = ['ip' => $ip] + $turn;

        return true;
    }
}

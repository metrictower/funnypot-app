<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Cmdi\SourceState;

/** Per-source console history. Every implementation fails open: a fault means "no history", never an error. */
interface CmdiShellStore
{
    public function load(string $ip): SourceState;

    /**
     * Persist the source's new state and one attribution row for the turn. Returns false when a write
     * cap or a fault stopped the write; the turn has already been answered either way.
     *
     * @param array<string,scalar|null> $turn
     */
    public function save(string $ip, SourceState $state, array $turn): bool;
}

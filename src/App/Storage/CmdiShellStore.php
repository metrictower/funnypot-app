<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Cmdi\SourceState;

/** Per-source console history. Every implementation fails open: a fault means "no history", never an error. */
interface CmdiShellStore
{
    public function load(string $ip): SourceState;

    /**
     * Merge one turn's delta ({@see SourceState::delta()}) onto the source's row as it is now, and add
     * one attribution row. The read and the write are one atomic step, so overlapping turns from one
     * source merge instead of overwriting each other. It fails open: a write that cannot get the lock
     * within the short busy timeout is dropped (under heavy same-source concurrency, a few of many),
     * never an error. Returns false when a write cap, the lock or a fault stopped it; the turn has
     * already been answered either way.
     *
     * @param array<string,mixed>       $delta
     * @param array<string,scalar|null> $turn
     */
    public function save(string $ip, array $delta, array $turn): bool;
}

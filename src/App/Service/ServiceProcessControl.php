<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The narrow child-process seam the supervisor drives. Production is {@see PcntlServiceProcessControl}
 * (fork / owned-child signal / reap — never exec, proc_open or a shell); tests substitute a fake so
 * the supervisor state machine is exercised without a real process. The supervisor only ever names
 * cataloged process ids and only ever signals a child it started.
 */
interface ServiceProcessControl
{
    /** Start the child for one cataloged process id. Idempotent for an already-running id. */
    public function start(string $processId): void;

    /** Stop one owned child: TERM, a bounded grace, then KILL only for a still-owned child; then reap. */
    public function stop(string $processId): void;

    /** Child liveness from the supervisor's own waitpid bookkeeping (no socket probe). */
    public function isAlive(string $processId): bool;

    /** @return list<string> the currently-owned live process ids, sorted */
    public function running(): array;
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use RuntimeException;

/**
 * The production child-process control: fork, owned-child signal and reap through pcntl/posix — never
 * exec, proc_open or a shell (those stay in the FPM pool's disable_functions denylist; this runs only
 * in the root CLI supervisor). The parent records only its own child PIDs and never signals a PID it
 * did not start, so a reused/foreign PID is never touched.
 */
final class PcntlServiceProcessControl implements ServiceProcessControl
{
    /** @var array<string,int> process id => child pid */
    private array $pids = [];

    /**
     * @param callable(string):void $childMain runs in the forked child; must not return
     * @param int                   $graceMs   TERM->KILL grace
     */
    public function __construct(private $childMain, private int $graceMs = 2000)
    {
        foreach (['pcntl_fork', 'pcntl_waitpid', 'posix_kill'] as $fn) {
            if (!function_exists($fn)) {
                throw new RuntimeException("pcntl process control needs {$fn}");
            }
        }
    }

    public function start(string $processId): void
    {
        if (isset($this->pids[$processId]) && $this->isAlive($processId)) {
            return;
        }
        $pid = pcntl_fork();
        if ($pid === -1) {
            throw new RuntimeException("fork failed for process '{$processId}'");
        }
        if ($pid === 0) {
            // Child: run the listener; never return. Any fault exits non-zero.
            try {
                ($this->childMain)($processId);
            } catch (\Throwable $e) {
                exit(70);
            }
            exit(0);
        }
        $this->pids[$processId] = $pid;
    }

    public function stop(string $processId): void
    {
        $pid = $this->pids[$processId] ?? null;
        if ($pid === null) {
            return;
        }
        if ($this->isAlive($processId)) {
            @posix_kill($pid, SIGTERM);
            $deadline = microtime(true) + $this->graceMs / 1000;
            while (microtime(true) < $deadline) {
                if (!$this->isAlive($processId)) {
                    break;
                }
                usleep(20000);
            }
            if ($this->isAlive($processId)) {
                @posix_kill($pid, SIGKILL);
            }
        }
        // Reap.
        pcntl_waitpid($pid, $status, WNOHANG);
        unset($this->pids[$processId]);
    }

    public function isAlive(string $processId): bool
    {
        $pid = $this->pids[$processId] ?? null;
        if ($pid === null) {
            return false;
        }
        $res = pcntl_waitpid($pid, $status, WNOHANG);
        if ($res === $pid || $res === -1) {
            // Reaped or gone.
            unset($this->pids[$processId]);

            return false;
        }

        return true;
    }

    public function running(): array
    {
        $out = [];
        foreach (array_keys($this->pids) as $pid) {
            if ($this->isAlive($pid)) {
                $out[] = $pid;
            }
        }
        sort($out);

        return $out;
    }
}

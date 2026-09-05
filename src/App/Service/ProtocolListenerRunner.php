<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use RuntimeException;

/**
 * The closed process-id dispatch for listeners. It exposes the canonical joined process ids CI checks
 * against, and resolves a process id to its fixed (proto, bind) from the manifest — never from an
 * arbitrary protocol/bind argument. A forked child calls {@see runProcessId()}, which revalidates the
 * id, resolves its dispatch and invokes the provided server dispatcher in-process; there is no public
 * protocol/bind/port overload and it never executes a command or shell.
 */
final class ProtocolListenerRunner
{
    public function __construct(private ServiceCatalog $catalog)
    {
    }

    /** @return list<string> the canonical listener process ids (bind endpoints), sorted */
    public function supportedProcessIds(): array
    {
        $ids = [];
        foreach ($this->catalog->services() as $desc) {
            foreach ($desc->endpoints as $ep) {
                if ($ep->ownerKind === 'listener' && $ep->isBind() && $ep->processId !== null) {
                    $ids[$ep->processId] = true;
                }
            }
        }
        $out = array_keys($ids);
        sort($out);

        return $out;
    }

    /** @return array{proto:string,bind:string} the fixed dispatch for a process id */
    public function dispatchFor(string $processId): array
    {
        foreach ($this->catalog->services() as $desc) {
            foreach ($desc->endpoints as $ep) {
                if ($ep->processId === $processId && $ep->ownerKind === 'listener' && $ep->isBind()
                    && $ep->spawnProto !== null && $ep->spawnBind !== null) {
                    return ['proto' => $ep->spawnProto, 'bind' => $ep->spawnBind];
                }
            }
        }
        throw new RuntimeException("protocol runner: no dispatch for process id '{$processId}'");
    }

    /**
     * Revalidate the id, resolve its dispatch and invoke $dispatch(proto, bind) in-process. $dispatch
     * is the production server dispatcher (or a harmless fixture in the fork test); the runner never
     * accepts an arbitrary protocol/bind of its own.
     *
     * @param callable(string,string):void $dispatch
     */
    public function runProcessId(string $processId, callable $dispatch): void
    {
        if (!in_array($processId, $this->supportedProcessIds(), true)) {
            throw new RuntimeException("protocol runner: unknown process id '{$processId}'");
        }
        $d = $this->dispatchFor($processId);
        $dispatch($d['proto'], $d['bind']);
    }
}

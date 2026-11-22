<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * A fake fetch as it stands at one moment: its state, the reply once it has one, the error a worker
 * would log, and its attempts. Computed from the stored facts and the clock, never stored itself.
 */
final class FetchResult
{
    public const STATES = ['pending', 'delivered', 'failed', 'retrying', 'queued', 'fetching', 'waiting', 'cloning'];

    /** @param list<array{at:int,state:string,error:?string,ms:int}> $attempts */
    public function __construct(
        public readonly string $state,
        public readonly ?Reply $reply,
        public readonly ?string $error,
        public readonly int $durationMs,
        public readonly array $attempts,
    ) {
        if (!in_array($state, self::STATES, true)) {
            throw new \LogicException('state outside the closed set');
        }
    }

    public function done(): bool
    {
        return $this->state === 'delivered' || $this->state === 'failed';
    }
}

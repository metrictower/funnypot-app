<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * The outcome of PerIpAdmissionThrottle::admit() (FP-0221). Either admitted, dropped silently (the
 * flood is being suppressed and this command folds into the current rollup window), or dropped WITH a
 * rollup the caller should log once: `floodCount` suppressed commands over `floodSinceMs`.
 */
final class AdmissionDecision
{
    private function __construct(
        public readonly bool $admitted,
        public readonly ?int $floodCount,
        public readonly ?int $floodSinceMs
    ) {
    }

    public static function admitted(): self
    {
        return new self(true, null, null);
    }

    public static function droppedSilently(): self
    {
        return new self(false, null, null);
    }

    public static function droppedWithRollup(int $count, int $sinceMs): self
    {
        return new self(false, $count, $sinceMs);
    }

    /** True when the caller should emit a single flood-rollup log line for this drop. */
    public function hasRollup(): bool
    {
        return !$this->admitted && $this->floodCount !== null;
    }
}

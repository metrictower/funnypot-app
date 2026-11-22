<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

/** What a transaction body may read about the open BEGIN IMMEDIATE: the source's units this hour and the write caps. */
final class SsrfTx
{
    public function __construct(
        public readonly int $now,
        public readonly int $unitsUsed,
        public readonly bool $capReached,
    ) {
    }
}

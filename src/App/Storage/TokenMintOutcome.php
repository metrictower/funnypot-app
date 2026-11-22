<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Mint\MintState;

/**
 * What a token-mint transaction body decided: the state to write (null writes nothing), whether that
 * write changes account state (and so counts against the write caps) or only bumps counters, the work
 * units the request costs, and the caller's own result.
 */
final class TokenMintOutcome
{
    public function __construct(
        public readonly ?MintState $state,
        public readonly bool $stateChange,
        public readonly int $units,
        public readonly mixed $value,
    ) {
    }
}

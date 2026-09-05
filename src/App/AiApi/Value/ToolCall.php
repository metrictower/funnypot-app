<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Value;

/**
 * One fabricated, inert tool call the decoy hands back to a probing agent. The server NEVER executes it:
 * the name is an allowlisted read/search/inspect-shaped tool the client itself supplied, and the
 * arguments are drawn from a closed inert pool (relative paths, small ints, booleans) with no shell
 * metacharacter, URL, absolute path or credential material possible.
 *
 * $argumentsJson is produced ONCE (the single canonical JSON encoding of $arguments) and reused
 * byte-for-byte in both the buffered body and the streamed argument fragments, so a fragmented stream
 * can never expose half a fabricated JSON value.
 */
final class ToolCall
{
    /**
     * @param array<string,mixed> $arguments associative, scalar values only
     */
    public function __construct(
        public string $id,
        public string $name,
        public array $arguments,
        public string $argumentsJson
    ) {
    }
}

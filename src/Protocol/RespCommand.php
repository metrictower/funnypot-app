<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * One decoded RESP request: an immutable, ordered list of binary-safe argument strings. The bytes
 * are preserved exactly (embedded NUL / space / CRLF survive), so the engine sees the argument
 * boundaries a real client sent instead of a space-joined approximation.
 *
 * `name()`/`sub()` upper-case only argv[0] and argv[1] for case-insensitive command dispatch; the
 * raw values remain available for keys and payloads via {@see arg()} and {@see args()}.
 */
final class RespCommand
{
    /** @param list<string> $args */
    public function __construct(private array $args)
    {
    }

    /** @return list<string> */
    public function args(): array
    {
        return $this->args;
    }

    public function count(): int
    {
        return count($this->args);
    }

    public function isEmpty(): bool
    {
        return $this->args === [];
    }

    /** Upper-cased argv[0] for dispatch (the command word). '' for an empty command. */
    public function name(): string
    {
        return strtoupper($this->args[0] ?? '');
    }

    /** Upper-cased argv[1] — the sub-command word for CONFIG/CLIENT/COMMAND/MODULE. */
    public function sub(): string
    {
        return strtoupper($this->args[1] ?? '');
    }

    /** The raw (binary-safe) argument at $i, or '' when absent. */
    public function arg(int $i): string
    {
        return $this->args[$i] ?? '';
    }

    /** The raw argument at $i, or null when absent (to distinguish absent from empty). */
    public function argOrNull(int $i): ?string
    {
        return $this->args[$i] ?? null;
    }
}

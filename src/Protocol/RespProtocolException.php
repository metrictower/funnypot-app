<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * A bounded RESP framing error. Carries the exact wire error line a real Redis returns for a
 * protocol violation plus whether the connection must close after that line is flushed (Redis
 * closes the link on a malformed multibulk header, but not on an inline parse slip).
 *
 * The message is a fixed, attacker-independent string — never a reflection of the offending bytes —
 * so a malformed frame can never turn into an amplification or a fingerprint tell.
 */
final class RespProtocolException extends \RuntimeException
{
    public function __construct(private string $wireError, private bool $closeAfter = true)
    {
        parent::__construct($wireError);
    }

    /** The `ERR ...`/`Protocol error: ...` text Redis puts after the `-` in its error reply. */
    public function wireError(): string
    {
        return $this->wireError;
    }

    /** Whether the link is closed after the error is sent (true for a multibulk protocol error). */
    public function closeAfter(): bool
    {
        return $this->closeAfter;
    }
}

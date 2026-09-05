<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use RuntimeException;

/**
 * Thrown when a request exceeds a hard parser cap (body/message/tool/schema size, depth, name length).
 * The handler's parse guard turns any parse throwable into the provider's ordinary 400, so an oversize
 * or malformed request is refused in-shape rather than silently truncated in a way that changes meaning.
 */
final class ParseLimitError extends RuntimeException
{
}

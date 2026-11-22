<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use RuntimeException;

/** A command line that expansion grew past the console's limit: E2BIG. */
final class ArgListTooLong extends RuntimeException
{
}

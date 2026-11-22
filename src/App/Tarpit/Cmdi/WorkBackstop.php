<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use RuntimeException;

/** A request that ran past the wall-clock backstop: the console answers it with the plain landing. */
final class WorkBackstop extends RuntimeException
{
}

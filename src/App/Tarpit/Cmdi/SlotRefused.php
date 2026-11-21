<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use RuntimeException;

/** Thrown when an answer would have to echo attacker text that the reflection rules do not allow. */
final class SlotRefused extends RuntimeException
{
}

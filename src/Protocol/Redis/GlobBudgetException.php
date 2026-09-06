<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

/**
 * Raised when a KEYS / SCAN / CONFIG GET glob exhausts its per-command state-transition budget. The
 * command then returns one fixed bounded error before any partial result or cursor is emitted, so an
 * adversarial pattern spray can never pin the loop.
 */
final class GlobBudgetException extends \RuntimeException
{
}

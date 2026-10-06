<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * Thrown when a ledger entry violates the §2.1 schema (grammar, ranges, counts, missing control,
 * unknown implementation, duplicate variant) or its stored hash does not match the canonical bytes.
 * The registry catches it per entry: a bad definition is dropped, never fatal.
 */
final class InvalidExperimentException extends \RuntimeException
{
}

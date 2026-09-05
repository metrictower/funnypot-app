<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Value;

/**
 * One client-supplied tool, normalised to only the bounded values the decoy needs to decide whether it
 * is safe to fabricate a call to it. Descriptions, examples and unknown extension keys are discarded
 * after byte accounting so nothing attacker-controlled beyond the name/schema shape survives into the
 * response or telemetry.
 *
 * The schema is the canonical (recursively key-sorted) supported subset; $schemaHash is its SHA-256, so
 * two requests that describe the same tool differently still hash identically for telemetry/state.
 */
final class ToolDefinition
{
    /**
     * @param array<string,mixed> $schema canonical supported schema (object root, scalar properties)
     */
    public function __construct(
        public string $name,
        public array $schema,
        public string $schemaHash,
        public int $order
    ) {
    }
}

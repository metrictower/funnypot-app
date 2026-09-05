<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Value;

/**
 * The normalised tool-choice directive, collapsed across the three providers' spellings:
 *   - OpenAI: "none"|"auto"|"required" or {type:function, function:{name}}
 *   - Anthropic: {type:none|auto|any|tool, name?}
 *   - Ollama: no field — always AUTO (prompt intent selects the turn).
 *
 * AUTO calls only on explicit prompt intent; REQUIRED/ANY force a call to the first eligible tool;
 * NAMED forces that exact tool; NONE suppresses any call. A forcing choice never weakens the safety
 * selection — an unsafe named/first tool yields a clarification, not a call.
 */
final class ToolChoice
{
    public const NONE = 'none';
    public const AUTO = 'auto';
    public const REQUIRED = 'required';
    public const NAMED = 'named';

    public function __construct(
        public string $mode = self::AUTO,
        public ?string $name = null
    ) {
    }

    public function forcesCall(): bool
    {
        return $this->mode === self::REQUIRED || $this->mode === self::NAMED;
    }
}

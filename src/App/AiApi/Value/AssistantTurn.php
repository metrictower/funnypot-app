<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Value;

/**
 * The resolved semantic result of one chat turn, decided in full BEFORE any byte is framed. Exactly one
 * of three kinds — plain text, a single inert tool call, or a length stop (the output budget could not
 * fit the intended reply). Dialects frame this object into their provider-exact wire shape; resolving it
 * up front is what lets a fault degrade to a fallback rather than a torn half-stream.
 */
final class AssistantTurn
{
    public const TEXT = 'text';
    public const TOOL_CALL = 'tool_call';
    public const LENGTH = 'length';

    private function __construct(
        public string $kind,
        public string $text,
        public ?ToolCall $call
    ) {
    }

    public static function text(string $text): self
    {
        return new self(self::TEXT, $text, null);
    }

    public static function toolCall(ToolCall $call): self
    {
        return new self(self::TOOL_CALL, '', $call);
    }

    public static function length(): self
    {
        return new self(self::LENGTH, '', null);
    }

    public function isText(): bool
    {
        return $this->kind === self::TEXT;
    }

    public function isToolCall(): bool
    {
        return $this->kind === self::TOOL_CALL;
    }

    public function isLength(): bool
    {
        return $this->kind === self::LENGTH;
    }
}

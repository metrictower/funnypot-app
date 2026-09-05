<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\App\AiApi\Value\ToolDefinition;

/**
 * One normalised chat request, however the client phrased it (ollama /api/chat vs /api/generate,
 * OpenAI /v1/chat/completions, Anthropic /v1/messages). The dialect layer parses each of those
 * request shapes into this one DTO, so everything downstream (prompt builder, stats, stream emitter,
 * fallback, tool planner) works against a single shape instead of three.
 *
 * The first six fields are the original text-turn shape and stay positional so the error/fallback
 * blank-request path keeps working; everything after is the bounded tool-calling/loop state, defaulted
 * so a plain text request need not supply it. The requested $model is echoed only after the parser has
 * length- and control-character-bounded it.
 */
final class ChatRequest
{
    /**
     * @param list<ToolDefinition> $tools accepted tool definitions in provider order
     * @param list<array{role:string,text:string}> $promptMessages accepted user/system text, retained
     *        ONLY for the opt-in prompt-capture path; never read by telemetry or the wire response
     */
    public function __construct(
        public string $dialect,      // 'ollama-chat'|'ollama-generate'|'openai'|'anthropic'
        public string $model,        // as sent by client (bounded, then echoed)
        public string $userText,     // last user message / prompt, for the LLM
        public bool $stream,         // effective stream flag (dialect default applied by the dialect)
        public bool $hasAuth,        // auth header present & non-empty
        public bool $includeUsage,   // OpenAI stream_options.include_usage
        public array $tools = [],
        public string $toolChoiceMode = ToolChoice::AUTO,
        public ?string $toolChoiceName = null,
        public bool $callIntent = false,        // explicit "call the tool" intent in the latest user turn
        public bool $wantsAnotherCall = false,  // explicit ask for a further call (extends the loop)
        public int $priorToolCalls = 0,         // assistant tool_call turns already in the history
        public bool $hasToolResult = false,     // the latest turn is a returned tool result
        public ?string $lastCallId = null,      // OpenAI/Anthropic id the returned result correlates to
        public ?string $lastToolName = null,    // tool name of the most recent call/result
        public string $conversationKey = '',    // digest of the prior conversation (Ollama correlation)
        public int $maxOutputTokens = -1,        // requested output budget; -1 = absent
        public int $inputTokens = 0,             // accumulated input-token estimate
        public array $promptMessages = []
    ) {
    }
}

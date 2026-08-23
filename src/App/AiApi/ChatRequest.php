<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

/**
 * One normalised chat request, however the client phrased it (ollama /api/chat vs /api/generate,
 * OpenAI /v1/chat/completions, Anthropic /v1/messages). The dialect layer parses each of those
 * request shapes into this one DTO, so everything downstream (prompt builder, stats, stream emitter,
 * fallback) works against a single shape instead of three.
 */
final class ChatRequest
{
    public function __construct(
        public string $dialect,      // 'ollama-chat'|'ollama-generate'|'openai'|'anthropic'
        public string $model,        // as sent by client (echoed verbatim)
        public string $userText,     // last user message / prompt, for the LLM
        public bool $stream,         // effective stream flag (dialect default applied by the dialect)
        public bool $hasAuth,        // auth header present & non-empty
        public bool $includeUsage    // OpenAI stream_options.include_usage
    ) {
    }
}

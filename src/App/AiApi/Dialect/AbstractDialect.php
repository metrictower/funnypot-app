<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Dialect;

use Funnypot\App\AiApi\ChatDialect;
use Funnypot\App\AiApi\ChatStats;
use Funnypot\App\AiApi\ToolRequestParser;
use Funnypot\App\AiApi\UsageEstimator;

/**
 * Shared framing helpers for the concrete dialects: word-boundary chunking, real-server JSON encoding,
 * a deterministic token estimate, and case-insensitive header lookup. ChatStats is injectable so tests
 * pin exact ids/timestamps/counters instead of depending on wall-clock time or randomness. The bounded
 * tool-request parser and the shared usage estimator are shared instances the concrete parse()/framing
 * reuse so tool handling stays identical across providers.
 */
abstract class AbstractDialect implements ChatDialect
{
    protected ChatStats $stats;
    protected ToolRequestParser $toolParser;
    protected UsageEstimator $usageEstimator;

    public function __construct(?ChatStats $stats = null)
    {
        $this->stats = $stats ?? new ChatStats();
        $this->toolParser = new ToolRequestParser();
        $this->usageEstimator = new UsageEstimator();
    }

    public function toolCallId(): string
    {
        return '';
    }

    /**
     * A stable digest of the prior conversation (every message but the last), used to correlate an
     * Ollama tool result to the call the decoy issued, since Ollama's shape carries no call id.
     *
     * @param list<array{role:string,text:string}> $priorRoleTexts
     */
    protected function conversationKey(array $priorRoleTexts): string
    {
        if ($priorRoleTexts === []) {
            return '';
        }
        $parts = [];
        foreach ($priorRoleTexts as $rt) {
            $parts[] = $rt['role'] . ':' . $rt['text'];
        }

        return hash('sha256', implode("\n", $parts));
    }

    /**
     * Split into streaming pieces on word boundaries, keeping each run of whitespace attached to the
     * word before it, so concatenating the pieces reproduces $text byte-for-byte.
     *
     * @return string[]
     */
    protected function chunks(string $text): array
    {
        if ($text === '') {
            return [];
        }

        return preg_split('/(?<=\s)/u', $text, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    /** Encode like the real servers do: slashes and unicode unescaped, never pretty-printed. */
    protected function json(mixed $value): string
    {
        return (string) json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /** Rough token estimate that scales with text length like a real tokenizer; deterministic. */
    protected function estimateTokens(string $text): int
    {
        $text = trim($text);
        if ($text === '') {
            return 1;
        }

        return max(1, (int) ceil(strlen($text) / 4));
    }

    /**
     * Last user turn as plain text. Anthropic (and newer OpenAI) allow content to be an array of
     * typed blocks rather than a string; collect the text blocks in both shapes.
     *
     * @param array<int,mixed> $messages
     */
    protected function lastUserText(array $messages): string
    {
        $text = '';
        foreach ($messages as $message) {
            if (is_array($message) && ($message['role'] ?? null) === 'user') {
                $text = $this->flattenContent($message['content'] ?? '');
            }
        }

        return $text;
    }

    /** @param mixed $content string, or an array of {type:text,text} blocks */
    protected function flattenContent(mixed $content): string
    {
        if (is_string($content)) {
            return $content;
        }
        if (!is_array($content)) {
            return '';
        }

        $parts = [];
        foreach ($content as $block) {
            if (is_array($block) && ($block['type'] ?? null) === 'text' && is_string($block['text'] ?? null)) {
                $parts[] = $block['text'];
            }
        }

        return implode("\n", $parts);
    }

    /**
     * Case-insensitive header lookup — RequestContext keys are whatever casing the origin used.
     *
     * @param array<string,string> $headers
     */
    protected function header(array $headers, string $name): ?string
    {
        $needle = strtolower($name);
        foreach ($headers as $key => $value) {
            if (strtolower((string) $key) === $needle) {
                return (string) $value;
            }
        }

        return null;
    }

    /** @param array<string,string> $headers */
    protected function hasHeaderValue(array $headers, string $name): bool
    {
        $value = $this->header($headers, $name);

        return $value !== null && trim($value) !== '';
    }

    /** @return array<string,mixed> */
    protected function decodeBody(?string $rawBody): array
    {
        $data = json_decode((string) $rawBody, true);

        return is_array($data) ? $data : [];
    }

    /**
     * Walk an OpenAI/Ollama-style role message list into the bounded loop facts. Assistant messages with
     * a non-empty tool_calls array count as prior calls; a trailing role:tool message is a returned
     * result (its result content is measured, never retained). System/user text is collected for the
     * opt-in capture path only.
     *
     * @param array<int,mixed> $messages
     * @return array{priorToolCalls:int,hasToolResult:bool,lastCallId:?string,lastToolName:?string,userText:string,conversationKey:string,promptMessages:list<array{role:string,text:string}>,textTokens:int}
     */
    protected function openAiStyleHistory(array $messages): array
    {
        $priorToolCalls = 0;
        $lastCallId = null;
        $lastToolName = null;
        $userText = '';
        $promptMessages = [];
        $prior = [];
        $textTokens = 0;
        $count = count($messages);

        foreach (array_values($messages) as $i => $message) {
            if (!is_array($message)) {
                continue;
            }
            $role = is_string($message['role'] ?? null) ? $message['role'] : '';
            $text = $this->flattenContent($message['content'] ?? '');

            if ($role === 'assistant' && is_array($message['tool_calls'] ?? null) && $message['tool_calls'] !== []) {
                $priorToolCalls++;
                $name = $this->lastToolCallName($message['tool_calls']);
                if ($name !== null) {
                    $lastToolName = $name;
                }
            }
            if ($role === 'user' && $text !== '') {
                $userText = $text;
            }
            if (($role === 'user' || $role === 'system') && $text !== '') {
                $promptMessages[] = ['role' => $role, 'text' => $text];
                $textTokens += $this->usageEstimator->tokens($text);
            }
            if ($i < $count - 1) {
                $prior[] = ['role' => $role, 'text' => $text];
            }
        }

        $last = $count > 0 ? $messages[$count - 1] : null;
        $hasToolResult = is_array($last) && ($last['role'] ?? null) === 'tool';
        if ($hasToolResult) {
            if (is_string($last['tool_call_id'] ?? null)) {
                $lastCallId = substr($last['tool_call_id'], 0, ToolRequestParser::MAX_NAME_BYTES);
            }
            if (is_string($last['tool_name'] ?? null) && $lastToolName === null) {
                $lastToolName = substr($last['tool_name'], 0, ToolRequestParser::MAX_NAME_BYTES);
            }
        }

        return [
            'priorToolCalls' => $priorToolCalls,
            'hasToolResult' => $hasToolResult,
            'lastCallId' => $lastCallId,
            'lastToolName' => $lastToolName,
            'userText' => $userText,
            'conversationKey' => $this->conversationKey($prior),
            'promptMessages' => $promptMessages,
            'textTokens' => $textTokens,
        ];
    }

    /**
     * Walk an Anthropic content-block message list (plus its top-level system text) into the same loop
     * facts. Assistant tool_use blocks count as prior calls; a trailing user message carrying a
     * tool_result block is a returned result.
     *
     * @param array<int,mixed> $messages
     * @param mixed $system top-level system: string or array of {type:text,text} blocks
     * @return array{priorToolCalls:int,hasToolResult:bool,lastCallId:?string,lastToolName:?string,userText:string,conversationKey:string,promptMessages:list<array{role:string,text:string}>,textTokens:int}
     */
    protected function anthropicHistory(array $messages, mixed $system): array
    {
        $priorToolCalls = 0;
        $lastCallId = null;
        $lastToolName = null;
        $userText = '';
        $promptMessages = [];
        $prior = [];
        $textTokens = 0;
        $count = count($messages);

        $systemText = $this->flattenContent($system);
        if ($systemText !== '') {
            $promptMessages[] = ['role' => 'system', 'text' => $systemText];
            $textTokens += $this->usageEstimator->tokens($systemText);
        }

        foreach (array_values($messages) as $i => $message) {
            if (!is_array($message)) {
                continue;
            }
            $role = is_string($message['role'] ?? null) ? $message['role'] : '';
            $blocks = is_array($message['content'] ?? null) ? $message['content'] : [];
            $text = $this->flattenContent($message['content'] ?? '');

            if ($role === 'assistant') {
                foreach ($blocks as $block) {
                    if (is_array($block) && ($block['type'] ?? null) === 'tool_use') {
                        $priorToolCalls++;
                        if (is_string($block['name'] ?? null)) {
                            $lastToolName = substr($block['name'], 0, ToolRequestParser::MAX_NAME_BYTES);
                        }
                    }
                }
            }
            if ($role === 'user' && $text !== '') {
                $userText = $text;
                $promptMessages[] = ['role' => 'user', 'text' => $text];
                $textTokens += $this->usageEstimator->tokens($text);
            }
            if ($i < $count - 1) {
                $prior[] = ['role' => $role, 'text' => $text];
            }
        }

        $hasToolResult = false;
        $last = $count > 0 ? $messages[$count - 1] : null;
        if (is_array($last) && ($last['role'] ?? null) === 'user' && is_array($last['content'] ?? null)) {
            foreach ($last['content'] as $block) {
                if (is_array($block) && ($block['type'] ?? null) === 'tool_result') {
                    $hasToolResult = true;
                    if (is_string($block['tool_use_id'] ?? null)) {
                        $lastCallId = substr($block['tool_use_id'], 0, ToolRequestParser::MAX_NAME_BYTES);
                    }
                }
            }
        }

        return [
            'priorToolCalls' => $priorToolCalls,
            'hasToolResult' => $hasToolResult,
            'lastCallId' => $lastCallId,
            'lastToolName' => $lastToolName,
            'userText' => $userText,
            'conversationKey' => $this->conversationKey($prior),
            'promptMessages' => $promptMessages,
            'textTokens' => $textTokens,
        ];
    }

    /**
     * A deterministic token estimate for the accepted tool definitions, so usage reflects the tools a
     * client sent rather than message text alone.
     *
     * @param list<\Funnypot\App\AiApi\Value\ToolDefinition> $tools
     */
    protected function schemaTokens(array $tools): int
    {
        $total = 0;
        foreach ($tools as $tool) {
            $encoded = $tool->name . ' ' . (string) json_encode($tool->schema, JSON_UNESCAPED_SLASHES);
            $total += $this->usageEstimator->tokens($encoded);
        }

        return $total;
    }

    /**
     * Fragment a canonical argument JSON string into streamable pieces whose concatenation is exactly
     * the original — the only thing streamed for a tool call's arguments, so a fragmented stream can
     * never expose an incomplete JSON value. Empty input yields no fragments.
     *
     * @return list<string>
     */
    protected function splitArguments(string $json): array
    {
        if ($json === '') {
            return [];
        }
        $parts = str_split($json, 24);

        return $parts === false ? [$json] : $parts;
    }

    /** @param array<int,mixed> $toolCalls */
    private function lastToolCallName(array $toolCalls): ?string
    {
        $name = null;
        foreach ($toolCalls as $call) {
            if (is_array($call) && is_array($call['function'] ?? null) && is_string($call['function']['name'] ?? null)) {
                $name = substr($call['function']['name'], 0, ToolRequestParser::MAX_NAME_BYTES);
            }
        }

        return $name;
    }
}

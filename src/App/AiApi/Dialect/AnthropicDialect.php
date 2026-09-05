<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Dialect;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\AiApi\Value\AssistantTurn;
use Funnypot\App\AiApi\Value\ToolCall;
use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\Core\RequestContext;

/**
 * Anthropic's /v1/messages. Streaming is named-event SSE (`event: <name>\ndata: {json}\n\n`) in a
 * fixed order — message_start, content_block_start, ping, content_block_delta*, content_block_stop,
 * message_delta, message_stop — with NO `[DONE]` terminator. Streaming is OFF by default, and message
 * content may arrive as a plain string or as an array of typed blocks. A tool call is a single
 * `tool_use` content block with `stop_reason:"tool_use"`; its input is streamed as `input_json_delta`
 * `partial_json` fragments. `max_tokens:0` is a valid cache-warm request: HTTP 200, empty content,
 * `stop_reason:"max_tokens"`, no content-block stream event.
 */
final class AnthropicDialect extends AbstractDialect
{
    private const CT_JSON = 'application/json';
    private const CT_STREAM = 'text/event-stream';

    public function parse(RequestContext $ctx): ChatRequest
    {
        $this->toolParser->assertBodySize($ctx->rawBody);
        $data = $this->decodeBody($ctx->rawBody);
        $hasAuth = $this->hasHeaderValue($ctx->headers, 'x-api-key')
            || $this->hasHeaderValue($ctx->headers, 'Authorization');
        $messages = is_array($data['messages'] ?? null) ? $data['messages'] : [];
        $history = $this->anthropicHistory($messages, $data['system'] ?? null);

        $tools = $this->toolParser->tools($this->normalizeTools($data['tools'] ?? []), 'input_schema');
        $choice = $this->toolParser->choice($data['tool_choice'] ?? null, ToolChoice::AUTO);

        return new ChatRequest(
            'anthropic',
            substr((string) ($data['model'] ?? ''), 0, 128),
            $history['userText'],
            array_key_exists('stream', $data) ? (bool) $data['stream'] : false,
            $hasAuth,
            false,
            $tools,
            $choice->mode,
            $choice->name,
            $this->toolParser->callIntent($history['userText']),
            $this->toolParser->anotherCallIntent($history['userText']),
            $history['priorToolCalls'],
            $history['hasToolResult'],
            $history['lastCallId'],
            $history['lastToolName'],
            $history['conversationKey'],
            (isset($data['max_tokens']) && is_int($data['max_tokens']) && $data['max_tokens'] >= 0) ? $data['max_tokens'] : -1,
            $history['textTokens'] + $this->schemaTokens($tools),
            $history['promptMessages'],
        );
    }

    public function needsAuth(): bool
    {
        return true;
    }

    public function toolCallId(): string
    {
        return $this->stats->toolId('toolu_');
    }

    public function contentTypeStream(): string
    {
        return self::CT_STREAM;
    }

    public function streamOk(string $text, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        $id = $this->stats->anthropicId();
        $inputTokens = $this->estimateTokens($req->userText);
        $outputTokens = $this->estimateTokens($text);

        $this->messageStart($out, $id, $req, $inputTokens);
        $out->chunk($this->event('content_block_start', [
            'type' => 'content_block_start',
            'index' => 0,
            'content_block' => ['type' => 'text', 'text' => ''],
        ]));
        $out->chunk($this->event('ping', ['type' => 'ping']));

        foreach ($this->chunks($text) as $piece) {
            $out->chunk($this->event('content_block_delta', [
                'type' => 'content_block_delta',
                'index' => 0,
                'delta' => ['type' => 'text_delta', 'text' => $piece],
            ]));
        }

        $out->chunk($this->event('content_block_stop', ['type' => 'content_block_stop', 'index' => 0]));
        $this->messageDelta($out, 'end_turn', $outputTokens);
        $out->chunk($this->event('message_stop', ['type' => 'message_stop']));
    }

    public function bufferedOk(string $text, ChatRequest $req): array
    {
        $body = $this->message($req, [['type' => 'text', 'text' => $text]], 'end_turn', [
            'input_tokens' => $this->estimateTokens($req->userText),
            'output_tokens' => $this->estimateTokens($text),
        ]);

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function bufferedTool(ToolCall $call, ChatRequest $req): array
    {
        $u = $this->usageEstimator->usage($req->inputTokens, AssistantTurn::toolCall($call));
        $body = $this->message($req, [[
            'type' => 'tool_use',
            'id' => $call->id,
            'name' => $call->name,
            'input' => $call->arguments === [] ? new \stdClass() : $call->arguments,
        ]], 'tool_use', ['input_tokens' => $u['input'], 'output_tokens' => $u['output']]);

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function streamTool(ToolCall $call, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        $id = $this->stats->anthropicId();
        $u = $this->usageEstimator->usage($req->inputTokens, AssistantTurn::toolCall($call));

        $this->messageStart($out, $id, $req, $u['input']);
        $out->chunk($this->event('content_block_start', [
            'type' => 'content_block_start',
            'index' => 0,
            'content_block' => ['type' => 'tool_use', 'id' => $call->id, 'name' => $call->name, 'input' => new \stdClass()],
        ]));
        $out->chunk($this->event('ping', ['type' => 'ping']));
        foreach ($this->splitArguments($call->argumentsJson) as $piece) {
            $out->chunk($this->event('content_block_delta', [
                'type' => 'content_block_delta',
                'index' => 0,
                'delta' => ['type' => 'input_json_delta', 'partial_json' => $piece],
            ]));
        }
        $out->chunk($this->event('content_block_stop', ['type' => 'content_block_stop', 'index' => 0]));
        $this->messageDelta($out, 'tool_use', $u['output']);
        $out->chunk($this->event('message_stop', ['type' => 'message_stop']));
    }

    public function bufferedLength(ChatRequest $req): array
    {
        // Empty content + max_tokens covers both a length stop and the cache-warm max_tokens:0 request.
        $input = max(1, $req->inputTokens);
        $body = $this->message($req, [], 'max_tokens', ['input_tokens' => $input, 'output_tokens' => 0]);

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function streamLength(ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        $id = $this->stats->anthropicId();
        $input = max(1, $req->inputTokens);
        $this->messageStart($out, $id, $req, $input);
        // No content-block events for a length/zero-token stop.
        $this->messageDelta($out, 'max_tokens', 0);
        $out->chunk($this->event('message_stop', ['type' => 'message_stop']));
    }

    public function error(string $kind, ChatRequest $req): array
    {
        [$status, $type, $message] = $this->errorSpec($kind, $req);

        return [$status, ['Content-Type' => self::CT_JSON], $this->json([
            'type' => 'error',
            'error' => ['type' => $type, 'message' => $message],
        ])];
    }

    private function messageStart(StreamEmitter $out, string $id, ChatRequest $req, int $inputTokens): void
    {
        $out->chunk($this->event('message_start', [
            'type' => 'message_start',
            'message' => [
                'id' => $id,
                'type' => 'message',
                'role' => 'assistant',
                'model' => $req->model,
                'content' => [],
                'stop_reason' => null,
                'stop_sequence' => null,
                'usage' => ['input_tokens' => $inputTokens, 'output_tokens' => 1],
            ],
        ]));
    }

    private function messageDelta(StreamEmitter $out, string $stopReason, int $outputTokens): void
    {
        $out->chunk($this->event('message_delta', [
            'type' => 'message_delta',
            'delta' => ['stop_reason' => $stopReason, 'stop_sequence' => null],
            'usage' => ['output_tokens' => $outputTokens],
        ]));
    }

    /**
     * @param array<int,array<string,mixed>> $content
     * @param array<string,int> $usage input/output tokens
     * @return array<string,mixed>
     */
    private function message(ChatRequest $req, array $content, string $stopReason, array $usage): array
    {
        return [
            'id' => $this->stats->anthropicId(),
            'type' => 'message',
            'role' => 'assistant',
            'model' => $req->model,
            'content' => $content,
            'stop_reason' => $stopReason,
            'stop_sequence' => null,
            'usage' => [
                'input_tokens' => $usage['input_tokens'],
                'output_tokens' => $usage['output_tokens'],
                'cache_creation_input_tokens' => 0,
                'cache_read_input_tokens' => 0,
            ],
        ];
    }

    /** @return array{0:int,1:string,2:string} */
    private function errorSpec(string $kind, ChatRequest $req): array
    {
        if ($kind === 'auth') {
            return [401, 'authentication_error', 'invalid x-api-key'];
        }
        if ($kind === 'model') {
            return [404, 'not_found_error', "model: {$req->model}"];
        }

        return [400, 'invalid_request_error', 'invalid request'];
    }

    /**
     * Anthropic tools are already {name, input_schema}; keep only well-formed entries for the parser.
     *
     * @param mixed $tools
     * @return array<int,array<string,mixed>>
     */
    private function normalizeTools(mixed $tools): array
    {
        if (!is_array($tools)) {
            return [];
        }
        $out = [];
        foreach ($tools as $tool) {
            if (is_array($tool) && is_string($tool['name'] ?? null)) {
                $out[] = ['name' => $tool['name'], 'input_schema' => $tool['input_schema'] ?? []];
            }
        }

        return $out;
    }

    /** @param array<string,mixed> $obj */
    private function event(string $name, array $obj): string
    {
        return "event: {$name}\ndata: " . $this->json($obj) . "\n\n";
    }
}

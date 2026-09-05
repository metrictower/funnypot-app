<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Dialect;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\AiApi\Value\AssistantTurn;
use Funnypot\App\AiApi\Value\ToolCall;
use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\Core\RequestContext;
use stdClass;

/**
 * OpenAI's /v1/chat/completions. Streaming is Server-Sent Events (`data: {json}\n\n` per chunk,
 * object chatcompletion.chunk) terminated by a literal `data: [DONE]`. Streaming is OFF by default,
 * and the same id/created/system_fingerprint repeats on every chunk of one response. A tool call comes
 * back with `message.content:null`, `finish_reason:"tool_calls"`, and function arguments as a JSON
 * string; streaming fragments only the argument string and closes with an empty `finish_reason` delta.
 */
final class OpenAiDialect extends AbstractDialect
{
    private const CT_JSON = 'application/json';
    private const CT_STREAM = 'text/event-stream';

    public function parse(RequestContext $ctx): ChatRequest
    {
        $this->toolParser->assertBodySize($ctx->rawBody);
        $data = $this->decodeBody($ctx->rawBody);
        $streamOptions = $data['stream_options'] ?? null;
        $messages = is_array($data['messages'] ?? null) ? $data['messages'] : [];
        $history = $this->openAiStyleHistory($messages);

        $tools = $this->toolParser->tools($this->unwrapFunctionTools($data['tools'] ?? []), 'parameters');
        $choice = $this->toolParser->choice($data['tool_choice'] ?? null, ToolChoice::AUTO);
        $schemaTokens = $this->schemaTokens($tools);

        return new ChatRequest(
            'openai',
            substr((string) ($data['model'] ?? ''), 0, 128),
            $history['userText'],
            array_key_exists('stream', $data) ? (bool) $data['stream'] : false,
            $this->hasHeaderValue($ctx->headers, 'Authorization'),
            is_array($streamOptions) && ($streamOptions['include_usage'] ?? null) === true,
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
            $this->outputBudget($data),
            $history['textTokens'] + $schemaTokens,
            $history['promptMessages'],
        );
    }

    public function needsAuth(): bool
    {
        return true;
    }

    public function toolCallId(): string
    {
        return $this->stats->toolId('call_');
    }

    public function contentTypeStream(): string
    {
        return self::CT_STREAM;
    }

    public function streamOk(string $text, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        [$id, $created, $fp] = $this->streamIdentity();
        $chunk = fn (mixed $delta, ?string $finish): string => $this->sse(
            $this->chunkObject($id, $created, $req->model, $fp, $delta, $finish)
        );

        $out->chunk($chunk(['role' => 'assistant', 'content' => ''], null));
        foreach ($this->chunks($text) as $piece) {
            $out->chunk($chunk(['content' => $piece], null));
        }
        $out->chunk($chunk(new stdClass(), 'stop'));
        $this->maybeUsageChunk($out, $id, $created, $req->model, $fp, $req, $this->usage($req->userText, $text));
        $out->chunk("data: [DONE]\n\n");
    }

    public function bufferedOk(string $text, ChatRequest $req): array
    {
        $body = $this->completion($req, [
            'index' => 0,
            'message' => ['role' => 'assistant', 'content' => $text, 'refusal' => null],
            'logprobs' => null,
            'finish_reason' => 'stop',
        ], $this->usage($req->userText, $text));

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function bufferedTool(ToolCall $call, ChatRequest $req): array
    {
        $body = $this->completion($req, [
            'index' => 0,
            'message' => [
                'role' => 'assistant',
                'content' => null,
                'tool_calls' => [$this->toolCallObject($call)],
                'refusal' => null,
            ],
            'logprobs' => null,
            'finish_reason' => 'tool_calls',
        ], $this->toolUsage($req, $call));

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function streamTool(ToolCall $call, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        [$id, $created, $fp] = $this->streamIdentity();
        // When include_usage is set, every non-final chunk carries usage:null and only the trailing
        // usage chunk carries the real counts — the exact shape a real server emits.
        $chunk = function (mixed $delta, ?string $finish) use ($id, $created, $req, $fp): string {
            $obj = $this->chunkObject($id, $created, $req->model, $fp, $delta, $finish);
            if ($req->includeUsage) {
                $obj['usage'] = null;
            }

            return $this->sse($obj);
        };

        $out->chunk($chunk(['role' => 'assistant', 'content' => null], null));
        // First tool-call delta carries the identity + name and empty arguments; the id/name never
        // repeat, only the argument fragments do.
        $out->chunk($chunk(['tool_calls' => [[
            'index' => 0,
            'id' => $call->id,
            'type' => 'function',
            'function' => ['name' => $call->name, 'arguments' => ''],
        ]]], null));
        foreach ($this->splitArguments($call->argumentsJson) as $piece) {
            $out->chunk($chunk(['tool_calls' => [[
                'index' => 0,
                'function' => ['arguments' => $piece],
            ]]], null));
        }
        $out->chunk($chunk(new stdClass(), 'tool_calls'));
        $this->maybeUsageChunk($out, $id, $created, $req->model, $fp, $req, $this->toolUsage($req, $call));
        $out->chunk("data: [DONE]\n\n");
    }

    public function bufferedLength(ChatRequest $req): array
    {
        $body = $this->completion($req, [
            'index' => 0,
            'message' => ['role' => 'assistant', 'content' => '', 'refusal' => null],
            'logprobs' => null,
            'finish_reason' => 'length',
        ], $this->lengthUsage($req));

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function streamLength(ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        [$id, $created, $fp] = $this->streamIdentity();
        $chunk = function (mixed $delta, ?string $finish) use ($id, $created, $req, $fp): string {
            $obj = $this->chunkObject($id, $created, $req->model, $fp, $delta, $finish);
            if ($req->includeUsage) {
                $obj['usage'] = null;
            }

            return $this->sse($obj);
        };

        $out->chunk($chunk(['role' => 'assistant', 'content' => ''], null));
        $out->chunk($chunk(new stdClass(), 'length'));
        $this->maybeUsageChunk($out, $id, $created, $req->model, $fp, $req, $this->lengthUsage($req));
        $out->chunk("data: [DONE]\n\n");
    }

    public function error(string $kind, ChatRequest $req): array
    {
        [$status, $message, $type, $code] = $this->errorSpec($kind, $req);

        return [$status, ['Content-Type' => self::CT_JSON], $this->json([
            'error' => ['message' => $message, 'type' => $type, 'param' => null, 'code' => $code],
        ])];
    }

    /** @return array{0:string,1:int,2:string} */
    private function streamIdentity(): array
    {
        return [$this->stats->openAiId(), $this->stats->openAiCreated(), $this->stats->systemFingerprint()];
    }

    /**
     * @param array<string,mixed> $choice a single choices[] entry
     * @param array<string,int> $usage
     * @return array<string,mixed>
     */
    private function completion(ChatRequest $req, array $choice, array $usage): array
    {
        return [
            'id' => $this->stats->openAiId(),
            'object' => 'chat.completion',
            'created' => $this->stats->openAiCreated(),
            'model' => $req->model,
            'choices' => [$choice],
            'usage' => $usage,
            'system_fingerprint' => $this->stats->systemFingerprint(),
        ];
    }

    /** @return array<string,mixed> */
    private function toolCallObject(ToolCall $call): array
    {
        return [
            'id' => $call->id,
            'type' => 'function',
            'function' => ['name' => $call->name, 'arguments' => $call->argumentsJson],
        ];
    }

    private function maybeUsageChunk(StreamEmitter $out, string $id, int $created, string $model, string $fp, ChatRequest $req, array $usage): void
    {
        if (!$req->includeUsage) {
            return;
        }
        $out->chunk($this->sse([
            'id' => $id,
            'object' => 'chat.completion.chunk',
            'created' => $created,
            'model' => $model,
            'system_fingerprint' => $fp,
            'choices' => [],
            'usage' => $usage,
        ]));
    }

    /** @return array{0:int,1:string,2:string,3:?string} */
    private function errorSpec(string $kind, ChatRequest $req): array
    {
        if ($kind === 'auth') {
            return [401, 'Incorrect API key provided.', 'invalid_request_error', 'invalid_api_key'];
        }
        if ($kind === 'model') {
            return [
                404,
                "The model `{$req->model}` does not exist or you do not have access to it.",
                'invalid_request_error',
                'model_not_found',
            ];
        }

        return [400, 'Invalid request body.', 'invalid_request_error', null];
    }

    /**
     * @param mixed $delta assoc array, or an empty stdClass so it encodes as `{}` not `[]`
     * @return array<string,mixed>
     */
    private function chunkObject(string $id, int $created, string $model, string $fp, mixed $delta, ?string $finish): array
    {
        return [
            'id' => $id,
            'object' => 'chat.completion.chunk',
            'created' => $created,
            'model' => $model,
            'system_fingerprint' => $fp,
            'choices' => [[
                'index' => 0,
                'delta' => $delta,
                'logprobs' => null,
                'finish_reason' => $finish,
            ]],
        ];
    }

    /** @return array<string,int> */
    private function usage(string $prompt, string $completion): array
    {
        $promptTokens = $this->estimateTokens($prompt);
        $completionTokens = $this->estimateTokens($completion);

        return [
            'prompt_tokens' => $promptTokens,
            'completion_tokens' => $completionTokens,
            'total_tokens' => $promptTokens + $completionTokens,
        ];
    }

    /** @return array<string,int> */
    private function toolUsage(ChatRequest $req, ToolCall $call): array
    {
        $u = $this->usageEstimator->usage($req->inputTokens, AssistantTurn::toolCall($call));

        return ['prompt_tokens' => $u['input'], 'completion_tokens' => $u['output'], 'total_tokens' => $u['total']];
    }

    /** @return array<string,int> */
    private function lengthUsage(ChatRequest $req): array
    {
        $input = max(1, $req->inputTokens);

        return ['prompt_tokens' => $input, 'completion_tokens' => 0, 'total_tokens' => $input];
    }

    /** @param array<string,mixed> $obj */
    private function sse(array $obj): string
    {
        return 'data: ' . $this->json($obj) . "\n\n";
    }

    /**
     * OpenAI function tools wrap the schema under function.{name,parameters}. Flatten to the parser's
     * {name, parameters} shape; non-function or malformed entries are dropped.
     *
     * @param mixed $tools
     * @return array<int,array<string,mixed>>
     */
    private function unwrapFunctionTools(mixed $tools): array
    {
        if (!is_array($tools)) {
            return [];
        }
        $out = [];
        foreach ($tools as $tool) {
            if (!is_array($tool)) {
                continue;
            }
            $fn = $tool['function'] ?? null;
            if (($tool['type'] ?? 'function') === 'function' && is_array($fn) && is_string($fn['name'] ?? null)) {
                $out[] = ['name' => $fn['name'], 'parameters' => $fn['parameters'] ?? []];
            }
        }

        return $out;
    }

    /** Prefer max_completion_tokens; fall back to legacy max_tokens; absent => -1 (no budget). */
    private function outputBudget(array $data): int
    {
        foreach (['max_completion_tokens', 'max_tokens'] as $key) {
            if (isset($data[$key]) && is_int($data[$key]) && $data[$key] >= 0) {
                return $data[$key];
            }
        }

        return -1;
    }
}

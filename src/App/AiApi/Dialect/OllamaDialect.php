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
 * Ollama's native API — both /api/chat (message array) and /api/generate (single prompt), told apart
 * by the request path. Streaming is newline-delimited JSON (one object per line, no framing prefix,
 * no terminator) and defaults ON; the done object carries the timing/eval counters. Tool calls are
 * supported on /api/chat only: the assistant message carries `tool_calls[].function` with an OBJECT
 * arguments value; the stream emits exactly one call-bearing record then one call-free `done` record so
 * an accumulating client sees exactly one call. /api/generate stays text-only. Ollama's shape has no
 * call id, so a returned result is correlated by conversation + tool name instead.
 */
final class OllamaDialect extends AbstractDialect
{
    private const CT_JSON = 'application/json; charset=utf-8';
    private const CT_STREAM = 'application/x-ndjson';

    public function parse(RequestContext $ctx): ChatRequest
    {
        $this->toolParser->assertBodySize($ctx->rawBody);
        $data = $this->decodeBody($ctx->rawBody);
        $isGenerate = strpos($ctx->path, '/api/generate') !== false;

        if ($isGenerate) {
            $prompt = (string) ($data['prompt'] ?? '');

            return new ChatRequest(
                'ollama-generate',
                substr((string) ($data['model'] ?? ''), 0, 128),
                $prompt,
                array_key_exists('stream', $data) ? (bool) $data['stream'] : true,
                false,
                false,
                [],
                ToolChoice::AUTO,
                null,
                false,
                false,
                0,
                false,
                null,
                null,
                '',
                -1,
                $this->usageEstimator->tokens($prompt),
                $prompt !== '' ? [['role' => 'user', 'text' => $prompt]] : [],
            );
        }

        $messages = is_array($data['messages'] ?? null) ? $data['messages'] : [];
        $history = $this->openAiStyleHistory($messages);
        $tools = $this->toolParser->tools($this->unwrapFunctionTools($data['tools'] ?? []), 'parameters');

        return new ChatRequest(
            'ollama-chat',
            substr((string) ($data['model'] ?? ''), 0, 128),
            $history['userText'],
            array_key_exists('stream', $data) ? (bool) $data['stream'] : true,
            false,
            false,
            $tools,
            ToolChoice::AUTO,
            null,
            $this->toolParser->callIntent($history['userText']),
            $this->toolParser->anotherCallIntent($history['userText']),
            $history['priorToolCalls'],
            $history['hasToolResult'],
            $history['lastCallId'],
            $history['lastToolName'],
            $history['conversationKey'],
            $this->numPredict($data),
            $history['textTokens'] + $this->schemaTokens($tools),
            $history['promptMessages'],
        );
    }

    public function needsAuth(): bool
    {
        return false;
    }

    public function contentTypeStream(): string
    {
        return self::CT_STREAM;
    }

    public function streamOk(string $text, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        $isGenerate = $req->dialect === 'ollama-generate';
        $pieces = $this->chunks($text);

        foreach ($pieces as $piece) {
            $out->chunk($this->json($this->progress($req->model, $piece, $isGenerate)) . "\n");
        }

        $out->chunk($this->json($this->done($req->model, '', count($pieces), $isGenerate, $this->promptTokens($req), null, 'stop')) . "\n");
    }

    public function bufferedOk(string $text, ChatRequest $req): array
    {
        $isGenerate = $req->dialect === 'ollama-generate';
        $body = $this->done($req->model, $text, count($this->chunks($text)), $isGenerate, $this->promptTokens($req), null, 'stop');

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function bufferedTool(ToolCall $call, ChatRequest $req): array
    {
        $body = $this->done($req->model, '', 1, false, $this->promptTokens($req), $call, 'stop');

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function streamTool(ToolCall $call, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        // One record carrying the complete call (done=false), then one call-free done record — an
        // accumulating client therefore sees exactly one call.
        $progress = [
            'model' => $req->model,
            'created_at' => $this->stats->ollamaCreatedAt(),
            'message' => ['role' => 'assistant', 'content' => '', 'tool_calls' => [$this->toolCallObject($call)]],
            'done' => false,
        ];
        $out->chunk($this->json($progress) . "\n");
        $out->chunk($this->json($this->done($req->model, '', 1, false, $this->promptTokens($req), null, 'stop')) . "\n");
    }

    public function bufferedLength(ChatRequest $req): array
    {
        $body = $this->done($req->model, '', 0, $req->dialect === 'ollama-generate', $this->promptTokens($req), null, 'length');

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function streamLength(ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);
        $out->chunk($this->json($this->done($req->model, '', 0, $req->dialect === 'ollama-generate', $this->promptTokens($req), null, 'length')) . "\n");
    }

    public function error(string $kind, ChatRequest $req): array
    {
        if ($kind === 'model') {
            return [404, ['Content-Type' => self::CT_JSON], $this->json([
                'error' => "model '{$req->model}' not found",
            ])];
        }

        return [400, ['Content-Type' => self::CT_JSON], $this->json(['error' => 'invalid request'])];
    }

    /** @return array<string,mixed> */
    private function progress(string $model, string $piece, bool $isGenerate): array
    {
        $obj = ['model' => $model, 'created_at' => $this->stats->ollamaCreatedAt()];
        if ($isGenerate) {
            $obj['response'] = $piece;
        } else {
            $obj['message'] = ['role' => 'assistant', 'content' => $piece];
        }
        $obj['done'] = false;

        return $obj;
    }

    /** @return array<string,mixed> */
    private function toolCallObject(ToolCall $call): array
    {
        return ['function' => ['name' => $call->name, 'arguments' => $call->arguments === [] ? new \stdClass() : $call->arguments]];
    }

    /**
     * The done object — full text for the buffered case, empty for the final streamed line, or one
     * carrying a tool call. Field order matches real ollama exactly (prompt_eval_count sits between
     * load_duration and prompt_eval_duration; /api/generate carries a context array right after
     * done_reason). prompt_eval_count is derived from the request, never a literal.
     *
     * @return array<string,mixed>
     */
    private function done(string $model, string $text, int $pieces, bool $isGenerate, int $promptTokens, ?ToolCall $call, string $doneReason): array
    {
        $d = $this->stats->durationsNs($pieces);

        $obj = ['model' => $model, 'created_at' => $this->stats->ollamaCreatedAt()];
        if ($isGenerate) {
            $obj['response'] = $text;
        } else {
            $message = ['role' => 'assistant', 'content' => $text];
            if ($call !== null) {
                $message['tool_calls'] = [$this->toolCallObject($call)];
            }
            $obj['message'] = $message;
        }
        $obj['done'] = true;
        $obj['done_reason'] = $doneReason;
        if ($isGenerate) {
            $obj['context'] = $this->stats->contextInts();
        }
        $obj['total_duration'] = $d['total_duration'];
        $obj['load_duration'] = $d['load_duration'];
        $obj['prompt_eval_count'] = $promptTokens;
        $obj['prompt_eval_duration'] = $d['prompt_eval_duration'];
        $obj['eval_count'] = $call !== null ? max(1, $this->usageEstimator->outputTokens(AssistantTurn::toolCall($call))) : $this->stats->evalCount($pieces);
        $obj['eval_duration'] = $d['eval_duration'];

        return $obj;
    }

    private function promptTokens(ChatRequest $req): int
    {
        $tokens = $req->inputTokens > 0 ? $req->inputTokens : $this->usageEstimator->tokens($req->userText);

        return max(1, $tokens);
    }

    /** options.num_predict is Ollama's output budget; absent/invalid => -1 (no budget). */
    private function numPredict(array $data): int
    {
        $options = $data['options'] ?? null;
        if (is_array($options) && isset($options['num_predict']) && is_int($options['num_predict']) && $options['num_predict'] >= 0) {
            return $options['num_predict'];
        }

        return -1;
    }

    /**
     * @param mixed $tools OpenAI-shaped function tool definitions
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
}

<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Dialect;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\Core\RequestContext;
use stdClass;

/**
 * OpenAI's /v1/chat/completions. Streaming is Server-Sent Events (`data: {json}\n\n` per chunk,
 * object chatcompletion.chunk) terminated by a literal `data: [DONE]`. Streaming is OFF by default,
 * and the same id/created/system_fingerprint repeats on every chunk of one response.
 */
final class OpenAiDialect extends AbstractDialect
{
    private const CT_JSON = 'application/json';
    private const CT_STREAM = 'text/event-stream';

    public function parse(RequestContext $ctx): ChatRequest
    {
        $data = $this->decodeBody($ctx->rawBody);
        $streamOptions = $data['stream_options'] ?? null;

        return new ChatRequest(
            'openai',
            (string) ($data['model'] ?? ''),
            $this->lastUserText(is_array($data['messages'] ?? null) ? $data['messages'] : []),
            array_key_exists('stream', $data) ? (bool) $data['stream'] : false,
            $this->hasHeaderValue($ctx->headers, 'Authorization'),
            is_array($streamOptions) && ($streamOptions['include_usage'] ?? null) === true
        );
    }

    public function needsAuth(): bool
    {
        return true;
    }

    public function contentTypeStream(): string
    {
        return self::CT_STREAM;
    }

    public function streamOk(string $text, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        $id = $this->stats->openAiId();
        $created = $this->stats->openAiCreated();
        $fp = $this->stats->systemFingerprint();
        $chunk = fn (mixed $delta, ?string $finish): string => $this->sse(
            $this->chunkObject($id, $created, $req->model, $fp, $delta, $finish)
        );

        $out->chunk($chunk(['role' => 'assistant', 'content' => ''], null));
        foreach ($this->chunks($text) as $piece) {
            $out->chunk($chunk(['content' => $piece], null));
        }
        $out->chunk($chunk(new stdClass(), 'stop'));

        if ($req->includeUsage) {
            $out->chunk($this->sse([
                'id' => $id,
                'object' => 'chat.completion.chunk',
                'created' => $created,
                'model' => $req->model,
                'system_fingerprint' => $fp,
                'choices' => [],
                'usage' => $this->usage($req->userText, $text),
            ]));
        }

        $out->chunk("data: [DONE]\n\n");
    }

    public function bufferedOk(string $text, ChatRequest $req): array
    {
        $body = [
            'id' => $this->stats->openAiId(),
            'object' => 'chat.completion',
            'created' => $this->stats->openAiCreated(),
            'model' => $req->model,
            'choices' => [[
                'index' => 0,
                'message' => ['role' => 'assistant', 'content' => $text, 'refusal' => null],
                'logprobs' => null,
                'finish_reason' => 'stop',
            ]],
            'usage' => $this->usage($req->userText, $text),
            'system_fingerprint' => $this->stats->systemFingerprint(),
        ];

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function error(string $kind, ChatRequest $req): array
    {
        [$status, $message, $type, $code] = $this->errorSpec($kind, $req);

        return [$status, ['Content-Type' => self::CT_JSON], $this->json([
            'error' => ['message' => $message, 'type' => $type, 'param' => null, 'code' => $code],
        ])];
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

    /** @param array<string,mixed> $obj */
    private function sse(array $obj): string
    {
        return 'data: ' . $this->json($obj) . "\n\n";
    }
}

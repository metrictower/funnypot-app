<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Dialect;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\Core\RequestContext;

/**
 * Anthropic's /v1/messages. Streaming is named-event SSE (`event: <name>\ndata: {json}\n\n`) in a
 * fixed order — message_start, content_block_start, ping, content_block_delta*, content_block_stop,
 * message_delta, message_stop — with NO `[DONE]` terminator. Streaming is OFF by default, and message
 * content may arrive as a plain string or as an array of typed blocks.
 */
final class AnthropicDialect extends AbstractDialect
{
    private const CT_JSON = 'application/json';
    private const CT_STREAM = 'text/event-stream';

    public function parse(RequestContext $ctx): ChatRequest
    {
        $data = $this->decodeBody($ctx->rawBody);
        $hasAuth = $this->hasHeaderValue($ctx->headers, 'x-api-key')
            || $this->hasHeaderValue($ctx->headers, 'Authorization');

        return new ChatRequest(
            'anthropic',
            (string) ($data['model'] ?? ''),
            $this->lastUserText(is_array($data['messages'] ?? null) ? $data['messages'] : []),
            array_key_exists('stream', $data) ? (bool) $data['stream'] : false,
            $hasAuth,
            false
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

        $id = $this->stats->anthropicId();
        $inputTokens = $this->estimateTokens($req->userText);
        $outputTokens = $this->estimateTokens($text);

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
        $out->chunk($this->event('message_delta', [
            'type' => 'message_delta',
            'delta' => ['stop_reason' => 'end_turn', 'stop_sequence' => null],
            'usage' => ['output_tokens' => $outputTokens],
        ]));
        $out->chunk($this->event('message_stop', ['type' => 'message_stop']));
    }

    public function bufferedOk(string $text, ChatRequest $req): array
    {
        $body = [
            'id' => $this->stats->anthropicId(),
            'type' => 'message',
            'role' => 'assistant',
            'model' => $req->model,
            'content' => [['type' => 'text', 'text' => $text]],
            'stop_reason' => 'end_turn',
            'stop_sequence' => null,
            'usage' => [
                'input_tokens' => $this->estimateTokens($req->userText),
                'output_tokens' => $this->estimateTokens($text),
                'cache_creation_input_tokens' => 0,
                'cache_read_input_tokens' => 0,
            ],
        ];

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function error(string $kind, ChatRequest $req): array
    {
        [$status, $type, $message] = $this->errorSpec($kind, $req);

        return [$status, ['Content-Type' => self::CT_JSON], $this->json([
            'type' => 'error',
            'error' => ['type' => $type, 'message' => $message],
        ])];
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

    /** @param array<string,mixed> $obj */
    private function event(string $name, array $obj): string
    {
        return "event: {$name}\ndata: " . $this->json($obj) . "\n\n";
    }
}

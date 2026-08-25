<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\ChatStats;
use Funnypot\App\AiApi\Dialect\OpenAiDialect;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * Byte-fidelity tests for the OpenAI SSE dialect: `data: {json}\n\n` chunks, empty stop delta, the
 * literal `data: [DONE]` terminator, and the optional usage chunk.
 */
final class OpenAiDialectTest extends TestCase
{
    private function dialect(): OpenAiDialect
    {
        return new OpenAiDialect(new ChatStats(1769904000, static fn (int $min, int $max): int => $min));
    }

    private function ctx(array $body, array $headers = []): RequestContext
    {
        return new RequestContext('POST', '/v1/chat/completions', '', $headers, json_encode($body));
    }

    /** @return array<int,array<string,mixed>> decoded SSE data objects (excluding the [DONE] line) */
    private function events(string $captured): array
    {
        $events = [];
        foreach (explode("\n\n", $captured) as $frame) {
            if ($frame === '' || $frame === 'data: [DONE]') {
                continue;
            }
            self::assertStringStartsWith('data: ', $frame);
            $events[] = json_decode(substr($frame, 6), true);
        }

        return $events;
    }

    public function test_parse_reads_auth_stream_and_include_usage(): void
    {
        $req = $this->dialect()->parse($this->ctx([
            'model' => 'gpt-4o',
            'messages' => [['role' => 'user', 'content' => 'hello there']],
            'stream' => true,
            'stream_options' => ['include_usage' => true],
        ], ['Authorization' => 'Bearer sk-test']));

        self::assertSame('openai', $req->dialect);
        self::assertSame('gpt-4o', $req->model);
        self::assertSame('hello there', $req->userText);
        self::assertTrue($req->stream);
        self::assertTrue($req->hasAuth);
        self::assertTrue($req->includeUsage);
    }

    public function test_parse_defaults_stream_false_no_auth_no_usage(): void
    {
        $req = $this->dialect()->parse($this->ctx([
            'model' => 'gpt-4o',
            'messages' => [['role' => 'user', 'content' => 'hi']],
        ]));

        self::assertFalse($req->stream);
        self::assertFalse($req->hasAuth);
        self::assertFalse($req->includeUsage);
    }

    public function test_needs_auth_and_stream_content_type(): void
    {
        self::assertTrue($this->dialect()->needsAuth());
        self::assertSame('text/event-stream', $this->dialect()->contentTypeStream());
    }

    public function test_buffered_shape(): void
    {
        $req = new ChatRequest('openai', 'gpt-4o', 'hi', false, true, false);
        [$status, $headers, $body] = $this->dialect()->bufferedOk('hello world', $req);

        self::assertSame(200, $status);
        self::assertSame('application/json', $headers['Content-Type']);

        $decoded = json_decode($body, true);
        self::assertMatchesRegularExpression('/^chatcmpl-[A-Za-z0-9]{24}$/', $decoded['id']);
        self::assertSame('chat.completion', $decoded['object']);
        self::assertSame('gpt-4o', $decoded['model']);
        self::assertSame('hello world', $decoded['choices'][0]['message']['content']);
        self::assertNull($decoded['choices'][0]['message']['refusal']);
        self::assertSame('stop', $decoded['choices'][0]['finish_reason']);
        self::assertArrayHasKey('prompt_tokens', $decoded['usage']);
        self::assertArrayHasKey('completion_tokens', $decoded['usage']);
        self::assertArrayHasKey('total_tokens', $decoded['usage']);
        self::assertMatchesRegularExpression('/^fp_[0-9a-f]{8}$/', $decoded['system_fingerprint']);
    }

    public function test_stream_sse_framing_and_done_terminator(): void
    {
        $emitter = new StreamEmitter(static function (): void {
        }, 0);
        $req = new ChatRequest('openai', 'gpt-4o', 'hi', true, true, false);

        $this->dialect()->streamOk('one two three', $req, $emitter);

        self::assertSame(200, $emitter->status());
        self::assertSame('text/event-stream', $emitter->headers()['Content-Type']);

        $captured = $emitter->captured();
        self::assertStringEndsWith("data: [DONE]\n\n", $captured);
        self::assertStringContainsString('"delta":{}', $captured, 'stop chunk delta must be an empty object');

        $events = $this->events($captured);

        // First chunk announces the assistant role.
        self::assertSame('assistant', $events[0]['choices'][0]['delta']['role']);
        self::assertSame('', $events[0]['choices'][0]['delta']['content']);
        self::assertNull($events[0]['choices'][0]['finish_reason']);

        // Content deltas concatenate to the full text; the stop chunk carries an empty delta.
        $content = '';
        $stopSeen = false;
        foreach ($events as $event) {
            $choice = $event['choices'][0] ?? null;
            if ($choice === null) {
                continue;
            }
            if (isset($choice['delta']['content'])) {
                $content .= $choice['delta']['content'];
            }
            if ($choice['finish_reason'] === 'stop') {
                self::assertSame([], $choice['delta']);
                $stopSeen = true;
            }
        }
        self::assertSame('one two three', $content);
        self::assertTrue($stopSeen);
    }

    public function test_stream_include_usage_adds_a_choiceless_usage_chunk_before_done(): void
    {
        $emitter = new StreamEmitter(static function (): void {
        }, 0);
        $req = new ChatRequest('openai', 'gpt-4o', 'the prompt', true, true, true);

        $this->dialect()->streamOk('hi there', $req, $emitter);

        $captured = $emitter->captured();
        // The usage frame must sit before the [DONE] terminator.
        $usagePos = strpos($captured, '"usage"');
        $donePos = strpos($captured, 'data: [DONE]');
        self::assertNotFalse($usagePos);
        self::assertLessThan($donePos, $usagePos);

        $usageChunk = null;
        foreach ($this->events($captured) as $event) {
            if (isset($event['usage'])) {
                $usageChunk = $event;
            }
        }
        self::assertNotNull($usageChunk);
        self::assertSame([], $usageChunk['choices']);
        self::assertArrayHasKey('prompt_tokens', $usageChunk['usage']);
        self::assertArrayHasKey('total_tokens', $usageChunk['usage']);
    }

    public function test_stream_without_include_usage_has_no_usage_chunk(): void
    {
        $emitter = new StreamEmitter(static function (): void {
        }, 0);
        $req = new ChatRequest('openai', 'gpt-4o', 'hi', true, true, false);

        $this->dialect()->streamOk('hello', $req, $emitter);

        self::assertStringNotContainsString('"usage"', $emitter->captured());
    }

    public function test_error_auth_is_401_invalid_api_key(): void
    {
        $req = new ChatRequest('openai', 'gpt-4o', '', false, false, false);
        [$status, $headers, $body] = $this->dialect()->error('auth', $req);

        self::assertSame(401, $status);
        self::assertSame('application/json', $headers['Content-Type']);
        $decoded = json_decode($body, true);
        self::assertSame('invalid_api_key', $decoded['error']['code']);
        self::assertSame('invalid_request_error', $decoded['error']['type']);
    }

    public function test_error_model_is_404_model_not_found(): void
    {
        $req = new ChatRequest('openai', 'gpt-9', '', false, false, false);
        [$status, , $body] = $this->dialect()->error('model', $req);

        self::assertSame(404, $status);
        $decoded = json_decode($body, true);
        self::assertSame('model_not_found', $decoded['error']['code']);
        self::assertStringContainsString('`gpt-9`', $decoded['error']['message']);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\ChatStats;
use Funnypot\App\AiApi\Dialect\AnthropicDialect;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * Byte-fidelity tests for the Anthropic named-event SSE dialect: the exact ordered event names,
 * text_delta pieces, and the absence of any `[DONE]` terminator.
 */
final class AnthropicDialectTest extends TestCase
{
    private function dialect(): AnthropicDialect
    {
        return new AnthropicDialect(new ChatStats(1769904000, static fn (int $min, int $max): int => $min));
    }

    private function ctx(array $body, array $headers = []): RequestContext
    {
        return new RequestContext('POST', '/v1/messages', '', $headers, json_encode($body));
    }

    /**
     * Parse the named-event SSE stream into ordered [name, dataObject] pairs.
     *
     * @return array<int,array{0:string,1:array<string,mixed>}>
     */
    private function events(string $captured): array
    {
        $events = [];
        foreach (explode("\n\n", $captured) as $frame) {
            if ($frame === '') {
                continue;
            }
            $lines = explode("\n", $frame);
            self::assertStringStartsWith('event: ', $lines[0]);
            self::assertStringStartsWith('data: ', $lines[1]);
            $events[] = [substr($lines[0], 7), json_decode(substr($lines[1], 6), true)];
        }

        return $events;
    }

    public function test_parse_string_content_with_x_api_key(): void
    {
        $req = $this->dialect()->parse($this->ctx([
            'model' => 'claude-3-5-sonnet-20241022',
            'messages' => [['role' => 'user', 'content' => 'hello there']],
            'stream' => true,
        ], ['x-api-key' => 'sk-ant-test']));

        self::assertSame('anthropic', $req->dialect);
        self::assertSame('claude-3-5-sonnet-20241022', $req->model);
        self::assertSame('hello there', $req->userText);
        self::assertTrue($req->stream);
        self::assertTrue($req->hasAuth);
    }

    public function test_parse_array_content_blocks(): void
    {
        $req = $this->dialect()->parse($this->ctx([
            'model' => 'claude-3-5-sonnet-20241022',
            'messages' => [[
                'role' => 'user',
                'content' => [
                    ['type' => 'text', 'text' => 'block one'],
                    ['type' => 'text', 'text' => 'block two'],
                ],
            ]],
        ], ['Authorization' => 'Bearer sk-ant']));

        self::assertSame("block one\nblock two", $req->userText);
        self::assertTrue($req->hasAuth);
        self::assertFalse($req->stream, 'stream defaults to false');
    }

    public function test_parse_defaults_no_auth(): void
    {
        $req = $this->dialect()->parse($this->ctx([
            'model' => 'claude-3-5-sonnet-20241022',
            'messages' => [['role' => 'user', 'content' => 'hi']],
        ]));

        self::assertFalse($req->stream);
        self::assertFalse($req->hasAuth);
    }

    public function test_needs_auth_and_stream_content_type(): void
    {
        self::assertTrue($this->dialect()->needsAuth());
        self::assertSame('text/event-stream', $this->dialect()->contentTypeStream());
    }

    public function test_buffered_shape(): void
    {
        $req = new ChatRequest('anthropic', 'claude-3-5-sonnet-20241022', 'hi', false, true, false);
        [$status, $headers, $body] = $this->dialect()->bufferedOk('hello world', $req);

        self::assertSame(200, $status);
        self::assertSame('application/json', $headers['Content-Type']);

        $decoded = json_decode($body, true);
        self::assertMatchesRegularExpression('/^msg_[A-Za-z0-9]{24}$/', $decoded['id']);
        self::assertSame('message', $decoded['type']);
        self::assertSame('assistant', $decoded['role']);
        self::assertSame('claude-3-5-sonnet-20241022', $decoded['model']);
        self::assertSame('text', $decoded['content'][0]['type']);
        self::assertSame('hello world', $decoded['content'][0]['text']);
        self::assertSame('end_turn', $decoded['stop_reason']);
        self::assertNull($decoded['stop_sequence']);
        self::assertSame(0, $decoded['usage']['cache_creation_input_tokens']);
        self::assertSame(0, $decoded['usage']['cache_read_input_tokens']);
        self::assertArrayHasKey('input_tokens', $decoded['usage']);
        self::assertArrayHasKey('output_tokens', $decoded['usage']);
    }

    public function test_stream_named_events_in_exact_order_no_done(): void
    {
        $emitter = new StreamEmitter(static function (): void {
        }, 0);
        $req = new ChatRequest('anthropic', 'claude-3-5-sonnet-20241022', 'hi', true, true, false);

        $this->dialect()->streamOk('one two three', $req, $emitter);

        self::assertSame(200, $emitter->status());
        self::assertSame('text/event-stream', $emitter->headers()['Content-Type']);

        $captured = $emitter->captured();
        self::assertStringNotContainsString('[DONE]', $captured, 'Anthropic has no DONE sentinel');

        $events = $this->events($captured);
        $names = array_column($events, 0);
        self::assertSame([
            'message_start',
            'content_block_start',
            'ping',
            'content_block_delta',
            'content_block_delta',
            'content_block_delta',
            'content_block_stop',
            'message_delta',
            'message_stop',
        ], $names);

        // Deltas are text_delta and concatenate to the full text.
        $text = '';
        foreach ($events as [$name, $data]) {
            if ($name === 'content_block_delta') {
                self::assertSame('text_delta', $data['delta']['type']);
                $text .= $data['delta']['text'];
            }
        }
        self::assertSame('one two three', $text);

        // message_start advertises output_tokens:1; message_delta reports end_turn + a real count.
        self::assertSame(1, $events[0][1]['message']['usage']['output_tokens']);
        $messageDelta = $events[7][1];
        self::assertSame('end_turn', $messageDelta['delta']['stop_reason']);
        self::assertGreaterThanOrEqual(1, $messageDelta['usage']['output_tokens']);
        self::assertSame('message_stop', $events[8][0]);
    }

    public function test_error_auth_is_401_authentication_error(): void
    {
        $req = new ChatRequest('anthropic', 'claude-3-5-sonnet-20241022', '', false, false, false);
        [$status, $headers, $body] = $this->dialect()->error('auth', $req);

        self::assertSame(401, $status);
        self::assertSame('application/json', $headers['Content-Type']);
        $decoded = json_decode($body, true);
        self::assertSame('error', $decoded['type']);
        self::assertSame('authentication_error', $decoded['error']['type']);
    }

    public function test_error_model_is_404_not_found_error(): void
    {
        $req = new ChatRequest('anthropic', 'claude-ghost', '', false, false, false);
        [$status, , $body] = $this->dialect()->error('model', $req);

        self::assertSame(404, $status);
        $decoded = json_decode($body, true);
        self::assertSame('not_found_error', $decoded['error']['type']);
        self::assertStringContainsString('claude-ghost', $decoded['error']['message']);
    }
}

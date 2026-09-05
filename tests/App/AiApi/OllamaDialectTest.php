<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\ChatStats;
use Funnypot\App\AiApi\Dialect\OllamaDialect;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * Byte-fidelity tests for the ollama NDJSON dialect. A deterministic ChatStats (fixed now, rand→min)
 * keeps ids/timestamps/counters stable so the wire bytes can be asserted exactly.
 */
final class OllamaDialectTest extends TestCase
{
    private function dialect(): OllamaDialect
    {
        return new OllamaDialect(new ChatStats(1769904000, static fn (int $min, int $max): int => $min));
    }

    private function ctx(string $path, array $body, array $headers = []): RequestContext
    {
        return new RequestContext('POST', $path, '', $headers, json_encode($body));
    }

    public function test_parse_chat_takes_last_user_message_and_defaults_stream_true(): void
    {
        $req = $this->dialect()->parse($this->ctx('/api/chat', [
            'model' => 'llama3.2',
            'messages' => [
                ['role' => 'user', 'content' => 'first'],
                ['role' => 'assistant', 'content' => 'ok'],
                ['role' => 'user', 'content' => 'the real question'],
            ],
        ]));

        self::assertSame('ollama-chat', $req->dialect);
        self::assertSame('llama3.2', $req->model);
        self::assertSame('the real question', $req->userText);
        self::assertTrue($req->stream);
        self::assertFalse($req->hasAuth);
        self::assertFalse($req->includeUsage);
    }

    public function test_parse_generate_uses_prompt(): void
    {
        $req = $this->dialect()->parse($this->ctx('/api/generate', [
            'model' => 'llama3.2',
            'prompt' => 'why is the sky blue',
            'stream' => false,
        ]));

        self::assertSame('ollama-generate', $req->dialect);
        self::assertSame('why is the sky blue', $req->userText);
        self::assertFalse($req->stream);
    }

    public function test_needs_auth_is_false(): void
    {
        self::assertFalse($this->dialect()->needsAuth());
        self::assertSame('application/x-ndjson', $this->dialect()->contentTypeStream());
    }

    public function test_buffered_chat_is_the_done_object_with_full_text(): void
    {
        $req = new ChatRequest('ollama-chat', 'llama3.2', 'hello world', false, false, false);
        [$status, $headers, $body] = $this->dialect()->bufferedOk('hello world', $req);

        self::assertSame(200, $status);
        self::assertSame('application/json; charset=utf-8', $headers['Content-Type']);

        $decoded = json_decode($body, true);
        self::assertSame('llama3.2', $decoded['model']);
        self::assertTrue($decoded['done']);
        self::assertSame('stop', $decoded['done_reason']);
        self::assertSame('assistant', $decoded['message']['role']);
        self::assertSame('hello world', $decoded['message']['content']);
        // prompt_eval_count is derived from the prompt (no longer the hard-coded literal that was a tell).
        self::assertSame((int) ceil(strlen('hello world') / 4), $decoded['prompt_eval_count']);
        self::assertGreaterThan(0, $decoded['total_duration']);
        self::assertArrayNotHasKey('context', $decoded);
    }

    public function test_buffered_generate_uses_response_and_context(): void
    {
        $req = new ChatRequest('ollama-generate', 'llama3.2', 'hi', false, false, false);
        [, , $body] = $this->dialect()->bufferedOk('hello world', $req);

        $decoded = json_decode($body, true);
        self::assertSame('hello world', $decoded['response']);
        self::assertTrue($decoded['done']);
        self::assertIsArray($decoded['context']);
        self::assertNotEmpty($decoded['context']);
        self::assertArrayNotHasKey('message', $decoded);
    }

    public function test_stream_chat_is_ndjson_with_a_done_final_line(): void
    {
        $emitter = new StreamEmitter(static function (): void {
        }, 0);
        $req = new ChatRequest('ollama-chat', 'llama3.2', 'hello world', true, false, false);

        $this->dialect()->streamOk('one two three', $req, $emitter);

        self::assertSame(200, $emitter->status());
        self::assertSame('application/x-ndjson', $emitter->headers()['Content-Type']);

        $lines = explode("\n", rtrim($emitter->captured(), "\n"));
        self::assertCount(4, $lines); // 3 word pieces + 1 done line

        $content = '';
        foreach ($lines as $i => $line) {
            self::assertStringStartsNotWith('data:', $line, 'NDJSON must not carry an SSE prefix');
            $obj = json_decode($line, true);
            self::assertIsArray($obj, 'each line is valid JSON');

            if ($i < 3) {
                self::assertFalse($obj['done']);
                self::assertNotSame('', $obj['message']['content']);
                $content .= $obj['message']['content'];
            } else {
                self::assertTrue($obj['done']);
                self::assertSame('stop', $obj['done_reason']);
                self::assertSame('', $obj['message']['content']);
                self::assertSame((int) ceil(strlen('hello world') / 4), $obj['prompt_eval_count']);
                self::assertGreaterThan(0, $obj['eval_duration']);
            }
        }
        self::assertSame('one two three', $content);
    }

    public function test_stream_generate_final_line_carries_context(): void
    {
        $emitter = new StreamEmitter(static function (): void {
        }, 0);
        $req = new ChatRequest('ollama-generate', 'llama3.2', 'hi', true, false, false);

        $this->dialect()->streamOk('alpha beta', $req, $emitter);

        $lines = explode("\n", rtrim($emitter->captured(), "\n"));
        $response = '';
        foreach (array_slice($lines, 0, -1) as $line) {
            $obj = json_decode($line, true);
            self::assertFalse($obj['done']);
            $response .= $obj['response'];
        }
        self::assertSame('alpha beta', $response);

        $final = json_decode($lines[count($lines) - 1], true);
        self::assertTrue($final['done']);
        self::assertSame('', $final['response']);
        self::assertIsArray($final['context']);
        self::assertNotEmpty($final['context']);
    }

    public function test_error_model_is_404_with_ollama_message(): void
    {
        $req = new ChatRequest('ollama-chat', 'ghost-model', '', false, false, false);
        [$status, $headers, $body] = $this->dialect()->error('model', $req);

        self::assertSame(404, $status);
        self::assertSame('application/json; charset=utf-8', $headers['Content-Type']);
        self::assertSame("model 'ghost-model' not found", json_decode($body, true)['error']);
    }

    public function test_error_bad_is_400(): void
    {
        $req = new ChatRequest('ollama-chat', 'llama3.2', '', false, false, false);
        [$status, , $body] = $this->dialect()->error('bad', $req);

        self::assertSame(400, $status);
        self::assertArrayHasKey('error', json_decode($body, true));
    }
}

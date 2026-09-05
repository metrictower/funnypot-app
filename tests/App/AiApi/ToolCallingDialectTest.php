<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\ChatStats;
use Funnypot\App\AiApi\Dialect\AnthropicDialect;
use Funnypot\App\AiApi\Dialect\OllamaDialect;
use Funnypot\App\AiApi\Dialect\OpenAiDialect;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\AiApi\Value\ToolCall;
use PHPUnit\Framework\TestCase;

/**
 * Provider-exact framing of an inert tool call and a length stop, buffered and streamed: correct stop
 * reasons, argument fragments that reassemble to the one canonical JSON, stable identity fields, right
 * terminal markers, and internally consistent (non-hard-coded) usage.
 */
final class ToolCallingDialectTest extends TestCase
{
    private function stats(): ChatStats
    {
        // Fixed clock + deterministic "randomness" so ids/timestamps are stable across chunks.
        $seq = 0;

        return new ChatStats(1_700_000_000, static function (int $min, int $max) use (&$seq): int {
            $seq++;

            return $min + ($seq % (($max - $min) ?: 1));
        });
    }

    private function call(): ToolCall
    {
        return new ToolCall('call_ABC', 'read_file', ['path' => 'README.md'], '{"path":"README.md"}');
    }

    private function emitter(): StreamEmitter
    {
        return new StreamEmitter(static fn (string $b): ?string => null, 0);
    }

    // --- OpenAI ---------------------------------------------------------------------------------------

    public function test_openai_buffered_tool_call(): void
    {
        $req = new ChatRequest('openai', 'gpt-oss-120b', 'go', false, false, false);
        $req->inputTokens = 20;
        [$status, $headers, $body] = (new OpenAiDialect($this->stats()))->bufferedTool($this->call(), $req);

        self::assertSame(200, $status);
        self::assertSame('application/json', $headers['Content-Type']);
        $d = json_decode($body, true);
        self::assertNull($d['choices'][0]['message']['content']);
        self::assertSame('tool_calls', $d['choices'][0]['finish_reason']);
        $tc = $d['choices'][0]['message']['tool_calls'][0];
        self::assertSame('function', $tc['type']);
        self::assertSame('read_file', $tc['function']['name']);
        self::assertSame('{"path":"README.md"}', $tc['function']['arguments']);
        self::assertSame($d['usage']['prompt_tokens'] + $d['usage']['completion_tokens'], $d['usage']['total_tokens']);
    }

    public function test_openai_streamed_tool_call_reassembles_and_terminates(): void
    {
        $req = new ChatRequest('openai', 'gpt-oss-120b', 'go', true, false, false);
        $out = $this->emitter();
        (new OpenAiDialect($this->stats()))->streamTool($this->call(), $req, $out);
        $bytes = $out->captured();

        self::assertStringEndsWith("data: [DONE]\n\n", $bytes);
        $chunks = $this->sseChunks($bytes);

        $ids = [];
        $args = '';
        $finish = null;
        $nameSeen = null;
        foreach ($chunks as $c) {
            $ids[] = $c['id'];
            $choice = $c['choices'][0] ?? null;
            if ($choice === null) {
                continue;
            }
            $delta = $choice['delta'];
            if (isset($delta['tool_calls'][0]['function']['name'])) {
                $nameSeen = $delta['tool_calls'][0]['function']['name'];
            }
            if (isset($delta['tool_calls'][0]['function']['arguments'])) {
                $args .= $delta['tool_calls'][0]['function']['arguments'];
            }
            if ($choice['finish_reason'] !== null) {
                $finish = $choice['finish_reason'];
            }
        }

        self::assertSame('read_file', $nameSeen);
        self::assertSame('{"path":"README.md"}', $args, 'argument fragments must reassemble to the canonical JSON');
        self::assertSame('tool_calls', $finish);
        self::assertCount(1, array_unique($ids), 'id is stable across all chunks');
    }

    public function test_openai_include_usage_puts_null_on_earlier_chunks_and_usage_last(): void
    {
        $req = new ChatRequest('openai', 'gpt-oss-120b', 'go', true, false, true); // includeUsage=true
        $req->inputTokens = 15;
        $out = $this->emitter();
        (new OpenAiDialect($this->stats()))->streamTool($this->call(), $req, $out);
        $chunks = $this->sseChunks($out->captured());

        $usageChunk = null;
        foreach ($chunks as $i => $c) {
            if (($c['choices'] ?? []) === [] && isset($c['usage'])) {
                $usageChunk = $c;
                continue;
            }
            self::assertArrayHasKey('usage', $c, 'every non-final chunk carries a usage member when include_usage');
            self::assertNull($c['usage'], 'non-final usage member must be null');
        }
        self::assertNotNull($usageChunk);
        self::assertSame($usageChunk['usage']['prompt_tokens'] + $usageChunk['usage']['completion_tokens'], $usageChunk['usage']['total_tokens']);
    }

    public function test_openai_length_stop(): void
    {
        $req = new ChatRequest('openai', 'gpt-oss-120b', 'go', false, false, false);
        [, , $body] = (new OpenAiDialect($this->stats()))->bufferedLength($req);
        $d = json_decode($body, true);
        self::assertSame('length', $d['choices'][0]['finish_reason']);
        self::assertArrayNotHasKey('tool_calls', $d['choices'][0]['message']);
    }

    // --- Anthropic ------------------------------------------------------------------------------------

    public function test_anthropic_buffered_tool_use(): void
    {
        $req = new ChatRequest('anthropic', 'kimi-k3', 'go', false, false, false);
        $req->inputTokens = 20;
        [, , $body] = (new AnthropicDialect($this->stats()))->bufferedTool($this->call(), $req);
        $d = json_decode($body, true);
        self::assertSame('tool_use', $d['stop_reason']);
        self::assertSame('tool_use', $d['content'][0]['type']);
        self::assertSame('read_file', $d['content'][0]['name']);
        self::assertSame(['path' => 'README.md'], $d['content'][0]['input']);
    }

    public function test_anthropic_streamed_tool_use_event_order_and_reassembly(): void
    {
        $req = new ChatRequest('anthropic', 'kimi-k3', 'go', true, false, false);
        $req->inputTokens = 20;
        $out = $this->emitter();
        (new AnthropicDialect($this->stats()))->streamTool($this->call(), $req, $out);
        $bytes = $out->captured();

        self::assertStringNotContainsString('[DONE]', $bytes);
        $order = ['message_start', 'content_block_start', 'ping', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop'];
        $prev = -1;
        foreach ($order as $name) {
            $pos = strpos($bytes, 'event: ' . $name);
            self::assertNotFalse($pos, "missing event {$name}");
            self::assertGreaterThan($prev, $pos, "event {$name} out of order");
            $prev = $pos;
        }
        // input_json_delta fragments reassemble to the canonical JSON (decode each event's data).
        $reassembled = '';
        foreach (explode("\n\n", $bytes) as $frame) {
            if (!preg_match('/data: (\{.*\})/s', $frame, $mm)) {
                continue;
            }
            $obj = json_decode($mm[1], true);
            if (is_array($obj) && ($obj['type'] ?? '') === 'content_block_delta' && ($obj['delta']['type'] ?? '') === 'input_json_delta') {
                $reassembled .= (string) $obj['delta']['partial_json'];
            }
        }
        self::assertSame('{"path":"README.md"}', $reassembled);
        // start block owns id+name.
        self::assertStringContainsString('"content_block":{"type":"tool_use","id":"call_ABC","name":"read_file"', $bytes);
    }

    public function test_anthropic_zero_token_cache_warm(): void
    {
        $req = new ChatRequest('anthropic', 'kimi-k3', 'go', false, false, false);
        $req->inputTokens = 12;
        [, , $body] = (new AnthropicDialect($this->stats()))->bufferedLength($req);
        $d = json_decode($body, true);
        self::assertSame([], $d['content']);
        self::assertSame('max_tokens', $d['stop_reason']);
        self::assertSame(0, $d['usage']['output_tokens']);
    }

    public function test_anthropic_length_stream_has_no_content_block_events(): void
    {
        $req = new ChatRequest('anthropic', 'kimi-k3', 'go', true, false, false);
        $out = $this->emitter();
        (new AnthropicDialect($this->stats()))->streamLength($req, $out);
        $bytes = $out->captured();
        self::assertStringContainsString('event: message_start', $bytes);
        self::assertStringContainsString('"stop_reason":"max_tokens"', $bytes);
        self::assertStringContainsString('event: message_stop', $bytes);
        self::assertStringNotContainsString('content_block_start', $bytes);
    }

    // --- Ollama chat ----------------------------------------------------------------------------------

    public function test_ollama_buffered_tool_call_has_object_arguments(): void
    {
        $req = new ChatRequest('ollama-chat', 'qwen3:235b', 'go', false, false, false);
        $req->inputTokens = 10;
        [, , $body] = (new OllamaDialect($this->stats()))->bufferedTool($this->call(), $req);
        $d = json_decode($body, true);
        self::assertTrue($d['done']);
        $tc = $d['message']['tool_calls'][0];
        self::assertSame('read_file', $tc['function']['name']);
        self::assertSame(['path' => 'README.md'], $tc['function']['arguments'], 'ollama arguments are an OBJECT, not a string');
    }

    public function test_ollama_stream_emits_exactly_one_call_then_a_call_free_done(): void
    {
        $req = new ChatRequest('ollama-chat', 'qwen3:235b', 'go', true, false, false);
        $req->inputTokens = 10;
        $out = $this->emitter();
        (new OllamaDialect($this->stats()))->streamTool($this->call(), $req, $out);
        $lines = array_values(array_filter(explode("\n", $out->captured()), static fn ($l) => trim($l) !== ''));
        self::assertCount(2, $lines);

        $callCount = 0;
        $doneSeen = false;
        foreach ($lines as $line) {
            self::assertStringStartsNotWith('data:', $line, 'NDJSON has no SSE prefix');
            $obj = json_decode($line, true);
            self::assertIsArray($obj);
            if (isset($obj['message']['tool_calls'])) {
                $callCount += count($obj['message']['tool_calls']);
            }
            if ($obj['done'] === true) {
                $doneSeen = true;
                self::assertArrayNotHasKey('tool_calls', $obj['message'], 'the final done record carries no call');
            }
        }
        self::assertSame(1, $callCount, 'an accumulating client sees exactly one call');
        self::assertTrue($doneSeen);
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function sseChunks(string $bytes): array
    {
        $out = [];
        foreach (explode("\n\n", $bytes) as $frame) {
            $frame = trim($frame);
            if ($frame === '' || $frame === 'data: [DONE]') {
                continue;
            }
            $json = preg_replace('/^data:\s*/', '', $frame);
            $decoded = json_decode((string) $json, true);
            if (is_array($decoded)) {
                $out[] = $decoded;
            }
        }

        return $out;
    }
}

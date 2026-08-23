<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\Ai\ModelCatalog;
use Funnypot\App\AiApi\AiChatHandler;
use Funnypot\App\AiApi\AiChatPromptBuilder;
use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\Dialect\AnthropicDialect;
use Funnypot\App\AiApi\Dialect\OllamaDialect;
use Funnypot\App\AiApi\Dialect\OpenAiDialect;
use Funnypot\App\AiApi\NonsenseFallback;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\RequestContext;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * The chat handler end to end with an injected transport (no network), temp sqlite stores, and sink-
 * backed emission (no real headers). Resolve-then-frame: a good generation is served, every fault
 * degrades to a dialect-shaped troll fallback at 200 — never a 500, never a half-stream.
 */
final class AiChatHandlerTest extends TestCase
{
    private const IP = '9.9.9.9';           // public/routable, so AbuseIPDB queues it
    private const OLLAMA_MODEL = 'qwen3:235b';
    private const OPENAI_MODEL = 'gpt-oss-120b';
    private const ANTHROPIC_MODEL = 'qwen3-235b';

    /** @var string[] */
    private array $tmp = [];
    private ?SqliteHitStore $store = null;
    private ?AbuseIpdb $abuse = null;
    private stdClass $cap;
    private StreamEmitter $emitter;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->cap = new stdClass();
        $this->cap->status = 0;
        $this->cap->headers = [];
        $this->cap->body = '';
        $this->emitter = new StreamEmitter(static fn (string $b): ?string => null, 0);
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function dbPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fp_{$n}_" . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function make(callable $transport): AiChatHandler
    {
        $this->store = new SqliteHitStore($this->dbPath('hits'));
        $this->abuse = new AbuseIpdb('testkey', $this->dbPath('intel'), ['10.0.0.1']);
        $cap = $this->cap;
        $emitter = $this->emitter;

        return new AiChatHandler(
            new LlmClient('http://sidecar/completion', 1500, 320, null, $transport),
            new AiChatPromptBuilder(),
            new LlmOutputSanitizer(),
            new NonsenseFallback(),
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $this->store),
            new LlmFakeCache($this->dbPath('cache')),
            $this->store,
            ModelCatalog::fromPackage(),
            $this->abuse,
            4,
            0,
            static function (int $s, array $h, string $b) use ($cap): void {
                $cap->status = $s;
                $cap->headers = $h;
                $cap->body = $b;
            },
            static fn (): StreamEmitter => $emitter,
        );
    }

    /** @param array<string,mixed> $body */
    private function ctx(string $path, array $body, array $headers = []): RequestContext
    {
        return new RequestContext('POST', $path, '', $headers, (string) json_encode($body));
    }

    public function test_happy_buffered_serves_generated_text_logs_and_reports(): void
    {
        $calls = 0;
        $handler = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])];
        });

        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => false,
        ]), self::IP);

        self::assertSame(1, $calls);
        self::assertSame(200, $this->cap->status);
        self::assertStringContainsString('obviously wrong', $this->cap->body);
        self::assertStringContainsString('"done":true', $this->cap->body);
        self::assertStringContainsString(self::OLLAMA_MODEL, $this->cap->body);   // model echoed verbatim

        // logged as an ai_api_recon hit
        $rows = $this->store->delta(0)['rows'];
        self::assertNotEmpty($rows);
        self::assertSame('/api/chat', $rows[count($rows) - 1]['path']);
        self::assertSame('POST', $rows[count($rows) - 1]['method']);

        // reported once (self-guard passes: 9.9.9.9 is public and not a self IP)
        self::assertSame(1, $this->abuse->queueCount());
    }

    public function test_no_x_powered_by_header_on_the_response(): void
    {
        $handler = $this->make(fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])]);
        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'hi']],
            'stream' => false,
        ]), self::IP);

        self::assertArrayNotHasKey('X-Powered-By', $this->cap->headers);
    }

    public function test_sidecar_fault_degrades_to_fallback_never_500(): void
    {
        $handler = $this->make(fn (): array => ['status' => 500, 'body' => '']);

        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => false,
        ]), self::IP);

        self::assertSame(200, $this->cap->status);   // degraded to 200, not a 500 tell
        $expected = (new NonsenseFallback())->text(
            new ChatRequest('ollama-chat', self::OLLAMA_MODEL, 'what is the capital of France', false, false, false)
        );
        self::assertStringContainsString($expected, $this->cap->body);
        self::assertSame(1, $this->abuse->queueCount());   // still reported
    }

    public function test_gate_decline_skips_the_llm(): void
    {
        $calls = 0;
        $handler = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])];
        });
        $this->store->flagBulkScan(self::IP, 24);   // pin the IP as a bulk scanner

        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => false,
        ]), self::IP);

        self::assertSame(0, $calls, 'a gated IP must not reach the sidecar');
        self::assertSame(200, $this->cap->status);
        self::assertStringContainsString('"done":true', $this->cap->body);   // fallback still framed
    }

    public function test_openai_missing_auth_gets_401_invalid_api_key(): void
    {
        $handler = $this->make(fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])]);

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => self::OPENAI_MODEL,
            'messages' => [['role' => 'user', 'content' => 'hi']],
        ]), self::IP);

        self::assertSame(401, $this->cap->status);
        self::assertStringContainsString('invalid_api_key', $this->cap->body);
    }

    public function test_openai_unknown_model_gets_404_model_not_found(): void
    {
        $handler = $this->make(fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])]);

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'no-such-model-xyz',
            'messages' => [['role' => 'user', 'content' => 'hi']],
        ], ['Authorization' => 'Bearer sk-test']), self::IP);

        self::assertSame(404, $this->cap->status);
        self::assertStringContainsString('model_not_found', $this->cap->body);
    }

    public function test_anthropic_stream_emits_ordered_events_and_no_done_sentinel(): void
    {
        $handler = $this->make(fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'this is a confidently wrong streamed answer'])]);

        $handler->serve(new AnthropicDialect(), $this->ctx('/v1/messages', [
            'model' => self::ANTHROPIC_MODEL,
            'messages' => [['role' => 'user', 'content' => 'hi']],
            'stream' => true,
        ], ['x-api-key' => 'sk-ant-test']), self::IP);

        $bytes = $this->emitter->captured();
        self::assertStringContainsString('event: message_start', $bytes);
        self::assertStringContainsString('event: content_block_delta', $bytes);
        self::assertStringContainsString('event: message_stop', $bytes);
        self::assertStringNotContainsString('[DONE]', $bytes);
        // ordering: start < content_block_stop < message_stop
        self::assertLessThan(strpos($bytes, 'content_block_stop'), strpos($bytes, 'message_start'));
        self::assertLessThan(strpos($bytes, 'event: message_stop'), strpos($bytes, 'content_block_stop'));
        self::assertSame(self::ANTHROPIC_MODEL, $this->requestedModelIn($bytes));
    }

    /** The buffered emit path must not have run for a stream. */
    public function test_stream_does_not_use_the_buffered_sink(): void
    {
        $handler = $this->make(fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'streamed and wrong'])]);
        $handler->serve(new AnthropicDialect(), $this->ctx('/v1/messages', [
            'model' => self::ANTHROPIC_MODEL,
            'messages' => [['role' => 'user', 'content' => 'hi']],
            'stream' => true,
        ], ['x-api-key' => 'sk-ant-test']), self::IP);

        self::assertSame(0, $this->cap->status);   // buffered sink never fired
        self::assertNotSame('', $this->emitter->captured());
    }

    private function requestedModelIn(string $bytes): string
    {
        return strpos($bytes, self::ANTHROPIC_MODEL) !== false ? self::ANTHROPIC_MODEL : '';
    }
}

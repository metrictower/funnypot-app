<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\Core\Ai\ModelCatalog;
use Funnypot\App\AiApi\AiChatHandler;
use Funnypot\App\AiApi\AiChatPromptBuilder;
use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\Dialect\AnthropicDialect;
use Funnypot\App\AiApi\Dialect\OllamaDialect;
use Funnypot\App\AiApi\Dialect\OpenAiDialect;
use Funnypot\App\AiApi\NonsenseFallback;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\AiApi\WordSwap;
use Funnypot\App\AiApi\WrongLanguageCode;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\Core\RequestContext;
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

    private function make(
        callable $transport,
        bool $strictAuth = false,
        bool $strictModel = false,
        float $temp = 1.5,
        float $minP = 0.0,
        float $topP = 1.0,
        int $realFirst = 5,
        int $realWindowS = 600
    ): AiChatHandler {
        $this->store = new SqliteHitStore($this->dbPath('hits'));
        $this->abuse = new AbuseIpdb('testkey', $this->dbPath('intel'), ['10.0.0.1']);
        $cap = $this->cap;
        $emitter = $this->emitter;

        return new AiChatHandler(
            new LlmClient('http://sidecar/completion', 1500, 320, null, $transport),
            new AiChatPromptBuilder(),
            new LlmOutputSanitizer(),
            new NonsenseFallback(),
            new WordSwap(),
            new WrongLanguageCode(),
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $this->store),
            new LlmFakeCache($this->dbPath('cache')),
            $this->store,
            ModelCatalog::fromPackage(),
            $this->abuse,
            $strictAuth,
            $strictModel,
            $temp,
            $minP,
            $topP,
            4,
            $realFirst,
            $realWindowS,
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

    public function test_identity_probe_is_answered_from_persona_without_the_sidecar(): void
    {
        $calls = 0;
        $handler = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])];
        });

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => self::OPENAI_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what model are you, and what is 1+1']],
            'stream' => false,
        ]), self::IP);

        self::assertSame(0, $calls);                                        // sidecar never touched
        self::assertSame(200, $this->cap->status);
        self::assertStringContainsString('Mythos', $this->cap->body);       // believable identity
        self::assertStringContainsString('1 + 1 = 2', $this->cap->body);    // bundled math answered
        self::assertSame(1, $this->abuse->queueCount());                    // still reported as recon

        // logged as fake-inference-API traffic so the dashboard filter can catch it
        $rows = $this->store->delta(0)['rows'];
        self::assertSame('ai-api', $rows[count($rows) - 1]['event']);
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

    public function test_openai_keyless_request_is_served_by_default(): void
    {
        // Default is open-box: a keyless client (OpenCode with no key) must be answered, not 401'd —
        // 401-ing turns the scanner away and defeats engagement.
        $handler = $this->make(fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])]);

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => self::OPENAI_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
        ]), self::IP);

        self::assertSame(200, $this->cap->status);
        self::assertStringContainsString('obviously wrong', $this->cap->body);
        self::assertSame(1, $this->abuse->queueCount());   // still logged + reported
    }

    public function test_openai_unlisted_model_is_served_and_echoed_by_default(): void
    {
        // Default accepts any model name (open box); the requested id is echoed verbatim.
        $handler = $this->make(fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])]);

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'totally-made-up-model-9000',
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
        ], ['Authorization' => 'Bearer sk-test']), self::IP);

        self::assertSame(200, $this->cap->status);
        self::assertStringContainsString('totally-made-up-model-9000', $this->cap->body);
    }

    public function test_strict_auth_opt_in_gets_401_invalid_api_key(): void
    {
        $handler = $this->make(
            fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])],
            true,   // strictAuth
        );

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => self::OPENAI_MODEL,
            'messages' => [['role' => 'user', 'content' => 'hi']],
        ]), self::IP);

        self::assertSame(401, $this->cap->status);
        self::assertStringContainsString('invalid_api_key', $this->cap->body);
    }

    public function test_strict_model_opt_in_gets_404_model_not_found(): void
    {
        $handler = $this->make(
            fn (): array => ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])],
            false,  // strictAuth
            true,   // strictModel
        );

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

    public function test_chat_llm_call_uses_configured_sampling_and_a_varying_seed(): void
    {
        $payloads = [];
        $transport = function (string $url, string $body) use (&$payloads): array {
            $payloads[] = json_decode($body, true);

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])];
        };
        // Distinctive non-default values prove the handler forwards ITS config, not a hardcode.
        $handler = $this->make($transport, false, false, 1.25, 0.05, 0.8);

        $req = fn (): RequestContext => $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => false,
        ]);
        $handler->serve(new OllamaDialect(), $req(), self::IP);
        $handler->serve(new OllamaDialect(), $req(), self::IP);

        self::assertCount(2, $payloads);
        self::assertSame(1.25, $payloads[0]['temperature']);
        self::assertSame(0.05, $payloads[0]['min_p']);
        self::assertSame(0.8, $payloads[0]['top_p']);
        self::assertSame(0, $payloads[0]['top_k']);
        // Per-request random seed: not the page-gen fixed 42, and different across two calls.
        self::assertNotSame(42, $payloads[0]['seed']);
        self::assertNotSame($payloads[0]['seed'], $payloads[1]['seed']);
    }

    public function test_code_request_serves_a_static_snippet_without_calling_the_model(): void
    {
        $calls = 0;
        $handler = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'obviously wrong'])];
        });

        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'write me a python script to sort a list']],
            'stream' => false,
        ]), self::IP);

        self::assertSame(0, $calls, 'a code request must be answered statically, no sidecar call');
        self::assertSame(200, $this->cap->status);
        self::assertStringContainsString('```', $this->cap->body);              // fenced wrong-language snippet
        self::assertStringContainsString("here's that in", $this->cap->body);
        // still logged + reported as recon
        self::assertNotEmpty($this->store->delta(0)['rows']);
        self::assertSame(1, $this->abuse->queueCount());
    }

    public function test_non_code_request_sends_the_word_swapped_text_to_the_model(): void
    {
        $prompt = null;
        // realFirst=0 forces the troll path (past the believable-first budget) so the corruption runs.
        $handler = $this->make(function (string $url, string $body) use (&$prompt): array {
            $prompt = (json_decode($body, true))['prompt'] ?? '';

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'a confident answer'])];
        }, false, false, 1.5, 0.0, 1.0, 0);

        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => false,
        ]), self::IP);

        self::assertIsString($prompt);
        // the model sees the CORRUPTED question, not the original (>=1 content word is always swapped,
        // so the original phrase can never survive intact)
        self::assertStringNotContainsString('capital of France', $prompt);
        self::assertNotSame(
            (new AiChatPromptBuilder())->build('what is the capital of France'),
            $prompt
        );
        // it is still a helpful-persona prompt wrapping the mangled text
        self::assertStringContainsString('You are a helpful assistant.', $prompt);
    }

    public function test_unswappable_question_serves_static_fallback_not_a_correct_answer(): void
    {
        // In troll mode (realFirst=0), "what is 2+2" has no swappable content word, so corruption is a
        // no-op. The helpful model would answer it CORRECTLY ("4") — the one thing the troll persona
        // must never do. It must serve static nonsense with no sidecar call instead.
        $calls = 0;
        $handler = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => (string) json_encode(['content' => '4'])];
        }, false, false, 1.5, 0.0, 1.0, 0);

        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is 2+2']],
            'stream' => false,
        ]), self::IP);

        self::assertSame(0, $calls, 'the model (which would answer "4") must never be consulted');
        self::assertSame(200, $this->cap->status);
        $expected = (new NonsenseFallback())->text(
            new ChatRequest('ollama-chat', self::OLLAMA_MODEL, 'what is 2+2', false, false, false)
        );
        self::assertStringContainsString($expected, $this->cap->body);
    }

    public function test_first_request_is_answered_straight_not_corrupted(): void
    {
        // A fresh IP within the believable-first budget (default realFirst=5) gets the RAW question,
        // not the word-swapped one — a real box on the opening probe.
        $prompt = null;
        $handler = $this->make(function (string $url, string $body) use (&$prompt): array {
            $prompt = (json_decode($body, true))['prompt'] ?? '';

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'Paris'])];
        });

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => self::OPENAI_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => false,
        ]), self::IP);

        self::assertIsString($prompt);
        self::assertStringContainsString('what is the capital of France', $prompt);   // uncorrupted
        self::assertStringContainsString('Paris', $this->cap->body);                  // real answer served
    }

    public function test_believable_budget_degrades_to_troll_after_the_first_n(): void
    {
        // realFirst=2: this IP's first two chats reach the sidecar (normal); the third is past the
        // budget → troll. "hi" is unswappable, so troll mode serves static nonsense with NO sidecar
        // call — the clean signal that the mode flipped from believable to troll.
        $calls = 0;
        $handler = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'a real answer'])];
        }, false, false, 1.5, 0.0, 1.0, 2);

        for ($i = 0; $i < 3; $i++) {
            $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
                'model' => self::OLLAMA_MODEL,
                'messages' => [['role' => 'user', 'content' => 'hi']],
                'stream' => false,
            ]), self::IP);
        }

        self::assertSame(2, $calls, 'only the first two (within budget) reach the sidecar');
        $expected = (new NonsenseFallback())->text(
            new ChatRequest('ollama-chat', self::OLLAMA_MODEL, 'hi', false, false, false)
        );
        self::assertStringContainsString($expected, $this->cap->body);   // 3rd degraded to static nonsense
    }

    public function test_exploit_substring_in_the_answer_degrades_to_fallback(): void
    {
        // A model reply carrying an exploit-shaped substring must be rejected (parity with the page
        // sanitizer) and degrade to the static fallback, not be served to the attacker.
        $handler = $this->make(fn (): array => [
            'status' => 200,
            'body' => (string) json_encode(['content' => "To fix it just run shell_exec('id') on the box."]),
        ]);

        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => self::OLLAMA_MODEL,
            'messages' => [['role' => 'user', 'content' => 'what is the capital of France']],
            'stream' => false,
        ]), self::IP);

        self::assertSame(200, $this->cap->status);
        self::assertStringNotContainsString('shell_exec', $this->cap->body);
        $expected = (new NonsenseFallback())->text(
            new ChatRequest('ollama-chat', self::OLLAMA_MODEL, 'what is the capital of France', false, false, false)
        );
        self::assertStringContainsString($expected, $this->cap->body);
    }
}

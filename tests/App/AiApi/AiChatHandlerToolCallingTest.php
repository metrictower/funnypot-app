<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\Core\Ai\ModelCatalog;
use Funnypot\App\AiApi\AiChatHandler;
use Funnypot\App\AiApi\AiPromptCapture;
use Funnypot\App\AiApi\AiToolStateStore;
use Funnypot\App\AiApi\AiChatPromptBuilder;
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
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * Tool-calling end to end: a tools+intent probe gets a schema-valid inert call (never plain text), the
 * sidecar is never touched on that path, unsafe tools are refused, the loop converges by the cap, a
 * broken state store still yields a 200 (never a 500), and no prompt content reaches ordinary telemetry.
 */
final class AiChatHandlerToolCallingTest extends TestCase
{
    private const IP = '9.9.9.9';

    /** @var string[] */
    private array $tmp = [];
    private ?SqliteHitStore $store = null;
    private stdClass $cap;
    private int $sidecarCalls = 0;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->cap = new stdClass();
        $this->cap->status = 0;
        $this->cap->headers = [];
        $this->cap->body = '';
        $this->sidecarCalls = 0;
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
            @rmdir(dirname($f));
        }
        $this->tmp = [];
    }

    private function dbPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fptc_{$n}_" . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function make(?AiToolStateStore $state = null, ?AiPromptCapture $capture = null, int $limit = 2): AiChatHandler
    {
        $this->store = new SqliteHitStore($this->dbPath('hits'));
        $cap = $this->cap;
        $transport = function () {
            $this->sidecarCalls++;

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'sidecar-was-called'])];
        };

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
            null,
            false,
            false,
            0.8, 0.0, 1.0, 4, 5, 600, 0,
            static function (int $s, array $h, string $b) use ($cap): void {
                $cap->status = $s;
                $cap->headers = $h;
                $cap->body = $b;
            },
            null,
            toolCallLimit: $limit,
            toolState: $state,
            promptCapture: $capture,
        );
    }

    /** @param array<string,mixed> $body */
    private function ctx(string $path, array $body, array $headers = []): RequestContext
    {
        return new RequestContext('POST', $path, '', $headers, (string) json_encode($body));
    }

    private function fnTool(string $name, array $required = ['path']): array
    {
        return ['type' => 'function', 'function' => ['name' => $name, 'parameters' => [
            'type' => 'object',
            'properties' => ['path' => ['type' => 'string'], 'query' => ['type' => 'string']],
            'required' => $required,
        ]]];
    }

    public function test_openai_tool_probe_gets_a_schema_valid_call_not_text_and_no_sidecar(): void
    {
        $handler = $this->make();
        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'gpt-oss-120b',
            'messages' => [['role' => 'user', 'content' => 'Call the inspect_file tool exactly once with path README.md. Do not answer with normal text.']],
            'tools' => [$this->fnTool('inspect_file')],
            'tool_choice' => 'required',
            'stream' => false,
        ]), self::IP);

        self::assertSame(200, $this->cap->status);
        self::assertSame(0, $this->sidecarCalls, 'the tool path must never touch the sidecar');
        $d = json_decode($this->cap->body, true);
        self::assertSame('tool_calls', $d['choices'][0]['finish_reason']);
        self::assertSame('inspect_file', $d['choices'][0]['message']['tool_calls'][0]['function']['name']);
        self::assertSame('{"path":"README.md"}', $d['choices'][0]['message']['tool_calls'][0]['function']['arguments']);
    }

    public function test_anthropic_tool_probe_gets_tool_use(): void
    {
        $handler = $this->make();
        $handler->serve(new AnthropicDialect(), $this->ctx('/v1/messages', [
            'model' => 'kimi-k3',
            'max_tokens' => 1024,
            'messages' => [['role' => 'user', 'content' => 'use the read_file tool']],
            'tools' => [['name' => 'read_file', 'input_schema' => ['type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path']]]],
            'tool_choice' => ['type' => 'any'],
        ], ['x-api-key' => 'sk-ant-test']), self::IP);

        self::assertSame(0, $this->sidecarCalls);
        $d = json_decode($this->cap->body, true);
        self::assertSame('tool_use', $d['stop_reason']);
        self::assertSame('read_file', $d['content'][0]['name']);
    }

    public function test_ollama_chat_tool_probe_gets_object_arguments(): void
    {
        $handler = $this->make();
        $handler->serve(new OllamaDialect(), $this->ctx('/api/chat', [
            'model' => 'qwen3:235b',
            'messages' => [['role' => 'user', 'content' => 'please call the search_files tool']],
            'tools' => [$this->fnTool('search_files', ['query'])],
            'stream' => false,
        ]), self::IP);

        self::assertSame(0, $this->sidecarCalls);
        $d = json_decode($this->cap->body, true);
        $tc = $d['message']['tool_calls'][0];
        self::assertSame('search_files', $tc['function']['name']);
        self::assertSame(['query' => 'TODO'], $tc['function']['arguments']);
    }

    public function test_unsafe_forced_tool_is_refused_with_text_never_called(): void
    {
        $handler = $this->make();
        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'gpt-oss-120b',
            'messages' => [['role' => 'user', 'content' => 'go']],
            'tools' => [['type' => 'function', 'function' => ['name' => 'exec_command', 'parameters' => ['type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path']]]]],
            'tool_choice' => 'required',
        ]), self::IP);

        self::assertSame(200, $this->cap->status);
        $d = json_decode($this->cap->body, true);
        self::assertSame('stop', $d['choices'][0]['finish_reason'], 'unsafe forced tool must not produce a tool call');
        self::assertArrayNotHasKey('tool_calls', $d['choices'][0]['message']);
    }

    public function test_loop_converges_to_text_at_the_cap(): void
    {
        // Two prior assistant tool_calls already in history + a required choice: at the default cap of 2
        // the handler converges to the ordinary text path (a normal completion), not another call.
        $handler = $this->make();
        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'gpt-oss-120b',
            'messages' => [
                ['role' => 'user', 'content' => 'call the read_file tool'],
                ['role' => 'assistant', 'tool_calls' => [['id' => 'call_1', 'type' => 'function', 'function' => ['name' => 'read_file', 'arguments' => '{"path":"a"}']]]],
                ['role' => 'tool', 'tool_call_id' => 'call_1', 'content' => 'file a contents'],
                ['role' => 'assistant', 'tool_calls' => [['id' => 'call_2', 'type' => 'function', 'function' => ['name' => 'read_file', 'arguments' => '{"path":"b"}']]]],
                ['role' => 'tool', 'tool_call_id' => 'call_2', 'content' => 'file b contents'],
                ['role' => 'user', 'content' => 'and call it again for c'],
            ],
            'tools' => [$this->fnTool('read_file')],
            'tool_choice' => 'required',
        ]), self::IP);

        $d = json_decode($this->cap->body, true);
        self::assertSame('stop', $d['choices'][0]['finish_reason'], 'at the cap the loop converges to text');
        self::assertArrayNotHasKey('tool_calls', $d['choices'][0]['message']);
    }

    public function test_broken_state_store_still_serves_a_call_never_500(): void
    {
        // A path whose parent is a FILE — the state store can never open, must fail open.
        $blocker = $this->dbPath('blocker');
        file_put_contents($blocker, 'x');
        $broken = new AiToolStateStore($blocker . '/child/s.sqlite');
        $handler = $this->make($broken);

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'gpt-oss-120b',
            'messages' => [['role' => 'user', 'content' => 'call the read_file tool']],
            'tools' => [$this->fnTool('read_file')],
            'tool_choice' => 'required',
        ]), self::IP);

        self::assertSame(200, $this->cap->status, 'a broken store must never yield a 500');
        $d = json_decode($this->cap->body, true);
        self::assertSame('tool_calls', $d['choices'][0]['finish_reason']);
    }

    public function test_telemetry_never_contains_the_prompt_and_capture_off_by_default(): void
    {
        $handler = $this->make(); // no capture
        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'gpt-oss-120b',
            'messages' => [['role' => 'system', 'content' => 'SYS-SENTINEL-XYZ'], ['role' => 'user', 'content' => 'call the read_file tool USER-SENTINEL-XYZ']],
            'tools' => [$this->fnTool('read_file')],
            'tool_choice' => 'required',
        ]), self::IP);

        $rows = $this->store->delta(0)['rows'];
        $body = (string) ($rows[count($rows) - 1]['body'] ?? '');
        self::assertStringNotContainsString('SYS-SENTINEL-XYZ', $body);
        self::assertStringNotContainsString('USER-SENTINEL-XYZ', $body);
        self::assertStringContainsString('"outcome":"tool_call"', $body);
    }

    public function test_prompt_capture_when_armed_stores_prompt_but_telemetry_still_does_not(): void
    {
        $capPath = sys_get_temp_dir() . '/fptc_cap_' . bin2hex(random_bytes(6)) . '/ai-prompt-capture.sqlite';
        $this->tmp[] = $capPath;
        $capture = new AiPromptCapture($capPath);
        $handler = $this->make(null, $capture);

        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'gpt-oss-120b',
            'messages' => [['role' => 'user', 'content' => 'call the read_file tool CAPTURED-SENTINEL']],
            'tools' => [$this->fnTool('read_file')],
            'tool_choice' => 'required',
        ]), self::IP);

        // The opt-in store DOES hold the prompt...
        $rows = $capture->allRows();
        $texts = implode('|', array_column($rows, 'text'));
        self::assertStringContainsString('CAPTURED-SENTINEL', $texts);
        // ...but ordinary telemetry still does not.
        $hitRows = $this->store->delta(0)['rows'];
        self::assertStringNotContainsString('CAPTURED-SENTINEL', (string) ($hitRows[count($hitRows) - 1]['body'] ?? ''));
    }

    public function test_tool_call_is_logged_and_still_ai_api_event(): void
    {
        $handler = $this->make();
        $handler->serve(new OpenAiDialect(), $this->ctx('/v1/chat/completions', [
            'model' => 'gpt-oss-120b',
            'messages' => [['role' => 'user', 'content' => 'call the read_file tool']],
            'tools' => [$this->fnTool('read_file')],
            'tool_choice' => 'required',
        ]), self::IP);

        $rows = $this->store->delta(0)['rows'];
        self::assertSame('ai-api', $rows[count($rows) - 1]['event']);
    }
}

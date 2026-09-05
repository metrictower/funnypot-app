<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\AiToolStateStore;
use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\SafeArgumentSynthesizer;
use Funnypot\App\AiApi\SafeToolSelector;
use Funnypot\App\AiApi\ToolTurnPlanner;
use Funnypot\App\AiApi\UsageEstimator;
use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\App\AiApi\Value\ToolDefinition;
use PHPUnit\Framework\TestCase;

/**
 * The loop decision: a probe gets one inert call; explicit-extra loops stop at the cap; a returned
 * result converges (or, when the store cannot corroborate it, still converges without a new call); a
 * too-small budget yields a length stop, never a partial call.
 */
final class ToolTurnPlannerTest extends TestCase
{
    private function planner(): ToolTurnPlanner
    {
        $sel = new SafeToolSelector();

        return new ToolTurnPlanner($sel, new SafeArgumentSynthesizer($sel), new UsageEstimator());
    }

    private function readTool(): ToolDefinition
    {
        $schema = ['type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path']];

        return new ToolDefinition('read_file', $schema, hash('sha256', (string) json_encode($schema)), 0);
    }

    private function req(array $overrides = []): ChatRequest
    {
        $r = new ChatRequest('openai', 'gpt-oss-120b', $overrides['userText'] ?? 'call the read_file tool', false, false, false, [$this->readTool()], ToolChoice::REQUIRED);
        foreach ($overrides as $k => $v) {
            if (property_exists($r, $k)) {
                $r->$k = $v;
            }
        }

        return $r;
    }

    public function test_simple_probe_gets_one_inert_call(): void
    {
        $turn = $this->planner()->plan($this->req(), 'call_1', 'actor', null, 2);
        self::assertNotNull($turn);
        self::assertTrue($turn->isToolCall());
        self::assertSame('read_file', $turn->call->name);
        self::assertSame('{"path":"README.md"}', $turn->call->argumentsJson);
    }

    public function test_at_cap_falls_through_to_text_path(): void
    {
        $turn = $this->planner()->plan($this->req(['priorToolCalls' => 2]), 'call_x', 'actor', null, 2);
        self::assertNull($turn, 'at the cap the planner defers to the ordinary text path');
    }

    public function test_limit_zero_never_calls(): void
    {
        $turn = $this->planner()->plan($this->req(), 'call_x', 'actor', null, 0);
        self::assertNull($turn);
    }

    public function test_returned_result_without_explicit_extra_converges_to_text(): void
    {
        $req = $this->req(['hasToolResult' => true, 'priorToolCalls' => 1, 'lastCallId' => 'call_1', 'userText' => 'thanks']);
        $turn = $this->planner()->plan($req, 'call_2', 'actor', null, 2);
        self::assertNotNull($turn);
        self::assertTrue($turn->isText());
    }

    public function test_returned_result_with_explicit_extra_under_cap_calls_again(): void
    {
        $req = $this->req(['hasToolResult' => true, 'priorToolCalls' => 1, 'lastCallId' => 'call_1', 'wantsAnotherCall' => true, 'userText' => 'now call the tool again for the next file']);
        $turn = $this->planner()->plan($req, 'call_2', 'actor', null, 2);
        self::assertNotNull($turn);
        self::assertTrue($turn->isToolCall());
    }

    public function test_replayed_result_does_not_advance_to_another_call(): void
    {
        $store = $this->store();
        // No matching issued row => consume returns REPLAYED => no advance even with explicit-extra intent.
        $req = $this->req(['hasToolResult' => true, 'priorToolCalls' => 1, 'lastCallId' => 'call_unknown', 'wantsAnotherCall' => true, 'userText' => 'call the tool again']);
        $turn = $this->planner()->plan($req, 'call_2', 'actor', $store, 2);
        self::assertNotNull($turn);
        self::assertTrue($turn->isText(), 'a result the store cannot corroborate must not advance to a new call');
    }

    public function test_budget_too_small_yields_a_length_stop_not_a_partial_call(): void
    {
        $turn = $this->planner()->plan($this->req(['maxOutputTokens' => 1]), 'call_1', 'actor', null, 2);
        self::assertNotNull($turn);
        self::assertTrue($turn->isLength());
    }

    public function test_unsafe_forced_tool_yields_a_clarification_not_a_call(): void
    {
        $schema = ['type' => 'object', 'properties' => ['url' => ['type' => 'string']], 'required' => ['url']];
        $unsafe = new ToolDefinition('fetch_url', $schema, hash('sha256', 'u'), 0);
        $req = new ChatRequest('openai', 'gpt', 'go', false, false, false, [$unsafe], ToolChoice::REQUIRED);
        $turn = $this->planner()->plan($req, 'call_1', 'actor', null, 2);
        self::assertNotNull($turn);
        self::assertTrue($turn->isText());
        self::assertStringContainsString("can't complete", $turn->text);
    }

    public function test_no_tools_returns_null(): void
    {
        $req = new ChatRequest('openai', 'gpt', 'hi', false, false, false);
        self::assertNull($this->planner()->plan($req, 'call_1', 'actor', null, 2));
    }

    /** @var string[] */
    private array $tmp = [];

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
            @rmdir(dirname($f));
        }
    }

    private function store(): AiToolStateStore
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $path = sys_get_temp_dir() . '/fp_planner_' . bin2hex(random_bytes(6)) . '/s.sqlite';
        $this->tmp[] = $path;

        return new AiToolStateStore($path);
    }
}

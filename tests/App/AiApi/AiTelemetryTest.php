<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\AiTelemetry;
use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\App\AiApi\Value\ToolDefinition;
use PHPUnit\Framework\TestCase;

/**
 * The ordinary hit body carries only closed metadata — never a prompt excerpt, tool schema, argument,
 * result, auth value or cookie — and stays within the 2000-byte cap.
 */
final class AiTelemetryTest extends TestCase
{
    public function test_records_only_closed_metadata_no_prompt_excerpt(): void
    {
        $tool = new ToolDefinition('read_file', ['type' => 'object'], hash('sha256', 'x'), 0);
        $req = new ChatRequest('openai', 'gpt-oss-120b', 'SECRET-USER-PROMPT-SENTINEL', false, false, false, [$tool], ToolChoice::AUTO);
        $req->inputTokens = 12;

        $json = AiTelemetry::forHit($req, 500, 300, 12, 4, AiTelemetry::OUT_TOOL_CALL);
        $decoded = json_decode($json, true);

        self::assertSame('openai', $decoded['provider']);
        self::assertSame('gpt-oss-120b', $decoded['model']);
        self::assertSame(1, $decoded['tool_count']);
        self::assertSame(['read_file'], $decoded['tool_names']);
        self::assertSame([hash('sha256', 'x')], $decoded['schema_hashes']);
        self::assertSame('tool_call', $decoded['outcome']);
        self::assertStringNotContainsString('SECRET-USER-PROMPT-SENTINEL', $json);
        // no argument or argument-derived field
        self::assertArrayNotHasKey('arguments', $decoded);
        self::assertArrayNotHasKey('argument_hash', $decoded);
    }

    public function test_stays_within_the_byte_cap_with_many_tools(): void
    {
        $tools = [];
        for ($i = 0; $i < 32; $i++) {
            $tools[] = new ToolDefinition('read_tool_' . $i, ['type' => 'object'], hash('sha256', (string) $i), $i);
        }
        $req = new ChatRequest('openai', 'gpt-oss-120b', 'hi', false, false, false, $tools);
        $json = AiTelemetry::forHit($req, 60000, 200, 5, 3, AiTelemetry::OUT_TEXT);
        self::assertLessThanOrEqual(2000, strlen($json));
        self::assertNotNull(json_decode($json, true));
    }
}

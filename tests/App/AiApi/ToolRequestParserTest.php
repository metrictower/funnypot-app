<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ParseLimitError;
use Funnypot\App\AiApi\ToolRequestParser;
use Funnypot\App\AiApi\Value\ToolChoice;
use PHPUnit\Framework\TestCase;

/**
 * The bounded tool-request normaliser: canonical schema hashing (descriptions/examples/extensions
 * dropped), choice collapsing across providers, and hard caps that throw in-shape rather than truncate.
 */
final class ToolRequestParserTest extends TestCase
{
    public function test_descriptions_examples_and_extensions_do_not_change_the_schema_hash(): void
    {
        $p = new ToolRequestParser();
        $lean = $p->tools([['name' => 'read_file', 'parameters' => [
            'type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path'],
        ]]], 'parameters');
        $fat = $p->tools([['name' => 'read_file', 'parameters' => [
            'type' => 'object',
            'description' => 'reads a file at PATH-SENTINEL',
            'examples' => ['EXAMPLE-SENTINEL'],
            'x-vendor-ext' => 'EXT-SENTINEL',
            'properties' => ['path' => ['type' => 'string', 'description' => 'the DESC-SENTINEL path']],
            'required' => ['path'],
        ]]], 'parameters');

        self::assertSame($lean[0]->schemaHash, $fat[0]->schemaHash);
        $encoded = (string) json_encode($fat[0]->schema);
        foreach (['PATH-SENTINEL', 'EXAMPLE-SENTINEL', 'EXT-SENTINEL', 'DESC-SENTINEL'] as $s) {
            self::assertStringNotContainsString($s, $encoded, 'free text must not survive canonicalisation');
        }
    }

    public function test_key_order_does_not_change_the_hash(): void
    {
        $p = new ToolRequestParser();
        $a = $p->tools([['name' => 'read_file', 'parameters' => ['type' => 'object', 'required' => ['path'], 'properties' => ['path' => ['type' => 'string']]]]], 'parameters');
        $b = $p->tools([['name' => 'read_file', 'parameters' => ['properties' => ['path' => ['type' => 'string']], 'type' => 'object', 'required' => ['path']]]], 'parameters');
        self::assertSame($a[0]->schemaHash, $b[0]->schemaHash);
    }

    public function test_over_body_size_throws(): void
    {
        $this->expectException(ParseLimitError::class);
        (new ToolRequestParser())->assertBodySize(str_repeat('x', ToolRequestParser::MAX_BODY_BYTES + 1));
    }

    public function test_exactly_at_body_size_is_accepted(): void
    {
        (new ToolRequestParser())->assertBodySize(str_repeat('x', ToolRequestParser::MAX_BODY_BYTES));
        self::assertTrue(true); // reached => no exception at the exact cap
    }

    public function test_null_body_is_accepted(): void
    {
        (new ToolRequestParser())->assertBodySize(null);
        self::assertTrue(true);
    }

    public function test_too_many_tools_throws(): void
    {
        $tools = [];
        for ($i = 0; $i <= ToolRequestParser::MAX_TOOLS; $i++) {
            $tools[] = ['name' => 'read_' . $i, 'parameters' => ['type' => 'object']];
        }
        $this->expectException(ParseLimitError::class);
        (new ToolRequestParser())->tools($tools, 'parameters');
    }

    public function test_too_deep_schema_throws(): void
    {
        $node = ['type' => 'object'];
        for ($i = 0; $i < ToolRequestParser::MAX_SCHEMA_DEPTH + 2; $i++) {
            $node = ['type' => 'object', 'properties' => ['a' => $node]];
        }
        $this->expectException(ParseLimitError::class);
        (new ToolRequestParser())->tools([['name' => 'read_x', 'parameters' => $node]], 'parameters');
    }

    public function test_over_length_tool_name_throws(): void
    {
        $this->expectException(ParseLimitError::class);
        (new ToolRequestParser())->tools([['name' => str_repeat('a', ToolRequestParser::MAX_NAME_BYTES + 1), 'parameters' => ['type' => 'object']]], 'parameters');
    }

    public function test_choice_collapses_across_providers(): void
    {
        $p = new ToolRequestParser();
        self::assertSame(ToolChoice::NONE, $p->choice('none')->mode);
        self::assertSame(ToolChoice::REQUIRED, $p->choice('required')->mode);
        self::assertSame(ToolChoice::REQUIRED, $p->choice(['type' => 'any'])->mode);      // Anthropic any
        $named = $p->choice(['type' => 'function', 'function' => ['name' => 'read_file']]); // OpenAI named
        self::assertSame(ToolChoice::NAMED, $named->mode);
        self::assertSame('read_file', $named->name);
        $anthNamed = $p->choice(['type' => 'tool', 'name' => 'read_file']);                 // Anthropic named
        self::assertSame(ToolChoice::NAMED, $anthNamed->mode);
        self::assertSame('read_file', $anthNamed->name);
        self::assertSame(ToolChoice::AUTO, $p->choice(null)->mode);                          // absent => default
    }

    public function test_call_intent_detects_explicit_asks_only(): void
    {
        $p = new ToolRequestParser();
        self::assertTrue($p->callIntent('Call the inspect_file tool exactly once with path README.md.'));
        self::assertTrue($p->callIntent('please use the search tool'));
        self::assertFalse($p->callIntent('what is the weather today'));
        self::assertFalse($p->callIntent('the toolbox is on the shelf'));
    }

    public function test_another_call_intent(): void
    {
        $p = new ToolRequestParser();
        self::assertTrue($p->anotherCallIntent('now call the tool again with the next file'));
        self::assertFalse($p->anotherCallIntent('thanks, that is all'));
    }
}

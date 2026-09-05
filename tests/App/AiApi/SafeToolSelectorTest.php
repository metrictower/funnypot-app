<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\SafeToolSelector;
use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\App\AiApi\Value\ToolDefinition;
use PHPUnit\Framework\TestCase;

/**
 * The closed inert-selection gate. "Read-only by name" is not enough: a mutation/network verb anywhere
 * in the tokenised name, or a required non-scalar/URI/traversal property, makes a tool ineligible. A
 * forcing choice never weakens this — an unsafe forced tool yields no selection.
 */
final class SafeToolSelectorTest extends TestCase
{
    private function tool(string $name, array $schema = ['type' => 'object']): ToolDefinition
    {
        return new ToolDefinition($name, $schema, hash('sha256', (string) json_encode($schema)), 0);
    }

    private function objSchema(array $props, array $required = []): array
    {
        return ['type' => 'object', 'properties' => $props, 'required' => $required];
    }

    /** @return array<string,array{0:string}> */
    public static function safeNames(): array
    {
        return [
            'inspect_file' => ['inspect_file'],
            'read_file' => ['read_file'],
            'getStatus' => ['getStatus'],
            'search_code' => ['search_code'],
            'list-items' => ['list-items'],
            'findThing' => ['findThing'],
            'describe' => ['describe'],
        ];
    }

    /** @dataProvider safeNames */
    public function test_safe_read_shaped_names_are_eligible(string $name): void
    {
        self::assertTrue((new SafeToolSelector())->eligible($this->tool($name)));
    }

    /** @return array<string,array{0:string}> */
    public static function unsafeNames(): array
    {
        return [
            'delete_file' => ['delete_file'],
            'get_url' => ['get_url'],          // 'url' token denied
            'getURL' => ['getURL'],            // camelCase 'url' token denied
            'read_and_exec' => ['read_and_exec'],
            'run_command' => ['run_command'],
            'send_request' => ['send_request'],
            'inspectHTTP' => ['inspectHTTP'],  // 'http' token denied
            'post_read' => ['post_read'],      // first token not an allow verb; also denied 'post'
            'fetch_data' => ['fetch_data'],    // first token 'fetch' not allowed
            'sql_query' => ['sql_query'],
            'download_backup' => ['download_backup'],
            'update_record' => ['update_record'],
            'ssh_connect' => ['ssh_connect'],
            'with space' => ['read file'],     // fails the name regex
            'dotted' => ['inspect.http'],      // fails the name regex
        ];
    }

    /** @dataProvider unsafeNames */
    public function test_unsafe_names_are_ineligible(string $name): void
    {
        self::assertFalse((new SafeToolSelector())->eligible($this->tool($name)));
    }

    public function test_required_scalar_vocabulary_property_is_eligible(): void
    {
        $t = $this->tool('read_file', $this->objSchema(['path' => ['type' => 'string']], ['path']));
        self::assertTrue((new SafeToolSelector())->eligible($t));
    }

    public function test_required_property_outside_the_vocabulary_is_ineligible(): void
    {
        $t = $this->tool('read_thing', $this->objSchema(['target' => ['type' => 'string']], ['target']));
        self::assertFalse((new SafeToolSelector())->eligible($t));
    }

    public function test_required_object_or_array_property_is_ineligible(): void
    {
        $nested = $this->tool('read_file', $this->objSchema(['path' => ['type' => 'object', 'properties' => ['a' => ['type' => 'string']]]], ['path']));
        self::assertFalse((new SafeToolSelector())->eligible($nested));
        $arr = $this->tool('read_file', $this->objSchema(['path' => ['type' => 'array']], ['path']));
        self::assertFalse((new SafeToolSelector())->eligible($arr));
    }

    public function test_required_uri_format_property_is_ineligible(): void
    {
        $t = $this->tool('read_file', $this->objSchema(['path' => ['type' => 'string', 'format' => 'uri']], ['path']));
        self::assertFalse((new SafeToolSelector())->eligible($t));
    }

    public function test_non_object_root_is_ineligible(): void
    {
        self::assertFalse((new SafeToolSelector())->eligible($this->tool('read_file', ['type' => 'string'])));
    }

    public function test_choice_none_never_selects(): void
    {
        $tools = [$this->tool('read_file', $this->objSchema(['path' => ['type' => 'string']], ['path']))];
        self::assertNull((new SafeToolSelector())->select($tools, new ToolChoice(ToolChoice::NONE), true));
    }

    public function test_choice_auto_needs_intent(): void
    {
        $tools = [$this->tool('read_file', $this->objSchema(['path' => ['type' => 'string']], ['path']))];
        $sel = new SafeToolSelector();
        self::assertNull($sel->select($tools, new ToolChoice(ToolChoice::AUTO), false));
        self::assertNotNull($sel->select($tools, new ToolChoice(ToolChoice::AUTO), true));
    }

    public function test_choice_required_picks_first_eligible_skipping_unsafe(): void
    {
        $tools = [
            $this->tool('delete_all'),                                             // unsafe, skipped
            $this->tool('read_file', $this->objSchema(['path' => ['type' => 'string']], ['path'])),
        ];
        $picked = (new SafeToolSelector())->select($tools, new ToolChoice(ToolChoice::REQUIRED), false);
        self::assertNotNull($picked);
        self::assertSame('read_file', $picked->name);
    }

    public function test_named_choice_selects_only_that_eligible_tool(): void
    {
        $tools = [
            $this->tool('read_file', $this->objSchema(['path' => ['type' => 'string']], ['path'])),
            $this->tool('list_dir', $this->objSchema(['path' => ['type' => 'string']])),
        ];
        $picked = (new SafeToolSelector())->select($tools, new ToolChoice(ToolChoice::NAMED, 'list_dir'), false);
        self::assertNotNull($picked);
        self::assertSame('list_dir', $picked->name);
    }

    public function test_named_choice_of_an_unsafe_tool_selects_nothing(): void
    {
        $tools = [$this->tool('exec_shell', $this->objSchema(['path' => ['type' => 'string']], ['path']))];
        self::assertNull((new SafeToolSelector())->select($tools, new ToolChoice(ToolChoice::NAMED, 'exec_shell'), false));
    }

    public function test_required_with_no_eligible_tool_selects_nothing(): void
    {
        $tools = [$this->tool('delete_it'), $this->tool('run_it')];
        self::assertNull((new SafeToolSelector())->select($tools, new ToolChoice(ToolChoice::REQUIRED), true));
    }
}

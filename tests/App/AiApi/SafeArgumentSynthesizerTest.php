<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\SafeArgumentSynthesizer;
use Funnypot\App\AiApi\SafeToolSelector;
use Funnypot\App\AiApi\Value\ToolDefinition;
use PHPUnit\Framework\TestCase;

/**
 * The synthesiser only ever emits inert values from a closed pool or a matching scalar enum, never from
 * prompt/description/result content. Its output can never carry a shell metacharacter, URL, absolute
 * path, traversal segment or credential-looking value.
 */
final class SafeArgumentSynthesizerTest extends TestCase
{
    private function synth(): SafeArgumentSynthesizer
    {
        return new SafeArgumentSynthesizer(new SafeToolSelector());
    }

    private function tool(array $schema): ToolDefinition
    {
        return new ToolDefinition('read_file', $schema, hash('sha256', (string) json_encode($schema)), 0);
    }

    public function test_fills_required_path_with_an_inert_relative_file(): void
    {
        $out = $this->synth()->synthesize($this->tool([
            'type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path'],
        ]));
        self::assertNotNull($out);
        [$args, $json] = $out;
        self::assertSame(['path' => 'README.md'], $args);
        self::assertSame('{"path":"README.md"}', $json);
    }

    public function test_prefers_a_matching_scalar_enum(): void
    {
        $out = $this->synth()->synthesize($this->tool([
            'type' => 'object',
            'properties' => ['pattern' => ['type' => 'string', 'enum' => ['alpha', 'beta']]],
            'required' => ['pattern'],
        ]));
        self::assertNotNull($out);
        self::assertSame(['pattern' => 'alpha'], $out[0]);
    }

    public function test_integer_and_boolean_required_props_get_inert_scalars(): void
    {
        $out = $this->synth()->synthesize($this->tool([
            'type' => 'object',
            'properties' => [
                'limit' => ['type' => 'integer'],
                'include_hidden' => ['type' => 'boolean'],
            ],
            'required' => ['limit', 'include_hidden'],
        ]));
        self::assertNotNull($out);
        self::assertSame(10, $out[0]['limit']);
        self::assertFalse($out[0]['include_hidden']);
    }

    public function test_no_required_props_fills_one_primary_natural_property(): void
    {
        $out = $this->synth()->synthesize($this->tool([
            'type' => 'object', 'properties' => ['query' => ['type' => 'string']],
        ]));
        self::assertNotNull($out);
        self::assertSame(['query' => 'TODO'], $out[0]);
    }

    public function test_empty_schema_yields_an_empty_argument_object(): void
    {
        $out = $this->synth()->synthesize($this->tool(['type' => 'object']));
        self::assertNotNull($out);
        self::assertSame([], $out[0]);
        self::assertSame('{}', $out[1]); // empty args encode as an object string, never "[]"
    }

    public function test_output_never_contains_a_shell_metacharacter_or_url_or_traversal(): void
    {
        // Even a maliciously-shaped (but selector-eligible) schema can only ever produce closed-pool
        // values — the synthesiser derives nothing from attacker input.
        $out = $this->synth()->synthesize($this->tool([
            'type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path'],
        ]));
        self::assertNotNull($out);
        $json = $out[1];
        foreach ([';', '|', '&', '`', '$', '..', '://', '/etc', 'C:\\'] as $needle) {
            self::assertStringNotContainsString($needle, $json);
        }
    }

    public function test_enum_of_unsafe_strings_only_yields_no_value_for_that_required_prop(): void
    {
        // Every enum option is unsafe (URL / traversal), so no safe value exists => no call.
        $out = $this->synth()->synthesize($this->tool([
            'type' => 'object',
            'properties' => ['path' => ['type' => 'string', 'enum' => ['http://x/y', '../../etc/passwd']]],
            'required' => ['path'],
        ]));
        self::assertNull($out);
    }
}

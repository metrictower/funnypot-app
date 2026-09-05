<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\App\AiApi\Value\ToolDefinition;

/**
 * The closed, deterministic gate deciding whether the decoy may fabricate a call to a client-supplied
 * tool — and to WHICH one. "Read-only by name" is not enough (`get_url`, `read_and_exec`, a required URI
 * property could each still cause exfiltration in the probing agent), so eligibility is doubly closed:
 * the tokenised name must START with a read/search/inspect verb and contain NO mutation/network token,
 * and the schema must be a plain object whose required properties are all scalar and all drawn from a
 * closed argument vocabulary. A forcing tool_choice never weakens these checks — an unsafe named/first
 * tool yields no call (the handler serves a clarification instead).
 */
final class SafeToolSelector
{
    /** The first semantic token of an eligible tool name must be one of these. */
    private const ALLOW_VERBS = [
        'read', 'get', 'list', 'search', 'find', 'inspect', 'lookup', 'stat', 'describe',
    ];

    /** No token of an eligible name may be any of these (mutation / execution / network / transport). */
    private const DENY_TOKENS = [
        'write', 'create', 'update', 'delete', 'remove', 'rename', 'move', 'copy', 'upload',
        'download', 'exec', 'execute', 'run', 'shell', 'command', 'spawn', 'send', 'request',
        'http', 'url', 'ssh', 'sql', 'insert', 'patch', 'put', 'post', 'connect', 'fetch', 'network',
    ];

    /** Every required property of an eligible tool must be one of these inert, read-shaped names. */
    private const ARG_VOCABULARY = [
        'path', 'file', 'filename', 'query', 'pattern', 'term', 'limit', 'offset', 'depth',
        'line', 'start', 'end', 'include_hidden',
    ];

    private const SCALAR_TYPES = ['string', 'integer', 'number', 'boolean'];

    /** Formats that imply network access or non-text payloads — an unsupported property shape. */
    private const UNSAFE_FORMATS = [
        'uri', 'url', 'uri-reference', 'iri', 'iri-reference', 'uri-template',
        'binary', 'byte', 'base64', 'data-url', 'hostname', 'idn-hostname', 'ipv4', 'ipv6', 'email',
    ];

    /**
     * Pick the tool to call for this choice, or null when no call should be made.
     *
     * @param list<ToolDefinition> $tools in provider order
     */
    public function select(array $tools, ToolChoice $choice, bool $hasCallIntent): ?ToolDefinition
    {
        if ($choice->mode === ToolChoice::NONE) {
            return null;
        }
        if ($choice->mode === ToolChoice::NAMED) {
            foreach ($tools as $tool) {
                if ($tool->name === $choice->name && $this->eligible($tool)) {
                    return $tool;
                }
            }

            return null;
        }
        if ($choice->mode === ToolChoice::AUTO && !$hasCallIntent) {
            return null;
        }

        // AUTO-with-intent and REQUIRED both take the first eligible tool in provider order.
        foreach ($tools as $tool) {
            if ($this->eligible($tool)) {
                return $tool;
            }
        }

        return null;
    }

    /** True when a tool's name and schema both pass the closed safety checks. */
    public function eligible(ToolDefinition $tool): bool
    {
        if (!$this->nameSafe($tool->name)) {
            return false;
        }

        return $this->schemaSafe($tool->schema);
    }

    /**
     * The subset of a tool's properties the synthesiser may fill — every supported scalar property. A
     * required unsupported property makes the tool ineligible, so this is only ever read for an eligible
     * tool; optional unsupported properties are simply omitted.
     *
     * @param array<string,mixed> $schema canonical schema
     * @return array<string,array<string,mixed>> property name => its canonical scalar schema
     */
    public function supportedProperties(array $schema): array
    {
        $props = is_array($schema['properties'] ?? null) ? $schema['properties'] : [];
        $out = [];
        foreach ($props as $name => $sub) {
            if (is_string($name) && is_array($sub) && $this->propertyScalar($sub)) {
                $out[$name] = $sub;
            }
        }

        return $out;
    }

    private function nameSafe(string $name): bool
    {
        if (preg_match('/^[A-Za-z][A-Za-z0-9_-]{0,63}$/', $name) !== 1) {
            return false;
        }
        $tokens = $this->tokenize($name);
        if ($tokens === []) {
            return false;
        }
        if (!in_array($tokens[0], self::ALLOW_VERBS, true)) {
            return false;
        }
        foreach ($tokens as $token) {
            if (in_array($token, self::DENY_TOKENS, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Split a tool name into lowercase semantic tokens on punctuation AND case boundaries, so
     * `getURL`, `read_and_exec`, `inspectHTTP` all expose their component words to the allow/deny sets.
     *
     * @return list<string>
     */
    private function tokenize(string $name): array
    {
        $spaced = str_replace(['_', '-'], ' ', $name);
        // camelCase / acronym boundaries: fooBar -> foo Bar, URLFetch -> URL Fetch.
        $spaced = (string) preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', ' ', $spaced);
        $spaced = (string) preg_replace('/(?<=[A-Z])(?=[A-Z][a-z])/', ' ', $spaced);
        $parts = preg_split('/\s+/', strtolower(trim($spaced)), -1, PREG_SPLIT_NO_EMPTY);

        return $parts === false ? [] : $parts;
    }

    /** @param array<string,mixed> $schema canonical root schema */
    private function schemaSafe(array $schema): bool
    {
        $type = $schema['type'] ?? null;
        $hasProps = isset($schema['properties']) && is_array($schema['properties']);
        // Root must be an object (declared, or evidenced by a properties map). An empty schema (no
        // constraints, no required args) is a plausible no-argument tool and is allowed.
        if ($type !== null && $type !== 'object') {
            return false;
        }
        if ($type === null && !$hasProps && $schema !== []) {
            return false;
        }

        $required = is_array($schema['required'] ?? null) ? $schema['required'] : [];
        $props = is_array($schema['properties'] ?? null) ? $schema['properties'] : [];
        foreach ($required as $name) {
            if (!is_string($name) || !in_array($name, self::ARG_VOCABULARY, true)) {
                return false;
            }
            $sub = $props[$name] ?? null;
            if (!is_array($sub) || !$this->propertyScalar($sub)) {
                return false;
            }
        }

        return true;
    }

    /** @param array<string,mixed> $sub canonical property schema */
    private function propertyScalar(array $sub): bool
    {
        $type = $sub['type'] ?? null;
        $enum = $sub['enum'] ?? null;
        $format = is_string($sub['format'] ?? null) ? strtolower($sub['format']) : null;

        if ($format !== null && in_array($format, self::UNSAFE_FORMATS, true)) {
            return false;
        }
        if (isset($sub['properties']) || (isset($sub['type']) && $sub['type'] === 'array')) {
            return false;
        }
        if (is_array($enum) && $enum !== []) {
            foreach ($enum as $v) {
                if (!is_scalar($v)) {
                    return false;
                }
            }

            return true;
        }
        if (is_string($type) && in_array($type, self::SCALAR_TYPES, true)) {
            return true;
        }

        return false;
    }
}

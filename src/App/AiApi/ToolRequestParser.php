<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\ToolChoice;
use Funnypot\App\AiApi\Value\ToolDefinition;
use RuntimeException;

/**
 * Shared, bounded normaliser for the tool-calling fields of every provider request. It turns a decoded
 * body into {@see ToolDefinition} objects + a {@see ToolChoice}, and walks the message history to derive
 * the small facts the loop planner needs (how many calls already happened, whether a tool result just
 * came back, its correlation id/name, whether the user explicitly asked for another call).
 *
 * Everything is capped BEFORE recursion so a hostile schema can neither blow memory nor smuggle
 * unbounded values downstream. Over-limit or structurally invalid input throws {@see ParseLimitError};
 * the handler's parse guard turns that into the provider's ordinary 400. Descriptions, examples and
 * unknown extension keys are dropped after byte accounting: only a canonical, key-sorted, scalar-only
 * schema subset (and its SHA-256) survives, so nothing free-text an attacker wrote reaches the wire or
 * telemetry.
 */
final class ToolRequestParser
{
    /** Hard parser limits — constants, never operator-tunable (spec §3). */
    public const MAX_BODY_BYTES = 65536;      // 64 KiB request body
    public const MAX_MESSAGES = 64;
    public const MAX_TOOLS = 32;
    public const MAX_SCHEMA_BYTES = 32768;    // aggregate canonical schema bytes
    public const MAX_SCHEMA_DEPTH = 8;
    public const MAX_PROPS = 64;              // properties per tool
    public const MAX_NAME_BYTES = 128;        // model/id/name fields
    public const MAX_TEXT_BYTES = 16384;      // aggregate accepted message text
    public const MAX_RESULT_BYTES = 4096;     // per tool-result

    /**
     * Reject an over-cap raw body before any JSON parsing. The declared/actual length is authoritative;
     * a body at or past MAX_BODY_BYTES+1 is an oversize decision, never a silently valid prefix.
     */
    public function assertBodySize(?string $rawBody): void
    {
        if ($rawBody !== null && strlen($rawBody) > self::MAX_BODY_BYTES) {
            throw new ParseLimitError('request body too large');
        }
    }

    /**
     * Normalise a list of provider tool definitions into bounded ToolDefinition objects.
     *
     * @param array<int,mixed> $rawTools already extracted per provider: each item carries a name and a
     *        JSON-Schema-shaped parameters object under the provider's own key
     * @param string $nameKey   key holding the tool name inside the provider wrapper ('' = item root)
     * @param string $schemaKey key holding the parameters schema ('function.parameters' style is
     *        pre-unwrapped by the caller, so this is a single key)
     * @return list<ToolDefinition>
     */
    public function tools(array $rawTools, string $schemaKey): array
    {
        if (count($rawTools) > self::MAX_TOOLS) {
            throw new ParseLimitError('too many tools');
        }

        $out = [];
        $order = 0;
        $aggregateSchemaBytes = 0;
        foreach ($rawTools as $raw) {
            if (!is_array($raw)) {
                continue;
            }
            $name = $raw['name'] ?? null;
            $schema = $raw[$schemaKey] ?? null;
            if (!is_string($name) || $name === '') {
                continue;
            }
            if (strlen($name) > self::MAX_NAME_BYTES) {
                throw new ParseLimitError('tool name too long');
            }
            $canonical = is_array($schema) ? $this->canonicalSchema($schema, 1) : [];
            $encoded = (string) json_encode($canonical, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $aggregateSchemaBytes += strlen($encoded);
            if ($aggregateSchemaBytes > self::MAX_SCHEMA_BYTES) {
                throw new ParseLimitError('aggregate tool schemas too large');
            }
            $out[] = new ToolDefinition($name, $canonical, hash('sha256', $encoded), $order++);
        }

        return $out;
    }

    /**
     * A canonical, recursively key-sorted, scalar-only subset of a JSON-Schema object. Only the keys the
     * selector reasons about survive (type, properties, required, enum); description/examples/default and
     * any unknown extension key are dropped, so the hash is stable across cosmetic differences and no
     * free text reaches downstream. Depth and property counts are checked before descent.
     *
     * @param array<string,mixed> $schema
     * @return array<string,mixed>
     */
    private function canonicalSchema(array $schema, int $depth): array
    {
        if ($depth > self::MAX_SCHEMA_DEPTH) {
            throw new ParseLimitError('schema too deep');
        }

        $out = [];
        if (isset($schema['type']) && is_string($schema['type'])) {
            $out['type'] = $schema['type'];
        }
        // 'format' is a bounded keyword, not free text: kept so the selector can reject URI/binary/media
        // formats. Truncated defensively so a hostile long value cannot bloat the canonical bytes.
        if (isset($schema['format']) && is_string($schema['format'])) {
            $out['format'] = substr($schema['format'], 0, 64);
        }
        if (isset($schema['enum']) && is_array($schema['enum'])) {
            $enum = [];
            foreach ($schema['enum'] as $v) {
                if (is_scalar($v) || $v === null) {
                    $enum[] = $v;
                }
            }
            $out['enum'] = $enum;
        }
        if (isset($schema['required']) && is_array($schema['required'])) {
            $req = [];
            foreach ($schema['required'] as $r) {
                if (is_string($r)) {
                    $req[] = $r;
                }
            }
            sort($req);
            $out['required'] = $req;
        }
        if (isset($schema['properties']) && is_array($schema['properties'])) {
            if (count($schema['properties']) > self::MAX_PROPS) {
                throw new ParseLimitError('too many properties');
            }
            $props = [];
            foreach ($schema['properties'] as $key => $sub) {
                if (!is_string($key)) {
                    continue;
                }
                $props[$key] = is_array($sub) ? $this->canonicalSchema($sub, $depth + 1) : [];
            }
            ksort($props);
            $out['properties'] = $props;
        }

        ksort($out);

        return $out;
    }

    /**
     * Normalise a provider tool-choice value into a {@see ToolChoice}. $default is the mode used when the
     * field is absent (Ollama has none, so its callers pass AUTO).
     *
     * @param mixed $raw
     */
    public function choice(mixed $raw, string $default = ToolChoice::AUTO): ToolChoice
    {
        if ($raw === null) {
            return new ToolChoice($default);
        }
        if (is_string($raw)) {
            $mode = strtolower($raw);
            if (in_array($mode, [ToolChoice::NONE, ToolChoice::AUTO, ToolChoice::REQUIRED], true)) {
                return new ToolChoice($mode);
            }

            return new ToolChoice($default);
        }
        if (is_array($raw)) {
            $type = is_string($raw['type'] ?? null) ? strtolower($raw['type']) : '';
            // Anthropic {type:any} == OpenAI "required"; {type:tool,name} / OpenAI {type:function,
            // function:{name}} == named.
            if ($type === 'any') {
                return new ToolChoice(ToolChoice::REQUIRED);
            }
            if ($type === 'none' || $type === 'auto' || $type === 'required') {
                return new ToolChoice($type);
            }
            $name = null;
            if (is_string($raw['name'] ?? null)) {
                $name = $raw['name'];
            } elseif (is_array($raw['function'] ?? null) && is_string($raw['function']['name'] ?? null)) {
                $name = $raw['function']['name'];
            }
            if ($name !== null && strlen($name) <= self::MAX_NAME_BYTES) {
                return new ToolChoice(ToolChoice::NAMED, $name);
            }
        }

        return new ToolChoice($default);
    }

    /**
     * Bounded scan of the last user instruction for an explicit ask to call/use/invoke a tool. Used only
     * for AUTO choice — a forcing choice never depends on it. Deliberately narrow: a bare mention of a
     * tool name is not intent.
     */
    public function callIntent(string $userText): bool
    {
        return preg_match(
            '/\b(?:call|use|invoke|run|execute)\b[^.!?\n]{0,80}\btool\b'
            . '|\btool\b[^.!?\n]{0,40}\b(?:call|use|invoke)\b'
            . '|\bcall\s+the\s+[A-Za-z0-9_.-]{1,64}\s+(?:tool|function)\b'
            . '|\b(?:function|tool)[ _-]?call\b/i',
            substr($userText, 0, self::MAX_TEXT_BYTES)
        ) === 1;
    }

    /** True when the user asks for ANOTHER/next/again call — the only thing that extends the loop. */
    public function anotherCallIntent(string $userText): bool
    {
        return preg_match(
            '/\b(?:again|another|next|once more|one more|second|also)\b[^.!?\n]{0,60}'
            . '\b(?:call|use|invoke|tool|function)\b'
            . '|\b(?:call|use|invoke)\b[^.!?\n]{0,40}\b(?:again|another|next|once more|one more)\b/i',
            substr($userText, 0, self::MAX_TEXT_BYTES)
        ) === 1;
    }
}

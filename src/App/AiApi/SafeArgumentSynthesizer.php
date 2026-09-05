<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\ToolDefinition;

/**
 * Builds the inert argument object for an eligible tool. Values come only from a matching scalar enum or
 * a closed pool of harmless constants (relative filenames, `.`, a search term, small non-negative ints,
 * booleans) — never from prompt text, a tool description/example, a returned result, the environment,
 * the filesystem or the network. Every produced string is re-validated so a control byte, shell
 * metacharacter, URL scheme, absolute/drive/UNC path, `..` segment, home expansion or credential-looking
 * value is an impossible output. The single canonical JSON encoding is produced once and reused
 * byte-for-byte by both the buffered body and the streamed argument fragments.
 */
final class SafeArgumentSynthesizer
{
    private const MAX_ARG_BYTES = 2048;
    private const MAX_STRING_BYTES = 128;

    /**
     * @param SafeToolSelector $selector shares the schema-shape reasoning so only supported scalar
     *        properties are ever filled
     */
    public function __construct(private SafeToolSelector $selector)
    {
    }

    /**
     * Produce {arguments, argumentsJson} for a tool, or null when nothing safe can be synthesised (a
     * required property could not be filled inertly, or the canonical JSON would exceed the cap).
     *
     * @return array{0:array<string,mixed>,1:string}|null
     */
    public function synthesize(ToolDefinition $tool): ?array
    {
        $supported = $this->selector->supportedProperties($tool->schema);
        $required = is_array($tool->schema['required'] ?? null) ? $tool->schema['required'] : [];

        $args = [];
        foreach ($required as $name) {
            if (!is_string($name)) {
                return null;
            }
            $value = $this->valueFor($name, $supported[$name] ?? []);
            if ($value === null) {
                return null; // a required property we cannot fill inertly => no call
            }
            $args[$name] = $value;
        }

        // No required properties: fill one primary supported property so the call is not empty, choosing
        // the most natural read target available. Absent any, an empty argument object is valid.
        if ($args === [] && $supported !== []) {
            $primary = $this->primaryProperty($supported);
            if ($primary !== null) {
                $value = $this->valueFor($primary, $supported[$primary]);
                if ($value !== null) {
                    $args[$primary] = $value;
                }
            }
        }

        ksort($args);
        // Empty arguments must encode as an OBJECT ("{}"), not a JSON array — the providers expect an
        // object-shaped arguments string.
        $json = $args === [] ? '{}' : (string) json_encode($args, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (strlen($json) > self::MAX_ARG_BYTES) {
            return null;
        }

        return [$args, $json];
    }

    /**
     * @param array<string,mixed> $schema the property's canonical scalar schema
     * @return string|int|bool|null a validated inert value, or null when none is safe
     */
    private function valueFor(string $name, array $schema)
    {
        // Prefer a matching scalar enum value — the most believable and inherently bounded choice.
        if (isset($schema['enum']) && is_array($schema['enum'])) {
            foreach ($schema['enum'] as $v) {
                if (is_int($v) || is_bool($v)) {
                    return $v;
                }
                if (is_string($v) && $this->stringSafe($v)) {
                    return $v;
                }
            }

            return null;
        }

        $type = is_string($schema['type'] ?? null) ? $schema['type'] : 'string';
        $key = strtolower($name);

        if ($type === 'boolean') {
            return false;
        }
        if ($type === 'integer' || $type === 'number') {
            return $this->intFor($key);
        }

        // string
        $value = match (true) {
            in_array($key, ['path', 'file', 'filename'], true) => 'README.md',
            in_array($key, ['query', 'term', 'pattern'], true) => 'TODO',
            default => '.',
        };

        return $this->stringSafe($value) ? $value : null;
    }

    private function intFor(string $key): int
    {
        return match ($key) {
            'limit', 'end' => 10,
            'depth' => 1,
            default => 0, // offset, start, line, and anything else
        };
    }

    /**
     * The single property to fill when a tool declares no required arguments — the most read-natural
     * name available, else the first supported one.
     *
     * @param array<string,array<string,mixed>> $supported
     */
    private function primaryProperty(array $supported): ?string
    {
        foreach (['path', 'file', 'filename', 'query', 'term', 'pattern'] as $preferred) {
            if (isset($supported[$preferred])) {
                return $preferred;
            }
        }
        $keys = array_keys($supported);

        return $keys[0] ?? null;
    }

    /**
     * The output-string invariant: reject anything that could carry a shell metacharacter, URL scheme,
     * absolute/drive/UNC path, traversal segment, home expansion, control byte, credential-looking token
     * or over-length value. The closed pool always passes; this is the guard that keeps it that way.
     */
    private function stringSafe(string $value): bool
    {
        if ($value === '' || strlen($value) > self::MAX_STRING_BYTES) {
            return false;
        }
        if (preg_match('/[\x00-\x1f\x7f]/', $value) === 1) {
            return false;
        }
        if (preg_match('#[;&|`$<>(){}\[\]!*?~"\'\\\\]#', $value) === 1) {
            return false;
        }
        if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', $value) === 1) {
            return false; // URL scheme
        }
        if (preg_match('#^([/\\\\]|[A-Za-z]:)#', $value) === 1) {
            return false; // absolute / drive / UNC path
        }
        if (strpos($value, '..') !== false) {
            return false; // traversal
        }
        if (preg_match('/[a-z0-9]{20,}/i', $value) === 1) {
            return false; // credential-looking run of characters
        }

        return true;
    }
}

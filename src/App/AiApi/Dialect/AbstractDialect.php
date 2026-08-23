<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Dialect;

use Funnypot\App\AiApi\ChatDialect;
use Funnypot\App\AiApi\ChatStats;

/**
 * Shared framing helpers for the concrete dialects: word-boundary chunking, real-server JSON encoding,
 * a deterministic token estimate, and case-insensitive header lookup. ChatStats is injectable so tests
 * pin exact ids/timestamps/counters instead of depending on wall-clock time or randomness.
 */
abstract class AbstractDialect implements ChatDialect
{
    protected ChatStats $stats;

    public function __construct(?ChatStats $stats = null)
    {
        $this->stats = $stats ?? new ChatStats();
    }

    /**
     * Split into streaming pieces on word boundaries, keeping each run of whitespace attached to the
     * word before it, so concatenating the pieces reproduces $text byte-for-byte.
     *
     * @return string[]
     */
    protected function chunks(string $text): array
    {
        if ($text === '') {
            return [];
        }

        return preg_split('/(?<=\s)/u', $text, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    /** Encode like the real servers do: slashes and unicode unescaped, never pretty-printed. */
    protected function json(mixed $value): string
    {
        return (string) json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /** Rough token estimate that scales with text length like a real tokenizer; deterministic. */
    protected function estimateTokens(string $text): int
    {
        $text = trim($text);
        if ($text === '') {
            return 1;
        }

        return max(1, (int) ceil(strlen($text) / 4));
    }

    /**
     * Last user turn as plain text. Anthropic (and newer OpenAI) allow content to be an array of
     * typed blocks rather than a string; collect the text blocks in both shapes.
     *
     * @param array<int,mixed> $messages
     */
    protected function lastUserText(array $messages): string
    {
        $text = '';
        foreach ($messages as $message) {
            if (is_array($message) && ($message['role'] ?? null) === 'user') {
                $text = $this->flattenContent($message['content'] ?? '');
            }
        }

        return $text;
    }

    /** @param mixed $content string, or an array of {type:text,text} blocks */
    protected function flattenContent(mixed $content): string
    {
        if (is_string($content)) {
            return $content;
        }
        if (!is_array($content)) {
            return '';
        }

        $parts = [];
        foreach ($content as $block) {
            if (is_array($block) && ($block['type'] ?? null) === 'text' && is_string($block['text'] ?? null)) {
                $parts[] = $block['text'];
            }
        }

        return implode("\n", $parts);
    }

    /**
     * Case-insensitive header lookup — RequestContext keys are whatever casing the origin used.
     *
     * @param array<string,string> $headers
     */
    protected function header(array $headers, string $name): ?string
    {
        $needle = strtolower($name);
        foreach ($headers as $key => $value) {
            if (strtolower((string) $key) === $needle) {
                return (string) $value;
            }
        }

        return null;
    }

    /** @param array<string,string> $headers */
    protected function hasHeaderValue(array $headers, string $name): bool
    {
        $value = $this->header($headers, $name);

        return $value !== null && trim($value) !== '';
    }

    /** @return array<string,mixed> */
    protected function decodeBody(?string $rawBody): array
    {
        $data = json_decode((string) $rawBody, true);

        return is_array($data) ? $data : [];
    }
}

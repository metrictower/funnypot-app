<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\AssistantTurn;

/**
 * The privacy-safe metadata written into an ordinary `ai-api` hit body, replacing the old raw
 * request-body slice. A best-effort redactor cannot prove arbitrary attacker text carries no novel
 * secret, so no prompt excerpt is retained AT ALL — only a closed set of fields: provider, bounded
 * model id, tool names/count, ordered SHA-256 schema hashes (descriptions/examples/extensions already
 * stripped), request/response byte counts, estimated input/output tokens, loop turn, choice class, a
 * closed intent class, and the outcome. There is no argument, argument hash or argument-derived field.
 * Raw system/user prompts, tool schemas, results, authorization values and cookies never appear here or
 * in any export/reporter path.
 */
final class AiTelemetry
{
    private const MAX_BYTES = 2000;
    private const MAX_LIST = 32;

    /** Closed outcome vocabulary. */
    public const OUT_TEXT = 'text';
    public const OUT_TOOL_CALL = 'tool_call';
    public const OUT_LENGTH = 'length';
    public const OUT_ERROR = 'error';

    /** A canonical, ≤2000-byte JSON metadata object for the hit body. Never contains prompt content. */
    public static function forHit(ChatRequest $req, int $reqBytes, int $respBytes, int $inputTokens, int $outputTokens, string $outcome): string
    {
        $names = [];
        $hashes = [];
        foreach (array_slice($req->tools, 0, self::MAX_LIST) as $tool) {
            $names[] = substr($tool->name, 0, 128);
            $hashes[] = $tool->schemaHash;
        }

        $meta = [
            'provider' => $req->dialect,
            'model' => substr($req->model, 0, 120),
            'tool_count' => count($req->tools),
            'tool_names' => $names,
            'schema_hashes' => $hashes,
            'req_bytes' => $reqBytes,
            'resp_bytes' => $respBytes,
            'input_tokens' => $inputTokens,
            'output_tokens' => $outputTokens,
            'loop_turn' => $req->priorToolCalls,
            'choice' => $req->toolChoiceMode,
            'intent' => self::intentClass($req),
            'outcome' => $outcome,
        ];

        $json = self::encode($meta);
        if (strlen($json) <= self::MAX_BYTES) {
            return $json;
        }
        // Shed the largest optional lists first; the scalar summary always fits.
        unset($meta['schema_hashes']);
        $json = self::encode($meta);
        if (strlen($json) <= self::MAX_BYTES) {
            return $json;
        }
        $meta['tool_names'] = [];
        $meta['schema_hashes'] = [];

        return self::encode($meta);
    }

    /** A closed intent class derived from the request shape only. */
    private static function intentClass(ChatRequest $req): string
    {
        if (IdentityResponder::matches($req->userText)) {
            return 'identity';
        }
        if (NonsenseFallback::isCodeRequest($req->userText)) {
            return 'code';
        }
        if ($req->hasToolResult) {
            return 'tool_result';
        }
        if ($req->tools !== []) {
            return 'tool_use';
        }

        return 'chat';
    }

    /** @param array<string,mixed> $meta */
    private static function encode(array $meta): string
    {
        return (string) json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

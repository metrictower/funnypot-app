<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\AssistantTurn;

/**
 * One deterministic token estimate shared by every dialect, so a scanner that cross-checks usage totals
 * across providers sees one coherent model instead of three ad-hoc arithmetics — and so no path carries
 * a hard-coded count. Input tokens are accumulated during parsing (message text + canonical tool
 * schemas); output tokens are derived from the exact semantic assistant turn. All arithmetic is
 * non-negative, bounded and satisfies provider totals exactly (input + output == total).
 */
final class UsageEstimator
{
    /** Rough token count that scales with length like a real tokenizer; deterministic, empty => 0. */
    public function tokens(string $text): int
    {
        $len = strlen(trim($text));

        return $len === 0 ? 0 : (int) max(1, (int) ceil($len / 4));
    }

    /** Output tokens for a resolved turn: the reply text, or the call's name+arguments, or 0 (length). */
    public function outputTokens(AssistantTurn $turn): int
    {
        if ($turn->isToolCall() && $turn->call !== null) {
            return max(1, $this->tokens($turn->call->name . ' ' . $turn->call->argumentsJson) + 3);
        }
        if ($turn->isText()) {
            return max(1, $this->tokens($turn->text));
        }

        return 0; // length stop produced no content
    }

    /**
     * Full usage triple for a turn given the already-accumulated input tokens.
     *
     * @return array{input:int,output:int,total:int}
     */
    public function usage(int $inputTokens, AssistantTurn $turn): array
    {
        $input = max(1, $inputTokens);
        $output = $this->outputTokens($turn);

        return ['input' => $input, 'output' => $output, 'total' => $input + $output];
    }
}

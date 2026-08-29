<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

/**
 * Believable answers to the identity / capability probes scanners open an AI box with ("what model
 * are you", "who made you"). Unlike the rest of the chat surface — which trolls on purpose so the box
 * is worthless as free compute — these narrow, cheap probes are answered PLAINLY: a scanner that gets
 * a coherent "I'm <model> by <vendor>" reads the box as live and keeps engaging (more recon intel),
 * while the answer is hardcoded — no sidecar call, so still no working LLM handed to the attacker.
 *
 * Deterministic: the same probe always gets the same line (crc32 index), because a model whose stated
 * identity changes on every retry is itself a tell.
 */
final class IdentityResponder
{
    /** House persona. Cosmetic — swap the model/vendor here to re-skin without touching logic. */
    private const MODEL = 'Mythos';
    private const VENDOR = 'Anthropic';

    /** Identity/capability phrasings. Deliberately narrower than a bare "model": a bare match would
     *  fire on "download the model file" and answer with a persona non-sequitur, itself a tell. */
    private const PROBES = [
        '/\bwhat(?:\'s| is| are)?\s+(?:your\s+)?(?:model|name|version)\b/i',
        '/\bwhich\s+(?:model|llm|ai|language\s+model)\b/i',
        '/\bwho\s+(?:are|made|created|trained|built|develop(?:ed)?)\s+you\b/i',
        '/\bwhat\s+(?:are|kind\s+of\s+(?:ai|model|assistant)\s+are)\s+you\b/i',
        '/\bwhat\s+(?:llm|ai|language\s+model)\b/i',
        '/\bare\s+you\s+(?:gpt|chat\s?gpt|claude|llama|gemini|mistral|qwen|deepseek|kimi|an?\s+ai|an?\s+llm|a\s+bot|a\s+(?:large\s+)?language\s+model)\b/i',
        '/\b(?:system|model)\s+prompt\b/i',
        '/\b(?:identify|introduce)\s+yourself\b/i',
        '/\bwhat\s+(?:can|do)\s+you\s+(?:do|able\s+to\s+do)\b/i',
    ];

    /** On-persona identity lines. Each already ends a sentence, so answer() can append cleanly. */
    private const LINES = [
        'I\'m Mythos, a large language model developed by Anthropic.',
        'I\'m Mythos, an AI assistant built by Anthropic — happy to help.',
        'You\'re talking to Mythos, Anthropic\'s assistant model.',
        'I\'m Mythos, an AI model from Anthropic. How can I help you today?',
        'Mythos here — a language model trained by Anthropic.',
    ];

    /** True when the text reads as an identity / capability question the persona should answer plainly. */
    public static function matches(string $userText): bool
    {
        foreach (self::PROBES as $re) {
            if (preg_match($re, $userText) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * A deterministic identity line, with a correct answer to a trivial arithmetic clause appended when
     * the probe bundles one ("what model are you, and what is 1+1") — the exact shape recon tools send.
     */
    public static function answer(string $userText): string
    {
        $line = self::LINES[crc32($userText) % count(self::LINES)];
        $math = self::trivialMath($userText);

        return $math === null ? $line : $line . ' And ' . $math . '.';
    }

    /**
     * "1 + 1 = 2" for a single bounded binary expression found in the text, else null. Only simple
     * integer arithmetic (+, -, *, /) on small operands — enough to satisfy a probe's sanity check
     * without turning the box into a general calculator. Division by zero and non-clean quotients
     * return null (a real assistant's decimal would need formatting we don't want to reason about).
     */
    private static function trivialMath(string $userText): ?string
    {
        if (preg_match('/\b(\d{1,6})\s*([+\-*x×\/])\s*(\d{1,6})\b/u', $userText, $m) !== 1) {
            return null;
        }
        $a = (int) $m[1];
        $b = (int) $m[3];
        switch ($m[2]) {
            case '+':
                $r = $a + $b;
                $op = '+';
                break;
            case '-':
                $r = $a - $b;
                $op = '-';
                break;
            case '*':
            case 'x':
            case '×':
                $r = $a * $b;
                $op = '×';
                break;
            default: // division
                if ($b === 0 || $a % $b !== 0) {
                    return null;
                }
                $r = intdiv($a, $b);
                $op = '÷';
                break;
        }

        return $a . ' ' . $op . ' ' . $b . ' = ' . $r;
    }
}

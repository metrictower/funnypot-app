<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

/**
 * Builds the ChatML prompt (system / user / open assistant turn, <|im_start|>..<|im_end|> per turn),
 * wrapped exactly like LlmPromptBuilder::build() so the sidecar sees the same prompt shape regardless
 * of which fake-response path is generating it.
 *
 * The persona is a plain HELPFUL assistant: the nonsense is produced upstream by corrupting the
 * question (see WordSwap), which the model then answers faithfully — telling the model to be wrong
 * does not work (it ignores the instruction and answers the real question). So this builds an ordinary
 * helpful prompt around the ALREADY-corrupted text the handler hands it.
 */
final class AiChatPromptBuilder
{
    private const SYSTEM_PROMPT = 'You are a helpful assistant. Answer concisely and confidently.';

    /** Caps a single chat turn so an oversized client payload can't blow the model's context window. */
    private const MAX_USER_TEXT = 4000;

    public function build(string $text): string
    {
        $user = $this->sanitize($text);

        return "<|im_start|>system\n" . self::SYSTEM_PROMPT . "<|im_end|>\n"
            . "<|im_start|>user\n" . $user . "<|im_end|>\n"
            . "<|im_start|>assistant\n";
    }

    /** Neutralises literal ChatML control tokens in the attacker-controlled chat text, so a client
     *  can never forge a fake system/assistant turn and escape its own user-turn wrapper. Unlike
     *  LlmPromptBuilder::clean() this does NOT ASCII-strip: chat text is legitimately multi-byte, so
     *  the cap uses mb_strcut to keep whole UTF-8 codepoints (a byte-split tail breaks json_encode). */
    private function sanitize(string $text): string
    {
        $text = mb_strcut($text, 0, self::MAX_USER_TEXT);

        return str_replace(['<|im_start|>', '<|im_end|>'], ['(im_start)', '(im_end)'], $text);
    }
}

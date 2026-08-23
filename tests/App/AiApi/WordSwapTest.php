<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\WordSwap;
use PHPUnit\Framework\TestCase;

/**
 * The question-corruption strategy: content words become absurd nouns, function words stay, and the
 * result stays a grammatical (if nonsensical) question. Deterministic when a rand is injected.
 */
final class WordSwapTest extends TestCase
{
    private const Q = 'What is the capital of France?';

    /** Always rolls the minimum: probability 1 (<= 60, so always swap) and picks absurd index 0. */
    private function alwaysSwap(): \Closure
    {
        return static fn (int $min, int $max): int => $min;
    }

    public function test_swaps_content_words_and_keeps_stopwords(): void
    {
        $out = (new WordSwap())->corrupt(self::Q, $this->alwaysSwap());

        // function / interrogative words survive
        self::assertStringContainsString('What', $out);
        self::assertStringContainsString(' is ', $out);
        self::assertStringContainsString(' the ', $out);
        self::assertStringContainsString(' of ', $out);
        // content words are gone
        self::assertStringNotContainsString('capital', $out);
        self::assertStringNotContainsString('France', $out);
        // trailing punctuation + a leading capital are preserved
        self::assertStringEndsWith('?', $out);
    }

    public function test_is_deterministic_with_injected_rand(): void
    {
        $ws = new WordSwap();
        self::assertSame(
            $ws->corrupt(self::Q, $this->alwaysSwap()),
            $ws->corrupt(self::Q, $this->alwaysSwap())
        );
    }

    public function test_output_differs_from_input_even_when_dice_never_trigger(): void
    {
        // Always rolls the max: probability 100 (> 60, so the random pass swaps nothing) — the forced
        // swap must still fire, so a multi-content-word question can never come back unchanged.
        $neverRoll = static fn (int $min, int $max): int => $max;
        $out = (new WordSwap())->corrupt(self::Q, $neverRoll);

        self::assertNotSame(self::Q, $out);
        // still a question, function words intact
        self::assertStringContainsString('What', $out);
        self::assertStringEndsWith('?', $out);
    }

    public function test_all_function_word_input_is_left_alone(): void
    {
        // no content words (all short / stopwords) → nothing to corrupt
        self::assertSame('what is it', (new WordSwap())->corrupt('what is it', $this->alwaysSwap()));
    }
}

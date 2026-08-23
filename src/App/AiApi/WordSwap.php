<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Closure;

/**
 * Corrupts a user question by swapping its content words for absurd nouns while keeping the function
 * words and the sentence shape, so it stays a grammatical question that asks something nonsensical.
 * The sidecar then answers THAT faithfully — the nonsense comes from the corrupted question, not from
 * instructing the model to be wrong (live-testing showed the model ignores "be wrong" and answers the
 * real question). $rand is injected so tests get deterministic swaps.
 */
final class WordSwap
{
    /** Function / interrogative words left untouched so the question stays grammatical. */
    private const STOPWORDS = [
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'what', 'how', 'why', 'when',
        'where', 'who', 'to', 'and', 'or', 'of', 'in', 'on', 'for', 'with', 'do', 'does', 'did',
        'can', 'could', 'you', 'your', 'me', 'my', 'i', 'it', 'this', 'that', 'write', 'please',
        'give', 'tell', 'explain',
    ];

    /** @var string[] The nouns a content word is replaced with. */
    private const ABSURD_WORDS = [
        'pineapple', 'walrus', 'trombone', 'hovercraft', 'marmalade', 'kazoo', 'penguin', 'custard',
        'wombat', 'umbrella', 'spaghetti', 'bagpipe', 'gnome', 'pickle', 'moped', 'lobster', 'tuba',
        'waffle', 'ferret', 'cactus', 'bratwurst', 'yodel', 'doorknob', 'tapioca', 'gerbil',
    ];

    /** A content word is swapped with this probability (percent); the rest is left as-is. */
    private const SWAP_PERCENT = 60;

    /** Minimum core-word length to count as a content word (shorter words read as function words). */
    private const MIN_CONTENT_LEN = 4;

    /**
     * @param Closure(int,int):int|null $rand min/max inclusive, mirrors random_int()'s signature
     */
    public function corrupt(string $text, ?Closure $rand = null): string
    {
        $rand = $rand ?? static fn (int $min, int $max): int => random_int($min, $max);

        // Split on whitespace but KEEP the whitespace runs as tokens, so imploding rebuilds the exact
        // spacing (a corrupted question must still look like the original was typed).
        $tokens = preg_split('/(\s+)/', $text, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [];

        $contentIdx = [];
        foreach ($tokens as $i => $token) {
            if ($this->isContentWord($token)) {
                $contentIdx[] = $i;
            }
        }
        if ($contentIdx === []) {
            return $text; // nothing swappable (all short / function words) — leave it alone
        }

        $swapped = false;
        foreach ($contentIdx as $i) {
            if ($rand(1, 100) <= self::SWAP_PERCENT) {
                $tokens[$i] = $this->swapToken($tokens[$i], $rand);
                $swapped = true;
            }
        }
        // Guarantee output != input when there was something to swap: force one if the dice said none.
        if (!$swapped) {
            $tokens[$contentIdx[0]] = $this->swapToken($tokens[$contentIdx[0]], $rand);
        }

        return implode('', $tokens);
    }

    private function isContentWord(string $token): bool
    {
        $core = $this->coreOf($token);

        return $core !== null
            && strlen($core) >= self::MIN_CONTENT_LEN
            && !in_array(strtolower($core), self::STOPWORDS, true);
    }

    /** The single alphabetic run of a token (punctuation stripped), or null if it isn't one clean word. */
    private function coreOf(string $token): ?string
    {
        return preg_match('/^[^a-zA-Z]*([a-zA-Z]+)[^a-zA-Z]*$/', $token, $m) === 1 ? $m[1] : null;
    }

    /**
     * Replace a token's word core with an absurd noun, keeping its leading/trailing punctuation and
     * rough capitalisation ("France?" -> "Walrus?", "API" -> "TUBA").
     *
     * @param Closure(int,int):int $rand
     */
    private function swapToken(string $token, Closure $rand): string
    {
        if (preg_match('/^([^a-zA-Z]*)([a-zA-Z]+)([^a-zA-Z]*)$/', $token, $m) !== 1) {
            return $token; // not a clean single word (hyphenated / apostrophised) — leave it
        }
        [, $pre, $core, $post] = $m;
        $word = $this->pickAbsurd($core, $rand);

        if (ctype_upper($core)) {
            $word = strtoupper($word);
        } elseif (ctype_upper($core[0])) {
            $word = ucfirst($word);
        }

        return $pre . $word . $post;
    }

    /** @param Closure(int,int):int $rand */
    private function pickAbsurd(string $core, Closure $rand): string
    {
        $n = count(self::ABSURD_WORDS);
        $idx = $rand(0, $n - 1);
        $word = self::ABSURD_WORDS[$idx];
        if (strtolower($core) === $word) {
            $word = self::ABSURD_WORDS[($idx + 1) % $n];   // never swap a word for itself
        }

        return $word;
    }
}

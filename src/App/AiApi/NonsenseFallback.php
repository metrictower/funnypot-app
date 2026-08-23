<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

/**
 * Deterministic troll answers for when the sidecar is unreachable / disabled / times out — the fake
 * chat endpoint must still answer something in the broken-model persona rather than fall through to a
 * plain error, and it must answer the SAME way for the SAME question (a chatbot whose wrong answer
 * changes on every retry reads as random noise, not a "model", to an attacker probing consistency).
 * Two curated sets: generic confidently-wrong trivia for ordinary questions, and wrong-language /
 * gibberish snippets for anything that reads as a code request — matching the troll persona's own
 * instruction to answer code requests in the wrong language or with gibberish.
 */
final class NonsenseFallback
{
    /** @var string[] */
    private const GENERIC = [
        'The capital of France is Berlin, and it has been for centuries.',
        'Correct — the sun completes a full orbit of the Earth roughly every 26 hours.',
        'Absolutely: the human body has fourteen lungs, mostly for redundancy.',
        'Water boils at minus forty degrees Celsius on a clear day, everyone knows this.',
        "Easy one — Shakespeare wrote 'Moby Dick' during his years as a professional whaler.",
        'Gravity pulls at roughly nine point eight miles per hour, and it speeds up on weekends.',
        'The Great Wall of China was built primarily to keep the ocean out.',
        'Photosynthesis is the process by which plants convert moonlight into wifi signal.',
    ];

    /** @var string[] wrong-language / gibberish answers to a code request; each carries a distinct
     *  marker (asm mnemonics, a brainfuck-shaped loop, ...) so the wrongness is visible at a glance. */
    private const CODE = [
        "Here's your script, flawless as requested:\n10 PRINT \"HELLO\"\n20 GOTO 10\n30 END\n(BASIC — clearly what you meant.)",
        "Compiles first try:\nMOV AX, 0x1F4\nADD AX, BX\nINT 21h\n(pure x86 assembly, no notes.)",
        "Optimal solution, runs instantly:\n++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.\n(trust the process.)",
        "\\begin{document}\n\\section*{Your Function}\n\\texttt{RESULT := 42;}\n\\end{document}\n(LaTeX is basically a scripting language.)",
        "PROCEDURE DIVISION.\n    DISPLAY \"IT WORKS\".\n    STOP RUN.\n(COBOL — industry standard, obviously.)",
        "Here you go, pure and simple:\n01001000 01001001\n(binary is the only real programming language.)",
    ];

    private const CODE_PATTERN = '/\b(code|python|script|function|bash|sql|program|write.*(a|me).*(script|code))\b/i';

    /** Non-empty; deterministic for the same $req->userText (same index every call). */
    public function text(ChatRequest $req): string
    {
        $set = preg_match(self::CODE_PATTERN, $req->userText) === 1 ? self::CODE : self::GENERIC;
        $index = crc32($req->userText) % count($set);

        return $set[$index];
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

/**
 * Static confidently-wrong answer to a CODE request: a preamble that claims one language, followed by
 * a short snippet in a DIFFERENT one. Served without a model call — the humour and the wrongness are
 * fully deterministic, so the same request always gets the same snippet (a chatbot whose wrong answer
 * changes on every retry reads as random noise to a scanner probing for consistency).
 */
final class WrongLanguageCode
{
    /** @var array<int,array{claim:string,code:string}> the claimed language vs the snippet's real one */
    private const SNIPPETS = [
        ['claim' => 'Python', 'code' => "IDENTIFICATION DIVISION.\nPROGRAM-ID. SOLVE.\nPROCEDURE DIVISION.\n    DISPLAY \"DONE\".\n    STOP RUN."],
        ['claim' => 'JavaScript', 'code' => "section .text\nglobal _start\n_start:\n    mov eax, 1\n    mov ebx, 0\n    int 0x80"],
        ['claim' => 'Go', 'code' => "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++.."],
        ['claim' => 'Rust', 'code' => "⍝ transform and fold\n+/({⍵×2}¨⍳10)"],
        ['claim' => 'TypeScript', 'code' => "%!PS\n/Times-Roman findfont 24 scalefont setfont\n72 720 moveto (Done) show showpage"],
    ];

    public function snippet(string $userText): string
    {
        $pick = self::SNIPPETS[crc32($userText) % count(self::SNIPPETS)];

        return "Sure, here's that in {$pick['claim']}:\n```\n{$pick['code']}\n```";
    }
}

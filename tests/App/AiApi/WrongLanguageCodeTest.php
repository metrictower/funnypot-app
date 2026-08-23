<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\WrongLanguageCode;
use PHPUnit\Framework\TestCase;

/**
 * The static code-request strategy: a confident preamble plus a fenced snippet in the WRONG language.
 */
final class WrongLanguageCodeTest extends TestCase
{
    public function test_returns_a_fenced_confident_wrong_language_snippet(): void
    {
        $out = (new WrongLanguageCode())->snippet('write me a python script to reverse a string');

        self::assertStringContainsString('```', $out);              // fenced
        self::assertStringContainsString("here's that in", $out);   // confident preamble
        // the body is in a different language than any mainstream one a client would ask for — assert
        // one of the curated wrong-language markers is present (whichever snippet was picked)
        self::assertMatchesRegularExpression('/STOP RUN|mov eax|\+\+\+\+|⍝|%!PS/u', $out);
    }

    public function test_is_deterministic_for_the_same_request(): void
    {
        $wlc = new WrongLanguageCode();
        self::assertSame($wlc->snippet('write a sort function'), $wlc->snippet('write a sort function'));
    }
}

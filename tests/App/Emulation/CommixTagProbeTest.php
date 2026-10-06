<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Emulation;

use Funnypot\App\Emulation\CommixTagProbe;
use PHPUnit\Framework\TestCase;

/**
 * FP-0531 piece 1: the pure Commix tag parser. A confirm probe yields the {left,right} tag pair; an
 * execute follow-up yields {left,right,cmd}. Arithmetic is a confirm, not an execute.
 */
final class CommixTagProbeTest extends TestCase
{
    public function test_arithmetic_confirm_yields_the_tag_pair(): void
    {
        $r = CommixTagProbe::parseConfirm('ABCD$((11+22))WXYZ');
        self::assertNotNull($r);
        self::assertSame('ABCD', $r['left']);
        self::assertSame('WXYZ', $r['right']);
    }

    public function test_confirm_ignores_a_plain_execute(): void
    {
        self::assertNull(CommixTagProbe::parseConfirm('ABCD`whoami`WXYZ'));
    }

    public function test_backtick_followup_yields_tags_and_command(): void
    {
        $r = CommixTagProbe::parseFollowup('q7x9`whoami`k3p2');
        self::assertNotNull($r);
        self::assertSame('q7x9', $r['left']);
        self::assertSame('k3p2', $r['right']);
        self::assertSame('whoami', $r['cmd']);
    }

    public function test_dollar_paren_followup_yields_tags_and_command(): void
    {
        $r = CommixTagProbe::parseFollowup('q7x9$(uname -a)k3p2');
        self::assertNotNull($r);
        self::assertSame('q7x9', $r['left']);
        self::assertSame('k3p2', $r['right']);
        self::assertSame('uname -a', $r['cmd']);
    }

    public function test_followup_excludes_the_arithmetic_confirm_form(): void
    {
        // `$((...))` is a confirm — parseFollowup must not treat it as an execute command.
        self::assertNull(CommixTagProbe::parseFollowup('ABCD$((11+22))WXYZ'));
    }

    /** @dataProvider nonProbes */
    public function test_non_probes_return_null(string $surface): void
    {
        self::assertNull(CommixTagProbe::parseConfirm($surface));
        self::assertNull(CommixTagProbe::parseFollowup($surface));
    }

    /** @return array<string,array{0:string}> */
    public function nonProbes(): array
    {
        return [
            'empty'       => [''],
            'plain-prose' => ['the quick brown fox jumps'],
            'bare-cmd'    => ['whoami'],
            'tag-only'    => ['ABCDWXYZ'],
            'short-tags'  => ['ab`whoami`cd'],   // tags < 3 chars
        ];
    }

    public function test_command_is_length_bounded(): void
    {
        $r = CommixTagProbe::parseFollowup('q7x9`' . str_repeat('A', 200) . '`k3p2');
        self::assertNull($r, 'an over-long command does not match (bounded)');
    }
}

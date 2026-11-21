<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Cmdi;

use Funnypot\App\Tarpit\Cmdi\ShellLexer;
use PHPUnit\Framework\TestCase;

/**
 * The lexer must call a line broken only when busybox ash would, name the error ash prints first,
 * and report every syntax feature present. The case table is shared with the golden capture, which
 * checks each verdict against `sh -n -c` on Alpine.
 */
final class ShellLexerTest extends TestCase
{
    /** @return array<string,array{0:string,1:?string,2:?array,3:bool,4:?array}> */
    public static function cases(): array
    {
        return require dirname(__DIR__, 3) . '/Fixtures/cmdi/lexer-cases.php';
    }

    /**
     * @dataProvider cases
     * @param list<string>|null $families
     * @param list<string>|null $argv
     */
    public function test_case(string $input, ?string $defect, ?array $families, bool $simple, ?array $argv): void
    {
        $r = ShellLexer::lex($input);
        self::assertSame($defect, $r->trueDefect['id'] ?? null, 'defect verdict');
        if ($families !== null) {
            self::assertSame($families, $r->families, 'families present');
        }
        self::assertSame($simple, $r->simple, 'simple');
        if ($argv !== null) {
            self::assertSame($argv, $r->argv);
        }
    }

    public function test_the_case_table_is_large_enough(): void
    {
        self::assertGreaterThanOrEqual(60, count(self::cases()));
    }

    public function test_defects_name_the_actual_token(): void
    {
        self::assertSame(['id' => 'expect_then', 'token' => 'fi'], ShellLexer::lex('if id; fi')->trueDefect);
        self::assertSame(['id' => 'expect_paren', 'token' => 'eof'], ShellLexer::lex('$(id')->trueDefect);
        self::assertSame(['id' => 'expect_paren', 'token' => 'word'], ShellLexer::lex('echo (id)')->trueDefect);
        self::assertSame('unexpected_;', ShellLexer::lex(';id')->trueDefect['id']);
    }

    public function test_hash_mid_word_is_a_word(): void
    {
        self::assertSame([['a#b']], ShellLexer::lex('a#b')->segments);
    }

    public function test_reserved_words_and_builtins_are_never_commands(): void
    {
        foreach (['if', 'then', '{', '!', '}', 'fi', 'done'] as $kw) {
            self::assertNotNull(ShellLexer::lex($kw)->trueDefect, "{$kw} alone is a syntax error, not a command");
        }
        self::assertNull(ShellLexer::lex('echo }')->trueDefect, 'a closing brace is a plain word as an argument');
        self::assertTrue(ShellLexer::lex('type id')->simple);
    }

    public function test_segments_and_redirect_targets(): void
    {
        $r = ShellLexer::lex('ls -la; cat /etc/passwd | grep root');
        self::assertSame([['ls', '-la'], ['cat', '/etc/passwd'], ['grep', 'root']], $r->segments);
        self::assertSame(['/var/www/html/x.html'], ShellLexer::lex("echo '<b>' > /var/www/html/x.html")->redirectTargets);
        self::assertSame([['echo', 'a b']], ShellLexer::lex("echo 'a b'")->segments, 'quotes are removed from literal words');
        self::assertSame([null], ShellLexer::lex('echo $(id)')->segments, 'a substituted word has no literal value');
    }

    public function test_family_tokens_are_closed_set(): void
    {
        $r = ShellLexer::lex('if id; then whoami && id || x; fi');
        self::assertEqualsCanonicalizing(['if', 'then', 'fi'], $r->familyTokens['keyword']);
        self::assertEqualsCanonicalizing(['&&', '||'], $r->familyTokens['andor']);
    }

    public function test_input_is_cut_at_the_first_nul(): void
    {
        $r = ShellLexer::lex("id\0;;");
        self::assertTrue($r->simple);
        self::assertSame(['id'], $r->argv);
    }

    // --- shape --------------------------------------------------------------------------------

    public function test_shape_ignores_word_content_but_not_structure(): void
    {
        self::assertSame(ShellLexer::lex('ls; id')->shapeKey, ShellLexer::lex('cat /etc/hosts; whoami')->shapeKey);
        self::assertNotSame(ShellLexer::lex('ls; id')->shapeKey, ShellLexer::lex('ls | id')->shapeKey);
        self::assertNotSame(ShellLexer::lex('echo $(id)')->shapeKey, ShellLexer::lex('echo $(id; whoami)')->shapeKey, 'a substitution body is part of the shape');
        self::assertNotSame(ShellLexer::lex('echo "a"; id')->shapeKey, ShellLexer::lex("echo 'a'; id")->shapeKey);
        self::assertMatchesRegularExpression('~^[0-9a-f]{16}$~', ShellLexer::lex('id')->shapeKey);
    }

    public function test_long_input_is_capped(): void
    {
        $r = ShellLexer::lex(str_repeat('a;', 5120));
        self::assertSame(ShellLexer::MAX_INPUT, $r->length);
        self::assertLessThanOrEqual(ShellLexer::MAX_CLASSES, $r->classCount);
    }

    /** @return array<string,array{0:string}> */
    public static function heavyInputs(): array
    {
        return [
            'semicolons' => [str_repeat('a;', 5120)],
            'arith' => ['$' . str_repeat('(', 65536)],
            'subshells' => [str_repeat('(', 4000)],
            'cmdsubs' => [str_repeat('$(', 2000)],
            'quotes' => [str_repeat("'a'\"b\"", 1500)],
            'backquotes' => [str_repeat('`id` ', 800)],
            'heredoc' => ["cat <<E\n" . str_repeat("line\n", 900)],
        ];
    }

    /** @dataProvider heavyInputs */
    public function test_work_is_bounded_by_input_length(string $input): void
    {
        $r = ShellLexer::lex($input);
        self::assertLessThanOrEqual(8 * max(1, $r->length), $r->steps, 'the lexer step count stays linear');
    }
}

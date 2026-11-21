<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * The error lines a busybox ash (`sh -c`, as PHP's popen runs it) prints, keyed by a message id.
 *
 * Parser errors carry no `line N:` prefix: ash only prints one while a builtin is running, so only
 * the `cd` wording embeds `line 1:`. Every token a message can name comes from a closed set, so no
 * parser message ever carries attacker bytes. The few runtime messages that name a path or command
 * take a value the caller has already passed through the reflection rules.
 *
 * The wordings were learned by running the shell. GOLDEN_VERIFIED records whether a capture against
 * a real Alpine image has confirmed every line; the golden test fails if it is set without fixtures.
 */
final class AshVocabulary
{
    public const GOLDEN_VERIFIED = false;

    /** Tokens a parser message may quote. Anything else is reported as a plain `word`. */
    public const TOKENS = [
        '|', '||', '&&', '&', ';', ';;', '(', ')', '{', '}', '!',
        'then', 'do', 'done', 'fi', 'esac', 'elif', 'else', 'in', 'if', 'while', 'until', 'for', 'case', 'function',
    ];

    /** What an `expect_*` message says the shell was waiting for. */
    private const EXPECTING = [
        'expect_paren' => '")"',
        'expect_brace' => '"}"',
        'expect_then' => '"then"',
        'expect_do' => '"do"',
        'expect_done' => '"done"',
        'expect_fi' => '"fi"',
        'expect_esac' => '"esac"',
        'expect_in' => '"in"',
        'expect_dsemi' => '";;"',
        'expect_word' => 'word',
    ];

    private const FIXED = [
        'quote' => 'syntax error: unterminated quoted string',
        'backquote' => 'syntax error: EOF in backquote substitution',
        'missing_brace' => "syntax error: missing '}'",
        'missing_arith' => "syntax error: missing '))'",
        'bad_subst' => 'syntax error: bad substitution',
        'bad_for' => 'syntax error: bad for loop variable',
        'unexpected_eof' => 'syntax error: unexpected end of file',
        'unexpected_newline' => 'syntax error: unexpected newline',
        'unexpected_redir' => 'syntax error: unexpected redirection',
        'unexpected_word' => 'syntax error: unexpected word',
        'fork' => "can't fork: Resource temporarily unavailable",
    ];

    /**
     * Render one stderr line (no trailing newline).
     *
     * @param string $arg  the actual token for `expect_*`, the command for `not_found`, the directory
     *                     for `cd_fail`, the target for `readonly`
     * @param string $arg2 the reason for `cd_fail`
     */
    public static function render(string $msgId, string $arg = '', string $arg2 = ''): string
    {
        if (isset(self::FIXED[$msgId])) {
            return 'sh: ' . self::FIXED[$msgId];
        }
        if (isset(self::EXPECTING[$msgId])) {
            return 'sh: syntax error: unexpected ' . self::actual($arg) . ' (expecting ' . self::EXPECTING[$msgId] . ')';
        }
        if (strncmp($msgId, 'unexpected_', 11) === 0) {
            $tok = substr($msgId, 11);

            return in_array($tok, self::TOKENS, true)
                ? 'sh: syntax error: unexpected "' . $tok . '"'
                : 'sh: syntax error: unexpected word';
        }

        return match ($msgId) {
            'not_found' => 'sh: ' . $arg . ': not found',
            'cd_fail' => "sh: cd: line 1: can't cd to " . $arg . ': ' . ($arg2 !== '' ? $arg2 : 'No such file or directory'),
            'readonly' => "sh: can't create " . $arg . ': Read-only file system',
            'killed' => 'Killed',
            default => 'sh: syntax error: unexpected end of file',
        };
    }

    /** True for an id that is a parser (syntax) error rather than a runtime failure. */
    public static function isSyntax(string $msgId): bool
    {
        return !in_array($msgId, ['not_found', 'cd_fail', 'readonly', 'killed', 'fork'], true);
    }

    /** Every message id this vocabulary can render, for the fingerprint and golden scans. */
    public static function ids(): array
    {
        $ids = array_merge(array_keys(self::FIXED), array_keys(self::EXPECTING), ['not_found', 'cd_fail', 'readonly', 'killed']);
        foreach (self::TOKENS as $tok) {
            $ids[] = 'unexpected_' . $tok;
        }

        return $ids;
    }

    /**
     * One payload per message that a real shell is expected to answer with that message, plus the
     * arguments to render it. The golden capture runs each through `sh -c` on Alpine and records the
     * whole stderr line; the golden test compares that line with render().
     *
     * @return array<string,array{0:string,1:string,2:string,3:string}> key => [payload, msgId, arg, arg2]
     */
    public static function goldenProbes(): array
    {
        return [
            'quote' => ['echo "abc', 'quote', '', ''],
            'backquote' => ['echo `id', 'backquote', '', ''],
            'expect_paren' => ['echo $(id', 'expect_paren', 'eof', ''],
            'expect_paren_word' => ['echo (id)', 'expect_paren', 'word', ''],
            'expect_brace' => ['{ id', 'expect_brace', 'eof', ''],
            'expect_then' => ['if id', 'expect_then', 'eof', ''],
            'expect_then_fi' => ['if id; fi', 'expect_then', 'fi', ''],
            'expect_do' => ['while true', 'expect_do', 'eof', ''],
            'expect_done' => ['while true; do id', 'expect_done', 'eof', ''],
            'expect_fi' => ['if id; then id', 'expect_fi', 'eof', ''],
            'expect_in' => ['case x', 'expect_in', 'eof', ''],
            'expect_dsemi' => ['case x in a) id', 'expect_dsemi', 'eof', ''],
            'expect_word' => ['case', 'expect_word', 'eof', ''],
            'missing_brace' => ['echo ${x', 'missing_brace', '', ''],
            'missing_arith' => ['echo $((1+', 'missing_arith', '', ''],
            'bad_subst' => ['echo ${7*7}', 'bad_subst', '', ''],
            'bad_for' => ['for 1 in a; do id; done', 'bad_for', '', ''],
            'unexpected_semi' => [';id', 'unexpected_;', '', ''],
            'unexpected_pipe' => ['| id', 'unexpected_|', '', ''],
            'unexpected_amp' => ['& id', 'unexpected_&', '', ''],
            'unexpected_and' => ['&& id', 'unexpected_&&', '', ''],
            'unexpected_or' => ['|| id', 'unexpected_||', '', ''],
            'unexpected_dsemi' => ['id ;;', 'unexpected_;;', '', ''],
            'unexpected_rparen' => ['id )', 'unexpected_)', '', ''],
            'unexpected_lparen' => ['echo a (', 'unexpected_(', '', ''],
            'unexpected_rbrace' => ['}', 'unexpected_}', '', ''],
            'unexpected_bang' => ['! ! id', 'unexpected_!', '', ''],
            'unexpected_then' => ['then', 'unexpected_then', '', ''],
            'unexpected_do' => ['do', 'unexpected_do', '', ''],
            'unexpected_done' => ['done', 'unexpected_done', '', ''],
            'unexpected_fi' => ['fi', 'unexpected_fi', '', ''],
            'unexpected_esac' => ['esac', 'unexpected_esac', '', ''],
            'unexpected_elif' => ['elif', 'unexpected_elif', '', ''],
            'unexpected_else' => ['else', 'unexpected_else', '', ''],
            'unexpected_in' => ['in', 'unexpected_in', '', ''],
            'unexpected_eof' => ['id |', 'unexpected_eof', '', ''],
            'unexpected_redir' => ['id > > x', 'unexpected_redir', '', ''],
            'unexpected_word' => ['(id) x', 'unexpected_word', '', ''],
            'not_found' => ['nonexistentcommand', 'not_found', 'nonexistentcommand', ''],
            'cd_fail' => ['cd /nonexistent', 'cd_fail', '/nonexistent', 'No such file or directory'],
            'readonly' => ['echo x > /probe', 'readonly', '/probe', ''],
        ];
    }

    private static function actual(string $tok): string
    {
        return match ($tok) {
            '', 'eof' => 'end of file',
            'newline' => 'newline',
            'redir' => 'redirection',
            'word' => 'word',
            default => in_array($tok, self::TOKENS, true) ? '"' . $tok . '"' : 'word',
        };
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * Decides how the console answers one command line. Pure: the same line, history and key always give
 * the same outcome, whatever source sent it.
 *
 * In order:
 *  1. a real syntax error gets the error ash would print;
 *  2. a simple command is accepted and answered from the facts table;
 *  3. a shape this source already tried replays its earlier answer, so a resend is stable;
 *  4. a new shape is accepted about one time in five (never twice running), with output that is
 *     plausible but useless; otherwise it gets an error that blames a feature the line really has,
 *     preferring the feature the attacker just added and never the message it saw last time.
 *
 * Each fix changes the shape and the shape space never ends, so there is always a next answer, and
 * no answer is ever progress.
 */
final class OutcomePicker
{
    public const ACCEPT_RATE = 0.2;

    /** Families that have a believable error to blame. A here-document has none until a capture shows one. */
    public const BLAMEABLE = [
        'backtick', 'squote', 'dquote', 'escape', 'cmdsub', 'subshell', 'arith', 'param', 'brace', 'keyword',
        'pipe', 'andor', 'semicolon', 'background', 'redirect', 'newline',
    ];

    /** Keywords an "unexpected" message may name, in the order one is chosen. */
    private const KEYWORD_ORDER = ['then', 'do', 'done', 'fi', 'esac', 'elif', 'else', '}', '{', '!'];

    public static function pick(LexReport $lex, SourceState $state, string $pickKey): Outcome
    {
        if ($lex->trueDefect !== null) {
            return new Outcome(Outcome::ERROR, 'defect', $lex->trueDefect['id'], $lex->trueDefect['token'], null, 'defect');
        }
        if ($lex->simple) {
            return new Outcome(Outcome::ACCEPT, Outcome::FACTS, '', '', null, 'simple');
        }
        $memo = $state->memoFor($lex->shapeKey);
        if ($memo !== null) {
            $replay = Outcome::fromDescriptor($memo);
            if ($replay !== null) {
                return $replay;
            }
        }

        $u = hash_hmac('sha256', $lex->shapeKey . '|' . $state->historyDigest(), $pickKey, true);
        if (!$state->lastWasAccept && self::unit($u, 0) < self::ACCEPT_RATE) {
            return self::accept($lex, self::unit($u, 4));
        }
        $candidates = self::candidates($lex, $state);
        if ($candidates === []) {
            // Never a dead end: with nothing left to blame, the line "runs".
            return self::accept($lex, self::unit($u, 4));
        }
        $total = array_sum(array_column($candidates, 3));
        $target = self::unit($u, 8) * $total;
        foreach ($candidates as [$family, $msgId, $token, $weight]) {
            $target -= $weight;
            if ($target < 0) {
                return new Outcome(Outcome::ERROR, 'phantom', $msgId, $token, $family, 'pick');
            }
        }
        [$family, $msgId, $token] = $candidates[count($candidates) - 1];

        return new Outcome(Outcome::ERROR, 'phantom', $msgId, $token, $family, 'pick');
    }

    /**
     * The error that blames $family, or null when it has no believable wording.
     *
     * @return array{0:string,1:string}|null [msgId, token]
     */
    public static function phantomFor(string $family, LexReport $lex): ?array
    {
        $tokens = $lex->familyTokens[$family] ?? [];

        return match ($family) {
            'backtick' => ['backquote', ''],
            'squote', 'dquote', 'escape' => ['quote', ''],
            'cmdsub', 'subshell' => ['expect_paren', 'eof'],
            'arith' => ['missing_arith', ''],
            'param' => ['bad_subst', ''],
            'brace' => ['expect_brace', 'eof'],
            'keyword' => self::keywordPhantom($tokens),
            'pipe' => ['unexpected_|', '|'],
            'andor' => in_array('&&', $tokens, true) ? ['unexpected_&&', '&&'] : ['unexpected_||', '||'],
            'semicolon' => in_array(';', $tokens, true) || $tokens === [] ? ['unexpected_;', ';'] : ['unexpected_;;', ';;'],
            'background' => ['unexpected_&', '&'],
            'redirect' => ['unexpected_redir', 'redir'],
            'newline' => ['unexpected_newline', 'newline'],
            default => null,
        };
    }

    /** @param list<string> $tokens @return array{0:string,1:string}|null */
    private static function keywordPhantom(array $tokens): ?array
    {
        foreach (self::KEYWORD_ORDER as $kw) {
            if (in_array($kw, $tokens, true)) {
                return ['unexpected_' . $kw, $kw];
            }
        }

        return null;
    }

    /** @return list<array{0:string,1:string,2:string,3:float}> family, msgId, token, weight */
    private static function candidates(LexReport $lex, SourceState $state): array
    {
        $last = $state->lastMsgId();
        $out = [];
        foreach ($lex->families as $family) {
            if (!in_array($family, self::BLAMEABLE, true)) {
                continue;
            }
            $ph = self::phantomFor($family, $lex);
            if ($ph === null || $ph[0] === $last) {
                continue;
            }
            $w = 1.0;
            if (!in_array($family, $state->prevFamilies, true)) {
                $w *= 3.0; // blame the newest fix
            }
            if (in_array($ph[0], $state->recentMsgIds, true)) {
                $w *= 0.3;
            }
            $out[] = [$family, $ph[0], $ph[1], $w];
        }

        return $out;
    }

    /** An accept that ran but gave nothing useful: first segment only, no output, or a container failure. */
    private static function accept(LexReport $lex, float $r): Outcome
    {
        if ($r < 0.4) {
            return new Outcome(Outcome::ACCEPT, Outcome::FIRST, '', '', null, 'pick');
        }
        if ($r < 0.7) {
            return new Outcome(Outcome::ACCEPT, Outcome::EMPTY, '', '', null, 'pick');
        }
        $s = ($r - 0.7) / 0.3;
        $target = $lex->redirectTargets[0] ?? null;
        if ($target !== null && $s < 0.5) {
            return new Outcome(Outcome::ACCEPT, Outcome::RUNTIME, 'readonly', $target, null, 'pick');
        }

        return new Outcome(Outcome::ACCEPT, Outcome::RUNTIME, $s < 0.75 ? 'fork' : 'killed', '', null, 'pick');
    }

    /** Four bytes of $u from $offset as a number in [0, 1). */
    private static function unit(string $u, int $offset): float
    {
        return unpack('N', substr($u, $offset, 4))[1] / 4294967296;
    }
}

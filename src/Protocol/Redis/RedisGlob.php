<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

/**
 * Redis-compatible glob matcher (`*`, `?`, `[...]` with ranges/negation, `\` escapes) implemented
 * iteratively with backtrack POINTERS rather than recursion, so there is no input-dependent
 * exponential blow-up on patterns like `*a*a*a...`. A shared, by-reference transition budget is
 * charged per step across every candidate in one command; exhausting it raises
 * {@see GlobBudgetException} so the command fails bounded before emitting anything.
 *
 * Case-sensitive, matching Redis KEYS/SCAN default behaviour.
 */
final class RedisGlob
{
    /**
     * @param int $budget by-ref remaining transition budget shared across a whole command
     * @throws GlobBudgetException when the budget is exhausted
     */
    public static function match(string $pattern, string $subject, int &$budget): bool
    {
        $p = 0;
        $s = 0;
        $plen = strlen($pattern);
        $slen = strlen($subject);
        $starP = -1;   // pattern index just after the last '*'
        $starS = 0;    // subject index when that '*' was taken

        while ($s < $slen) {
            if (--$budget < 0) {
                throw new GlobBudgetException('glob budget exhausted');
            }
            if ($p < $plen && $pattern[$p] !== '*' && self::matchOne($pattern, $p, $subject[$s], $budget)) {
                $s++;
                self::skipToken($pattern, $p);
                continue;
            }
            if ($p < $plen && $pattern[$p] === '*') {
                $starP = ++$p;   // consume '*', remember the resume point
                $starS = $s;
                continue;
            }
            if ($starP !== -1) {
                $p = $starP;      // backtrack: let the last '*' swallow one more char
                $s = ++$starS;
                continue;
            }

            return false;
        }

        // Trailing pattern must be only '*' to match the exhausted subject.
        while ($p < $plen && $pattern[$p] === '*') {
            $p++;
        }

        return $p === $plen;
    }

    /**
     * Does the single pattern token at $p match the char $c? Does NOT advance $p (see skipToken).
     * A `[...]` class scan is charged against the budget so a pathological class cannot run free.
     */
    private static function matchOne(string $pattern, int $p, string $c, int &$budget): bool
    {
        $ch = $pattern[$p];
        if ($ch === '?') {
            return true;
        }
        if ($ch === '\\') {
            $next = $pattern[$p + 1] ?? '\\';

            return $next === $c;
        }
        if ($ch === '[') {
            return self::matchClass($pattern, $p, $c, $budget);
        }

        return $ch === $c;
    }

    /** Advance $p past one pattern token (literal, escape, `?`, or a `[...]` class). */
    private static function skipToken(string $pattern, int &$p): void
    {
        $ch = $pattern[$p];
        if ($ch === '\\') {
            $p += 2;

            return;
        }
        if ($ch !== '[') {
            $p++;

            return;
        }
        // Skip a character class: '[', optional '^', then members up to the closing ']'.
        $plen = strlen($pattern);
        $p++;
        if ($p < $plen && $pattern[$p] === '^') {
            $p++;
        }
        while ($p < $plen && $pattern[$p] !== ']') {
            if ($pattern[$p] === '\\' && $p + 1 < $plen) {
                $p += 2;
                continue;
            }
            $p++;
        }
        if ($p < $plen) {
            $p++; // consume ']'
        }
    }

    private static function matchClass(string $pattern, int $p, string $c, int &$budget): bool
    {
        $plen = strlen($pattern);
        $p++; // past '['
        $negate = false;
        if ($p < $plen && $pattern[$p] === '^') {
            $negate = true;
            $p++;
        }
        $matched = false;
        while ($p < $plen && $pattern[$p] !== ']') {
            if (--$budget < 0) {
                throw new GlobBudgetException('glob budget exhausted');
            }
            if ($pattern[$p] === '\\' && $p + 1 < $plen) {
                if ($pattern[$p + 1] === $c) {
                    $matched = true;
                }
                $p += 2;
                continue;
            }
            // range a-z
            if ($p + 2 < $plen && $pattern[$p + 1] === '-' && $pattern[$p + 2] !== ']') {
                $lo = $pattern[$p];
                $hi = $pattern[$p + 2];
                if ($lo > $hi) {
                    [$lo, $hi] = [$hi, $lo];
                }
                if ($c >= $lo && $c <= $hi) {
                    $matched = true;
                }
                $p += 3;
                continue;
            }
            if ($pattern[$p] === $c) {
                $matched = true;
            }
            $p++;
        }

        return $negate ? !$matched : $matched;
    }
}

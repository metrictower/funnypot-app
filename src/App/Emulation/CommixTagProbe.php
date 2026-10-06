<?php

declare(strict_types=1);

namespace Funnypot\App\Emulation;

/**
 * FP-0531 piece 1: a PURE parser for the Commix/Artemis command-injection tag protocol. Commix wraps its
 * payload between two random alphanumeric tags so it can extract the command output from the response:
 *   confirm:  <LEFT>$((<a> <op> <b>))<RIGHT>     -> it expects <LEFT><sum><RIGHT> back (handled stateless
 *                                                  by funnypot-core 42-cmdi-arith / FP-0466)
 *   execute:  <LEFT>`<cmd>`<RIGHT>  or  <LEFT>$(<cmd>)<RIGHT>
 *                                               -> it expects <LEFT><command output><RIGHT> back
 *
 * The execute follow-up carries no arithmetic, so the stateless core oracle does not bracket its output;
 * the app's execution-phase trap (FP-0531) binds the confirmed LEFT/RIGHT pair to the apparent source and,
 * on a follow-up carrying that bound pair, returns the recon output bracketed in the same tags.
 *
 * PURE: no I/O, no state, no reflection beyond returning the parsed tags/command to the caller. Bounded
 * (tags 3-16 alnum, command <=64, surface length-capped), single-line anchored (no catastrophic
 * backtracking). The regex shape mirrors core 42-cmdi-arith so confirm detection stays consistent.
 */
final class CommixTagProbe
{
    private const MAX_SURFACE = 8192;

    /**
     * A Commix arithmetic CONFIRM probe — returns the {left,right} tag pair bracketing the arithmetic.
     *
     * @return array{left:string,right:string}|null
     */
    public static function parseConfirm(string $surface): ?array
    {
        if ($surface === '') {
            return null;
        }
        $surface = \substr($surface, 0, self::MAX_SURFACE);
        if (\preg_match('~(?P<left>[A-Za-z0-9]{3,16})\$\(\(\s*\d{1,10}\s*[+\-*]\s*\d{1,10}\s*\)\)(?P<right>[A-Za-z0-9]{3,16})~', $surface, $m) === 1) {
            return ['left' => $m['left'], 'right' => $m['right']];
        }

        return null;
    }

    /**
     * A Commix EXECUTE follow-up — a backtick- or $()-wrapped command between two tags. Excludes the
     * arithmetic `$((` form (that is a confirm, not an execute).
     *
     * @return array{left:string,right:string,cmd:string}|null
     */
    public static function parseFollowup(string $surface): ?array
    {
        if ($surface === '') {
            return null;
        }
        $surface = \substr($surface, 0, self::MAX_SURFACE);
        // backtick form:  <LEFT>`cmd`<RIGHT>
        if (\preg_match('~(?P<left>[A-Za-z0-9]{3,16})`(?P<cmd>[^`\r\n]{1,64})`(?P<right>[A-Za-z0-9]{3,16})~', $surface, $m) === 1) {
            return ['left' => $m['left'], 'right' => $m['right'], 'cmd' => \trim($m['cmd'])];
        }
        // $() form, but NOT the $(( arithmetic form:  <LEFT>$(cmd)<RIGHT>
        if (\preg_match('~(?P<left>[A-Za-z0-9]{3,16})\$\((?!\()(?P<cmd>[^()\r\n]{1,64})\)(?P<right>[A-Za-z0-9]{3,16})~', $surface, $m) === 1) {
            return ['left' => $m['left'], 'right' => $m['right'], 'cmd' => \trim($m['cmd'])];
        }

        return null;
    }
}

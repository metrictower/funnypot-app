<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * Reads one `sh -c` command line the way busybox ash parses it, without running anything.
 *
 * It answers three questions for the console: does the line hold a real syntax error (and which
 * message would ash print first), which syntax features are present (quotes, pipes, substitutions,
 * ...), and is it a single simple command. It also reduces the line to a shape key, so a resend or a
 * word swap inside the same shape is recognised as the same attempt.
 *
 * It is a single pass over one cursor: the parser pulls tokens on demand and command substitutions
 * are parsed in place, so the first error in reading order wins, as it does in ash. Input is cut at
 * the first NUL and at 4096 bytes, nesting is capped, and the work done is bounded by the length.
 */
final class ShellLexer
{
    public const MAX_INPUT = 4096;
    public const MAX_CLASSES = 128;
    private const MAX_DEPTH = 48;

    /** `function` is busybox's bash-compatible keyword; the rest are POSIX. */
    private const RESERVED = ['if', 'then', 'elif', 'else', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'in', '!', '{', '}', 'function'];
    /** Tokens that end a list inside a construct. */
    private const ENDERS = ['then', 'do', 'done', 'elif', 'else', 'esac', 'fi', '}'];
    private const SAFE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.,:@%+=/-';
    private const META = " \t\n;&|<>()";

    private string $s = '';
    private int $n = 0;
    private int $pos = 0;
    /** @var array<string,mixed>|null */
    private ?array $peeked = null;
    /** @var list<array{0:string,1:bool}> pending here-document delimiters */
    private array $heredocs = [];
    /** @var array<string,bool> */
    private array $families = [];
    /** @var array<string,array<string,bool>> */
    private array $familyTokens = [];
    /** @var list<array{0:string,1:array<string,bool>|string}> */
    private array $classes = [];
    private int $classTotal = 0;
    private int $steps = 0;
    /** @var list<list<string>|null> */
    private array $segments = [];
    /** @var list<string> */
    private array $redirectTargets = [];
    private bool $allSafe = true;
    private bool $construct = false;
    private int $depth = 0;

    public static function lex(string $input): LexReport
    {
        $nul = strpos($input, "\0");
        if ($nul !== false) {
            $input = substr($input, 0, $nul);
        }
        if (strlen($input) > self::MAX_INPUT) {
            $input = substr($input, 0, self::MAX_INPUT);
        }

        $l = new self();
        $l->s = $input;
        $l->n = strlen($input);
        $defect = null;
        try {
            $l->parseList('top');
        } catch (LexDefect $d) {
            $defect = ['id' => $d->id, 'token' => $d->token];
        }

        $families = array_keys($l->families);
        sort($families);
        $tokens = [];
        foreach ($l->familyTokens as $fam => $set) {
            $tokens[$fam] = array_keys($set);
        }
        $simple = $defect === null && $families === [] && !$l->construct && $l->allSafe
            && count($l->segments) === 1 && $l->segments[0] !== null && $l->segments[0] !== [];

        return new LexReport(
            $families,
            $tokens,
            $defect,
            $simple,
            $simple ? $l->segments[0] : [],
            $l->segments,
            $l->redirectTargets,
            substr(hash('sha256', self::serialize($l->classes)), 0, 16),
            $l->classTotal,
            $l->steps,
            $l->n,
        );
    }

    // --- grammar ----------------------------------------------------------------------------------

    /**
     * A list of and-or commands. 'top' is the whole line, 'body' a construct body (an immediate
     * closer is an error), 'sub' a substitution or case arm (may be empty).
     */
    private function parseList(string $mode): void
    {
        $this->skipNewlines();
        $first = true;
        while (true) {
            $t = $this->peek();
            if ($t['t'] === 'eof') {
                return;
            }
            if ($mode !== 'top' && $this->isEnder($t) && (!$first || $mode === 'sub')) {
                return;
            }
            $this->parseAndOr();
            $first = false;
            $t = $this->peek();
            if ($t['t'] === 'op' && ($t['v'] === ';' || $t['v'] === '&')) {
                $this->next();
                $this->fam($t['v'] === ';' ? 'semicolon' : 'background', $t['v']);
                $this->addClass($t['v']);
                $this->skipNewlines();
                continue;
            }
            if ($t['t'] === 'nl') {
                $this->skipNewlines();
                continue;
            }
            if ($t['t'] === 'eof' || ($mode !== 'top' && $this->isEnder($t))) {
                return;
            }
            throw $this->unexpected($t);
        }
    }

    private function parseAndOr(): void
    {
        $this->parsePipeline();
        while (true) {
            $t = $this->peek();
            if ($t['t'] !== 'op' || ($t['v'] !== '&&' && $t['v'] !== '||')) {
                return;
            }
            $this->next();
            $this->fam('andor', $t['v']);
            $this->addClass($t['v']);
            $this->skipNewlines();
            $this->parsePipeline();
        }
    }

    private function parsePipeline(): void
    {
        $t = $this->peek();
        if ($this->isWord($t, '!')) {
            $this->next();
            $this->fam('keyword', '!');
            $this->construct = true;
            $this->addClass('K!');
        }
        $this->parseCommand();
        while (true) {
            $t = $this->peek();
            if ($t['t'] !== 'op' || $t['v'] !== '|') {
                return;
            }
            $this->next();
            $this->fam('pipe', '|');
            $this->addClass('|');
            $this->skipNewlines();
            $this->parseCommand();
        }
    }

    private function parseCommand(): void
    {
        $t = $this->peek();
        switch ($t['t']) {
            case 'eof':
                throw new LexDefect('unexpected_eof');
            case 'nl':
                throw new LexDefect('unexpected_newline');
            case 'op':
                if ($t['v'] !== '(') {
                    throw $this->unexpected($t);
                }
                $this->next();
                $this->construct = true;
                $this->fam('subshell', '(');
                $this->addClass('(');
                $this->nest();
                $this->parseList('body');
                $this->expectOp(')', 'expect_paren');
                $this->depth--;
                $this->fam('subshell', ')');
                $this->addClass(')');
                $this->afterCompound();

                return;
            case 'redir':
                $this->parseSimple();

                return;
        }
        if ($t['unq'] && in_array($t['val'], self::RESERVED, true)) {
            switch ($t['val']) {
                case 'if':
                    $this->parseIf();
                    break;
                case 'while':
                case 'until':
                    $this->keyword($t['val']);
                    $this->nest();
                    $this->parseList('body');
                    $this->expectWord('do', 'expect_do');
                    $this->parseList('body');
                    $this->expectWord('done', 'expect_done');
                    $this->depth--;
                    break;
                case 'for':
                    $this->parseFor();
                    break;
                case 'case':
                    $this->parseCase();
                    break;
                case 'function':
                    $this->parseFunction();
                    break;
                case '{':
                    $this->next();
                    $this->construct = true;
                    $this->fam('brace', '{');
                    $this->fam('keyword', '{');
                    $this->addClass('K{');
                    $this->nest();
                    $this->parseList('body');
                    $this->expectWord('}', 'expect_brace');
                    $this->depth--;
                    $this->fam('brace', '}');
                    break;
                default:
                    throw $this->unexpected($t);
            }
            $this->afterCompound();

            return;
        }
        $this->parseSimple();
    }

    private function parseIf(): void
    {
        $this->keyword('if');
        $this->nest();
        $this->parseList('body');
        $this->expectWord('then', 'expect_then');
        $this->parseList('body');
        while (true) {
            $t = $this->peek();
            if ($this->isWord($t, 'elif')) {
                $this->keyword('elif');
                $this->parseList('body');
                $this->expectWord('then', 'expect_then');
                $this->parseList('body');
                continue;
            }
            if ($this->isWord($t, 'else')) {
                $this->keyword('else');
                $this->parseList('body');
            }
            break;
        }
        $this->expectWord('fi', 'expect_fi');
        $this->depth--;
    }

    private function parseFor(): void
    {
        $this->keyword('for');
        $t = $this->next();
        if ($t['t'] !== 'word' || !$t['unq'] || preg_match('~^[A-Za-z_][A-Za-z0-9_]*$~', (string) $t['val']) !== 1) {
            throw new LexDefect('bad_for');
        }
        $this->addWordClass($t);
        $this->skipNewlines();
        $t = $this->peek();
        if ($this->isWord($t, 'in')) {
            $this->keyword('in');
            while (($t = $this->peek())['t'] === 'word') {
                $this->addWordClass($this->next());
            }
            $t = $this->next();
            if (!($t['t'] === 'nl' || ($t['t'] === 'op' && $t['v'] === ';'))) {
                throw $this->unexpected($t);
            }
            $this->fam($t['t'] === 'nl' ? 'newline' : 'semicolon', $t['t'] === 'nl' ? "\n" : ';');
        } elseif ($t['t'] === 'op' && $t['v'] === ';') {
            $this->next();
            $this->fam('semicolon', ';');
        }
        $this->skipNewlines();
        $this->nest();
        $this->expectWord('do', 'expect_do');
        $this->parseList('body');
        $this->expectWord('done', 'expect_done');
        $this->depth--;
    }

    /** `function NAME [()] BODY`, busybox's bash-compatible definition form. */
    private function parseFunction(): void
    {
        $this->keyword('function');
        $t = $this->next();
        if ($t['t'] !== 'word') {
            throw new LexDefect('expect_word', $this->actual($t));
        }
        $this->addWordClass($t);
        $t = $this->peek();
        if ($t['t'] === 'op' && $t['v'] === '(') {
            $this->next();
            $this->expectOp(')', 'expect_paren');
            $this->fam('subshell', '(');
            $this->addClass('()');
        }
        $this->skipNewlines();
        $this->nest();
        $this->parseCommand();
        $this->depth--;
    }

    private function parseCase(): void
    {
        $this->keyword('case');
        $t = $this->next();
        if ($t['t'] !== 'word') {
            throw new LexDefect('expect_word', $this->actual($t));
        }
        $this->addWordClass($t);
        $this->skipNewlines();
        $this->expectWord('in', 'expect_in');
        $this->nest();
        while (true) {
            $this->skipNewlines();
            if ($this->isWord($this->peek(), 'esac')) {
                $this->keyword('esac');
                break;
            }
            $t = $this->peek();
            if ($t['t'] === 'op' && $t['v'] === '(') {
                $this->next();
            }
            do {
                $t = $this->next();
                if ($t['t'] !== 'word') {
                    throw new LexDefect('expect_paren', $this->actual($t));
                }
                $this->addWordClass($t);
                $more = ($p = $this->peek())['t'] === 'op' && $p['v'] === '|';
                if ($more) {
                    $this->next();
                }
            } while ($more);
            $this->expectOp(')', 'expect_paren');
            $this->skipNewlines();
            $t = $this->peek();
            if (!($t['t'] === 'op' && $t['v'] === ';;') && !$this->isWord($t, 'esac')) {
                $this->parseList('sub');
            }
            $t = $this->peek();
            if ($t['t'] === 'op' && $t['v'] === ';;') {
                $this->next();
                $this->fam('semicolon', ';;');
                $this->addClass(';;');
                continue;
            }
            if ($this->isWord($t, 'esac')) {
                $this->keyword('esac');
                break;
            }
            throw new LexDefect('expect_dsemi', $this->actual($t));
        }
        $this->depth--;
    }

    /** Simple command: words and redirections, or `name()` followed by a function body. */
    private function parseSimple(): void
    {
        $argv = [];
        $literal = true;
        $words = 0;
        $redirs = 0;
        while (true) {
            $t = $this->peek();
            if ($t['t'] === 'word') {
                $this->next();
                $words++;
                $this->addWordClass($t);
                if ($t['val'] === null) {
                    $literal = false;
                } else {
                    $argv[] = $t['val'];
                }
                if (!$t['safe']) {
                    $this->allSafe = false;
                }
                continue;
            }
            if ($t['t'] === 'redir') {
                $this->parseRedirect();
                $redirs++;
                continue;
            }
            if ($t['t'] === 'op' && $t['v'] === '(') {
                if ($words !== 1 || $redirs !== 0) {
                    throw $this->unexpected($t);
                }
                $this->next();
                $this->expectOp(')', 'expect_paren');
                $this->construct = true;
                $this->fam('subshell', '(');
                $this->addClass('()');
                $this->skipNewlines();
                $this->nest();
                $this->parseCommand();
                $this->depth--;

                return;
            }
            break;
        }
        $this->segments[] = $literal ? $argv : null;
    }

    private function parseRedirect(): void
    {
        $op = $this->next()['v'];
        $heredoc = $op === '<<' || $op === '<<-';
        $this->fam($heredoc ? 'heredoc' : 'redirect', $op);
        $this->addClass('R' . $op);
        $t = $this->peek();
        if ($t['t'] !== 'word') {
            throw $this->unexpected($t);
        }
        $this->next();
        $this->addWordClass($t);
        if ($heredoc) {
            $this->heredocs[] = [(string) ($t['val'] ?? $t['raw']), $op === '<<-'];
        } elseif ($t['val'] !== null) {
            $this->redirectTargets[] = $t['val'];
        }
    }

    /** After a compound command only redirections may follow on the same command. */
    private function afterCompound(): void
    {
        while (true) {
            $t = $this->peek();
            if ($t['t'] === 'redir') {
                $this->parseRedirect();
                continue;
            }
            if ($t['t'] === 'word' && !($t['unq'] && in_array($t['val'], self::ENDERS, true))) {
                throw new LexDefect('unexpected_word');
            }

            return;
        }
    }

    private function keyword(string $kw): void
    {
        $this->next();
        $this->construct = true;
        $this->fam('keyword', $kw);
        $this->addClass('K' . $kw);
    }

    private function expectWord(string $kw, string $msgId): void
    {
        $t = $this->peek();
        if (!$this->isWord($t, $kw)) {
            throw new LexDefect($msgId, $this->actual($t));
        }
        $this->keyword($kw);
    }

    private function expectOp(string $op, string $msgId): void
    {
        $t = $this->peek();
        if ($t['t'] !== 'op' || $t['v'] !== $op) {
            throw new LexDefect($msgId, $this->actual($t));
        }
        $this->next();
    }

    private function skipNewlines(): void
    {
        while ($this->peek()['t'] === 'nl') {
            $this->next();
            $this->fam('newline', "\n");
            $this->addClass('N');
        }
    }

    private function nest(): void
    {
        if (++$this->depth > self::MAX_DEPTH) {
            throw new LexDefect('expect_paren', 'eof');
        }
    }

    /** @param array<string,mixed> $t */
    private function isWord(array $t, string $v): bool
    {
        return $t['t'] === 'word' && $t['unq'] && $t['val'] === $v;
    }

    /** @param array<string,mixed> $t */
    private function isEnder(array $t): bool
    {
        if ($t['t'] === 'op') {
            return $t['v'] === ')' || $t['v'] === ';;';
        }

        return $t['t'] === 'word' && $t['unq'] && in_array($t['val'], self::ENDERS, true);
    }

    /** @param array<string,mixed> $t */
    private function actual(array $t): string
    {
        return match ($t['t']) {
            'eof' => 'eof',
            'nl' => 'newline',
            'redir' => 'redir',
            'op' => $t['v'],
            default => ($t['unq'] && in_array($t['val'], self::RESERVED, true)) ? $t['val'] : 'word',
        };
    }

    /** @param array<string,mixed> $t */
    private function unexpected(array $t): LexDefect
    {
        $a = $this->actual($t);

        return new LexDefect(match ($a) {
            'eof' => 'unexpected_eof',
            'newline' => 'unexpected_newline',
            'redir' => 'unexpected_redir',
            'word' => 'unexpected_word',
            default => 'unexpected_' . $a,
        }, $a);
    }

    // --- tokens -----------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    private function peek(): array
    {
        return $this->peeked ??= $this->scan();
    }

    /** @return array<string,mixed> */
    private function next(): array
    {
        $t = $this->peek();
        $this->peeked = null;

        return $t;
    }

    /** @return array<string,mixed> */
    private function scan(): array
    {
        while ($this->pos < $this->n) {
            $c = $this->s[$this->pos];
            if ($c === ' ' || $c === "\t") {
                $this->pos++;
                $this->steps++;
                continue;
            }
            if ($c === '\\' && ($this->s[$this->pos + 1] ?? '') === "\n") {
                $this->pos += 2;
                $this->steps++;
                continue;
            }
            if ($c === '#') {
                // A comment starts only at the beginning of a word.
                while ($this->pos < $this->n && $this->s[$this->pos] !== "\n") {
                    $this->pos++;
                    $this->steps++;
                }
                continue;
            }
            break;
        }
        $this->steps++;
        if ($this->pos >= $this->n) {
            return ['t' => 'eof'];
        }
        $c = $this->s[$this->pos];
        if ($c === "\n") {
            $this->pos++;
            $this->readHeredocs();

            return ['t' => 'nl'];
        }
        $two = substr($this->s, $this->pos, 2);
        if ($two === ';;' || $two === '&&' || $two === '||') {
            $this->pos += 2;

            return ['t' => 'op', 'v' => $two];
        }
        if ($two === '&>') {
            $this->pos += ($this->s[$this->pos + 2] ?? '') === '>' ? 3 : 2;

            return ['t' => 'redir', 'v' => '&>'];
        }
        if (strpos(';&|()', $c) !== false) {
            $this->pos++;

            return ['t' => 'op', 'v' => $c];
        }
        // Process substitution `<(…)` / `>(…)` is a word (busybox bash compatibility), not a redirect.
        if (($c === '<' || $c === '>') && ($this->s[$this->pos + 1] ?? '') === '(') {
            return $this->scanWord();
        }
        // No here-string: busybox ash reads `<<<x` as `<<` followed by another redirection.
        if (preg_match('~\G\d*(<<-|<<|<>|<&|>&|>>|>\||<|>)~', $this->s, $m, 0, $this->pos) === 1) {
            $this->pos += strlen($m[0]);
            $this->steps += strlen($m[0]);

            return ['t' => 'redir', 'v' => $m[1]];
        }

        return $this->scanWord();
    }

    /** @return array<string,mixed> */
    private function scanWord(): array
    {
        $start = $this->pos;
        $w = ['val' => '', 'lit' => true, 'feat' => [], 'safe' => true, 'quoted' => false];
        if ($this->s[$this->pos] === '~') {
            $w['feat']['t'] = true;
        }
        $c0 = $this->s[$this->pos];
        if (($c0 === '<' || $c0 === '>') && ($this->s[$this->pos + 1] ?? '') === '(') {
            $this->pos += 2;
            $inner = $this->subParse();
            $this->fam('cmdsub', $c0 . '(');
            $w['feat']['c{' . $inner . '}'] = true;
            $w['lit'] = false;
        }
        while ($this->pos < $this->n) {
            $c = $this->s[$this->pos];
            if (strpos(self::META, $c) !== false) {
                break;
            }
            $this->steps++;
            switch ($c) {
                case "'":
                    $end = strpos($this->s, "'", $this->pos + 1);
                    if ($end === false) {
                        throw new LexDefect('quote');
                    }
                    $w['val'] .= substr($this->s, $this->pos + 1, $end - $this->pos - 1);
                    $this->steps += $end - $this->pos;
                    $this->pos = $end + 1;
                    $w['feat']['q'] = true;
                    $w['quoted'] = true;
                    $this->fam('squote', "'");
                    break;
                case '"':
                    $this->pos++;
                    $this->scanDquote($w);
                    $w['quoted'] = true;
                    break;
                case '\\':
                    $nx = $this->s[$this->pos + 1] ?? null;
                    if ($nx === null) {
                        $w['val'] .= '\\';
                        $w['safe'] = false;
                        $this->pos++;
                        break;
                    }
                    $w['val'] .= $nx;
                    $this->pos += 2;
                    $w['feat']['e'] = true;
                    $w['quoted'] = true;
                    $this->fam('escape', '\\');
                    break;
                case '$':
                    $this->scanDollar($w);
                    break;
                case '`':
                    $this->scanBackquote($w);
                    break;
                default:
                    if ($c === '*' || $c === '?' || $c === '[') {
                        $w['feat']['g'] = true;
                    } elseif (strpos(self::SAFE_CHARS, $c) === false && $c !== ']' && !($c === '~' && $this->pos === $start)) {
                        $w['safe'] = false;
                        $w['feat']['x'] = true;
                    }
                    $w['val'] .= $c;
                    $this->pos++;
            }
        }
        $unq = !$w['quoted'] && $w['lit'];

        return [
            't' => 'word',
            'raw' => substr($this->s, $start, $this->pos - $start),
            'val' => $w['lit'] ? $w['val'] : null,
            'unq' => $unq,
            'safe' => $unq && $w['safe'],
            'feat' => $w['feat'],
        ];
    }

    /** @param array<string,mixed> $w */
    private function scanDquote(array &$w): void
    {
        $this->fam('dquote', '"');
        $w['feat']['d'] = true;
        while (true) {
            if ($this->pos >= $this->n) {
                throw new LexDefect('quote');
            }
            $c = $this->s[$this->pos];
            $this->steps++;
            if ($c === '"') {
                $this->pos++;

                return;
            }
            if ($c === '\\') {
                $nx = $this->s[$this->pos + 1] ?? null;
                if ($nx === null) {
                    throw new LexDefect('quote');
                }
                if (strpos('$`"\\', $nx) !== false) {
                    $w['val'] .= $nx;
                    $this->pos += 2;
                    $w['feat']['e'] = true;
                    $this->fam('escape', '\\');
                    continue;
                }
                if ($nx === "\n") {
                    $this->pos += 2;
                    continue;
                }
                $w['val'] .= '\\';
                $this->pos++;
                continue;
            }
            if ($c === '$') {
                $this->scanDollar($w);
                continue;
            }
            if ($c === '`') {
                $this->scanBackquote($w);
                continue;
            }
            $w['val'] .= $c;
            $this->pos++;
        }
    }

    /** @param array<string,mixed> $w */
    private function scanDollar(array &$w): void
    {
        $nx = $this->s[$this->pos + 1] ?? '';
        if ($nx === '(' && ($this->s[$this->pos + 2] ?? '') === '(') {
            $this->pos += 3;
            $this->scanArith();
            $this->fam('arith', '$((');
            $w['feat']['a'] = true;
            $w['lit'] = false;

            return;
        }
        if ($nx === '(') {
            $this->pos += 2;
            $inner = $this->subParse();
            $this->fam('cmdsub', '$(');
            $w['feat']['c{' . $inner . '}'] = true;
            $w['lit'] = false;

            return;
        }
        if ($nx === "'") {
            // $'…' (busybox bash compatibility): a quoted string in which a backslash escapes the next byte.
            $this->pos += 2;
            while (true) {
                if ($this->pos >= $this->n) {
                    throw new LexDefect('quote');
                }
                $c = $this->s[$this->pos];
                $this->steps++;
                if ($c === "'") {
                    $this->pos++;
                    break;
                }
                if ($c === '\\' && $this->pos + 1 < $this->n) {
                    $w['val'] .= $this->s[$this->pos + 1];
                    $this->pos += 2;
                    continue;
                }
                $w['val'] .= $c;
                $this->pos++;
            }
            $this->fam('squote', "\$'");
            $w['feat']['q'] = true;
            $w['quoted'] = true;

            return;
        }
        if ($nx === '{') {
            $this->pos += 2;
            $this->scanParam();
            $this->fam('param', '${');
            $w['feat']['p'] = true;
            $w['lit'] = false;

            return;
        }
        if (preg_match('~\G[A-Za-z_][A-Za-z0-9_]*~', $this->s, $m, 0, $this->pos + 1) === 1) {
            $this->pos += 1 + strlen($m[0]);
            $this->steps += strlen($m[0]);
            $this->fam('param', '$');
            $w['feat']['p'] = true;
            $w['lit'] = false;

            return;
        }
        if ($nx !== '' && strpos('0123456789@*#?$!-', $nx) !== false) {
            $this->pos += 2;
            $this->fam('param', '$');
            $w['feat']['p'] = true;
            $w['lit'] = false;

            return;
        }
        $w['val'] .= '$';
        $w['safe'] = false;
        $w['feat']['x'] = true;
        $this->pos++;
    }

    /** `$( … )`: parse the inner list in place and return its shape. */
    private function subParse(): string
    {
        $this->nest();
        // Commands inside a substitution run only through their parent, so they are not segments.
        $saved = [$this->classes, $this->segments];
        $this->classes = [];
        $this->peeked = null;
        $this->parseList('sub');
        $this->expectOp(')', 'expect_paren');
        $inner = self::serialize($this->classes);
        [$this->classes, $this->segments] = $saved;
        $this->depth--;

        return $inner;
    }

    /** @param array<string,mixed> $w */
    private function scanBackquote(array &$w): void
    {
        $this->pos++;
        $content = '';
        while (true) {
            if ($this->pos >= $this->n) {
                throw new LexDefect('backquote');
            }
            $c = $this->s[$this->pos];
            $this->steps++;
            if ($c === '`') {
                $this->pos++;
                break;
            }
            if ($c === '\\' && isset($this->s[$this->pos + 1]) && strpos('`$\\', $this->s[$this->pos + 1]) !== false) {
                $content .= $this->s[$this->pos + 1];
                $this->pos += 2;
                continue;
            }
            $content .= $c;
            $this->pos++;
        }
        $this->fam('backtick', '`');
        $this->nest();
        // The backquoted text is its own program: parse it on a fresh cursor, then resume.
        $saved = [$this->s, $this->n, $this->pos, $this->peeked, $this->heredocs, $this->classes, $this->segments];
        $this->s = $content;
        $this->n = strlen($content);
        $this->pos = 0;
        $this->peeked = null;
        $this->heredocs = [];
        $this->classes = [];
        try {
            $this->parseList('top');
            $inner = self::serialize($this->classes);
        } finally {
            [$this->s, $this->n, $this->pos, $this->peeked, $this->heredocs, $this->classes, $this->segments] = $saved;
        }
        $this->depth--;
        $w['feat']['b{' . $inner . '}'] = true;
        $w['lit'] = false;
    }

    private function scanArith(): void
    {
        $depth = 0;
        while (true) {
            if ($this->pos >= $this->n) {
                throw new LexDefect('missing_arith');
            }
            $c = $this->s[$this->pos];
            $this->steps++;
            if ($c === '(') {
                $depth++;
                $this->pos++;
                continue;
            }
            if ($c === ')') {
                if ($depth > 0) {
                    $depth--;
                    $this->pos++;
                    continue;
                }
                if (($this->s[$this->pos + 1] ?? '') === ')') {
                    $this->pos += 2;

                    return;
                }
                throw new LexDefect('missing_arith');
            }
            if ($c === '$' || $c === '`') {
                $tmp = ['val' => '', 'lit' => true, 'feat' => [], 'safe' => true, 'quoted' => false];
                $c === '$' ? $this->scanDollar($tmp) : $this->scanBackquote($tmp);
                continue;
            }
            $this->pos++;
        }
    }

    private function scanParam(): void
    {
        while (true) {
            if ($this->pos >= $this->n) {
                throw new LexDefect('missing_brace');
            }
            $c = $this->s[$this->pos];
            $this->steps++;
            if ($c === '}') {
                $this->pos++;

                return;
            }
            if ($c === '\\') {
                $this->pos += 2;
                continue;
            }
            if ($c === "'") {
                $end = strpos($this->s, "'", $this->pos + 1);
                if ($end === false) {
                    throw new LexDefect('quote');
                }
                $this->pos = $end + 1;
                continue;
            }
            if ($c === '"' || $c === '$' || $c === '`') {
                $tmp = ['val' => '', 'lit' => true, 'feat' => [], 'safe' => true, 'quoted' => false];
                if ($c === '"') {
                    $this->pos++;
                    $this->scanDquote($tmp);
                } elseif ($c === '$') {
                    $this->scanDollar($tmp);
                } else {
                    $this->scanBackquote($tmp);
                }
                continue;
            }
            $this->pos++;
        }
    }

    /** After a newline, swallow the bodies of any here-documents opened on that line. */
    private function readHeredocs(): void
    {
        foreach ($this->heredocs as [$delim, $stripTabs]) {
            while ($this->pos < $this->n) {
                $eol = strpos($this->s, "\n", $this->pos);
                $line = $eol === false ? substr($this->s, $this->pos) : substr($this->s, $this->pos, $eol - $this->pos);
                $this->steps += strlen($line) + 1;
                $this->pos = $eol === false ? $this->n : $eol + 1;
                if (($stripTabs ? ltrim($line, "\t") : $line) === $delim) {
                    break;
                }
            }
        }
        $this->heredocs = [];
    }

    // --- bookkeeping ------------------------------------------------------------------------------

    private function fam(string $family, string $token): void
    {
        $this->families[$family] = true;
        $this->familyTokens[$family][$token] = true;
    }

    private function addClass(string $c): void
    {
        if ($this->classTotal >= self::MAX_CLASSES) {
            return;
        }
        $this->classTotal++;
        $this->classes[] = ['k', $c];
    }

    /** Consecutive words collapse into one class carrying the union of their features. @param array<string,mixed> $t */
    private function addWordClass(array $t): void
    {
        $last = count($this->classes) - 1;
        if ($last >= 0 && $this->classes[$last][0] === 'w') {
            $this->classes[$last][1] = $this->classes[$last][1] + $t['feat'];

            return;
        }
        if ($this->classTotal >= self::MAX_CLASSES) {
            return;
        }
        $this->classTotal++;
        $this->classes[] = ['w', $t['feat']];
    }

    /** @param list<array{0:string,1:mixed}> $classes */
    private static function serialize(array $classes): string
    {
        $out = [];
        foreach ($classes as [$kind, $v]) {
            if ($kind === 'w') {
                $f = array_keys($v);
                sort($f, SORT_STRING);
                $out[] = 'W' . implode('', $f);
            } else {
                $out[] = $v;
            }
        }

        return implode(' ', $out);
    }

    /** The work done on the last line; bounded by a small multiple of its length. */
    public static function stepsFor(string $input): int
    {
        return self::lex($input)->steps;
    }
}

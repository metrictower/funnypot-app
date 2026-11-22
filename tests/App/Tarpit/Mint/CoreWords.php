<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

/**
 * Candidate words the installed core engine might key a path on, read from its compiled artifacts:
 * each literal word in any artifact file, plus every word its compiled match patterns can spell. A
 * pattern built by regex assembly holds a word only as a chain of alternatives and evasion gaps
 * (`b["'\x5c]*u…`), so the patterns are expanded: every alternative, an optional part with and
 * without it, a repeat that may be empty dropped unless it is a plain word, and anything else (a
 * class, `.`, an escape) a word break. A string keeps only its first and last unfinished parts while
 * it grows, so expansion stays bounded without a cap.
 */
final class CoreWords
{
    private const WORD = '~[A-Za-z0-9][A-Za-z0-9_-]{2,38}~';

    /** @var array<string,true> */
    private array $words = [];
    private string $re = '';
    private int $i = 0;

    /** @return list<string> lowercased */
    public static function all(): array
    {
        $root = dirname(__DIR__, 4) . '/vendor/metrictower/funnypot-core/resources/compiled/';
        $w = new self();
        foreach (glob($root . '*') ?: [] as $file) {
            preg_match_all(self::WORD, (string) file_get_contents($file), $m);
            foreach ($m[0] as $word) {
                $w->words[strtolower($word)] = true;
            }
            if (str_ends_with($file, '.php')) {
                $artifact = require $file;
                if (is_array($artifact)) {
                    array_walk_recursive($artifact, static function ($v, $k) use ($w): void {
                        if ($k === 'regex' && is_string($v)) {
                            $w->expand($v);
                        }
                    });
                }
            }
        }

        return array_map('strval', array_keys($w->words));
    }

    /** @return list<string> the words one pattern can spell, lowercased */
    public static function ofPattern(string $re): array
    {
        $w = new self();
        $w->expand($re);

        return array_map('strval', array_keys($w->words));
    }

    private function expand(string $re): void
    {
        $this->re = $re;
        $this->i = 0;
        foreach ($this->alt() as $s) {
            foreach (explode("\0", $s) as $part) {
                $this->emit($part);
            }
        }
    }

    private function emit(string $part): void
    {
        if (preg_match_all(self::WORD, $part, $m) > 0) {
            foreach ($m[0] as $word) {
                $this->words[strtolower($word)] = true;
            }
        }
    }

    /** Any non-word run is a break; the finished middle parts are emitted now. */
    private function fold(string $s): string
    {
        $parts = explode("\0", (string) preg_replace('~[^A-Za-z0-9_-]+~', "\0", $s));
        if (count($parts) <= 2) {
            return implode("\0", $parts);
        }
        foreach (array_slice($parts, 1, -1) as $part) {
            $this->emit($part);
        }

        return $parts[0] . "\0" . $parts[count($parts) - 1];
    }

    /** @return list<string> */
    private function alt(): array
    {
        $all = $this->seq();
        while (($this->re[$this->i] ?? '') === '|') {
            $this->i++;
            $all = array_merge($all, $this->seq());
        }

        return array_values(array_unique($all));
    }

    /** @return list<string> */
    private function seq(): array
    {
        $acc = [''];
        while ($this->i < strlen($this->re) && $this->re[$this->i] !== '|' && $this->re[$this->i] !== ')') {
            $atom = $this->quantified($this->atom());
            $next = [];
            foreach ($acc as $a) {
                foreach ($atom as $b) {
                    $next[$this->fold($a . $b)] = true;
                }
            }
            $acc = array_map('strval', array_keys($next));
        }

        return $acc;
    }

    /** @param list<string> $atom @return list<string> */
    private function quantified(array $atom): array
    {
        $c = $this->re[$this->i] ?? '';
        if ($c === '{' && preg_match('~\G\{(\d*)(,?)(\d*)\}~', $this->re, $m, 0, $this->i) === 1) {
            $this->i += strlen($m[0]);
            $min = (int) $m[1];
            $many = $m[2] === ',' ? ($m[3] === '' || (int) $m[3] > 1) : $min > 1;
        } elseif ($c === '?' || $c === '*' || $c === '+') {
            $this->i++;
            $min = $c === '+' ? 1 : 0;
            $many = $c !== '?';
        } else {
            return $atom;
        }
        if (in_array($this->re[$this->i] ?? '', ['?', '+'], true)) {
            $this->i++;
        }
        $wordy = preg_grep('~\A[A-Za-z0-9_-]*\z~', $atom, PREG_GREP_INVERT) === [];
        if (!$many) {
            return $min === 0 ? array_merge([''], $atom) : $atom;
        }
        if ($min === 0) {
            return $wordy ? array_merge([''], $atom) : [''];
        }

        return $wordy ? $atom : ["\0"];
    }

    /** @return list<string> */
    private function atom(): array
    {
        $c = $this->re[$this->i];
        if ($c === '(') {
            $this->i++;
            $zeroWidth = false;
            if (($this->re[$this->i] ?? '') === '?' && preg_match('~\G\?(?:[:>|]|<?[=!]|P?<[A-Za-z_]\w*>|\'[A-Za-z_]\w*\'|[a-zA-Z-]*:?)~', $this->re, $m, 0, $this->i) === 1) {
                $zeroWidth = preg_match('~\A\?<?[=!]~', $m[0]) === 1;
                $this->i += strlen($m[0]);
                if (preg_match('~\A\?[a-zA-Z-]+\z~', $m[0]) === 1 && ($this->re[$this->i] ?? '') === ')') {
                    $this->i++;

                    return [''];
                }
            }
            $inner = $this->alt();
            if (($this->re[$this->i] ?? '') === ')') {
                $this->i++;
            }

            return $zeroWidth ? [''] : $inner;
        }
        if ($c === '[') {
            $j = $this->i + 1;
            $j += ($this->re[$j] ?? '') === '^' ? 1 : 0;
            $j += ($this->re[$j] ?? '') === ']' ? 1 : 0;
            while ($j < strlen($this->re) && $this->re[$j] !== ']') {
                $j += $this->re[$j] === '\\' ? 2 : 1;
            }
            $this->i = $j + 1;

            return ["\0"];
        }
        if ($c === '\\') {
            $d = $this->re[$this->i + 1] ?? '';
            $this->i += 2;
            if ($d === 'x' && preg_match('~\G(?:\{[0-9a-fA-F]+\}|[0-9a-fA-F]{2})~', $this->re, $m, 0, $this->i) === 1) {
                $this->i += strlen($m[0]);
            }
            if (in_array($d, ['b', 'B', 'A', 'z', 'Z', 'G'], true)) {
                return [''];
            }

            return [$d === '-' || $d === '_' ? $d : "\0"];
        }
        $this->i++;
        if ($c === '^' || $c === '$') {
            return [''];
        }

        return [$c === '.' ? "\0" : $c];
    }
}

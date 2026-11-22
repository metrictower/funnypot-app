<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * IssuedValue's word lists against the installed core. The candidates are every word of up to eight
 * characters that core's request-content rules hold or spell (CoreWords over the attack and parameter
 * artifacts) plus every one- and two-character string. Each is put where an issued value can carry it
 * (its start, after a `.`, its middle, its end, before a `.`) between filler characters, and sent as a
 * form field followed by another field and as a field followed by a space; the engine joins path, query
 * and body before its rules run, so a query parameter reads the same. Every placement IssuedValue lets
 * through must leave the engine quiet, so a core bump that flags a new short word fails here; hex words
 * are also tried as path segments, where public ids travel. Every listed word must still be flagged at
 * its place, so the lists hold no dead word.
 */
final class TokenMintIssuedWordsTest extends TestCase
{
    private Honeypot $hp;

    protected function setUp(): void
    {
        $this->hp = MintCorpus::engine();
    }

    /**
     * Place => the ways to put a word there, a letter or a digit beside it. Only a JWT holds a dot, so
     * the dot places try one way each.
     *
     * @return array<string,list<callable(string):string>>
     */
    private static function places(): array
    {
        return [
            'start' => [static fn (string $w): string => $w . '7Q7Q7Q', static fn (string $w): string => $w . 'Q7Q7Q7'],
            'after a dot' => [static fn (string $w): string => 'eyJ7Q.' . $w . '7Q7Q7Q'],
            'middle' => [static fn (string $w): string => 'Q7Q7Q' . $w . '7Q7Q7'],
            'end' => [static fn (string $w): string => '7Q7Q7Q' . $w, static fn (string $w): string => 'Q7Q7Q7' . $w],
            'before a dot' => [static fn (string $w): string => '7Q7Q7Q' . $w . '.eyJ7Q'],
        ];
    }

    /** @param list<string> $values */
    private static function form(array $values): RequestContext
    {
        $pairs = [];
        foreach ($values as $i => $v) {
            $pairs[] = 'a' . $i . '=' . $v;
            $pairs[] = 'b' . $i . '=' . $v . '%20/x';
        }

        return new RequestContext('POST', '/settings/tokens', '', MintCorpus::F, implode('&', $pairs) . '&note=x');
    }

    /** @param list<string> $values */
    private static function path(array $values): RequestContext
    {
        return new RequestContext('POST', '/settings/tokens/' . implode('/', $values) . '/delete', '', MintCorpus::F, 'csrf_token=x');
    }

    private function trips(RequestContext $ctx): bool
    {
        $d = $this->hp->detect($ctx);

        return $d->matched || in_array('attack', $d->tags(), true);
    }

    /**
     * @param callable(list<string>):RequestContext $send
     * @param list<string> $values
     * @return list<string> the single values that trip the engine; a batch that trips only together is not one
     */
    private function tripping(callable $send, array $values): array
    {
        if ($values === [] || !$this->trips($send($values))) {
            return [];
        }
        if (count($values) === 1) {
            return $values;
        }
        $half = intdiv(count($values), 2);

        return [...$this->tripping($send, array_slice($values, 0, $half)), ...$this->tripping($send, array_slice($values, $half))];
    }

    /** @return list<string> */
    private static function candidates(): array
    {
        $words = array_values(array_filter(
            CoreWords::all(['funnypot-attack.php', 'funnypot-param.php']),
            static fn (string $w): bool => preg_match('~\A[a-z0-9_-]{3,8}\z~', $w) === 1,
        ));
        $chars = str_split('abcdefghijklmnopqrstuvwxyz0123456789_-');
        foreach ($chars as $a) {
            $words[] = $a;
            foreach ($chars as $b) {
                $words[] = $a . $b;
            }
        }

        return array_values(array_unique($words));
    }

    public function test_every_short_word_core_flags_where_a_value_carries_it_is_listed(): void
    {
        $words = self::candidates();
        self::assertGreaterThan(9000, count($words), 'sanity: the artifacts were read');
        foreach (['env', 'eval', 'setenv', 'busybox', 'bashrc'] as $known) {
            self::assertContains($known, $words);
        }
        $form = [self::class, 'form'];
        $path = [self::class, 'path'];
        self::assertFalse($this->trips(self::form(['7Q7Q7Q'])), 'sanity: the form alone is quiet');
        self::assertFalse($this->trips(self::path(['7a7a7a'])), 'sanity: the path alone is quiet');
        $missing = [];
        foreach (self::places() as $place => $ways) {
            foreach ($ways as $put) {
                $values = array_values(array_filter(array_map($put, $words), [IssuedValue::class, 'quiet']));
                foreach (array_chunk($values, 25) as $chunk) {
                    foreach ($this->tripping($form, $chunk) as $v) {
                        $missing[] = "{$place}: {$v}";
                    }
                }
            }
        }
        $hex = array_values(array_filter($words, static fn (string $w): bool => preg_match('~\A[a-f0-9]+\z~', $w) === 1));
        foreach ([static fn (string $w): string => '7a7a7a' . $w . '7a7a7a', static fn (string $w): string => $w . '7a7a7a', static fn (string $w): string => '7a7a7a' . $w] as $put) {
            foreach (array_chunk(array_map($put, $hex), 25) as $chunk) {
                foreach ($this->tripping($path, $chunk) as $v) {
                    $missing[] = "path: {$v}";
                }
            }
        }
        self::assertSame([], $missing, 'core flags these where an issued value carries them; add the word to IssuedValue');
    }

    public function test_every_listed_word_is_still_flagged_at_its_place(): void
    {
        $places = self::places();
        $dead = [];
        foreach (['start' => IssuedValue::START, 'after a dot' => IssuedValue::AFTER_DOT, 'end' => IssuedValue::END, 'middle' => IssuedValue::ANYWHERE] as $place => $list) {
            foreach ($list as $w) {
                $flagged = false;
                foreach ($places[$place] as $put) {
                    $flagged = $flagged || $this->trips(self::form([$put($w)]));
                }
                if (!$flagged) {
                    $dead[] = "{$place}: {$w}";
                }
                self::assertSame(0, preg_match('~\A[a-f0-9]+\z~', $w), "{$w}: no listed word is hex, so a hex value is never refused");
            }
        }
        self::assertSame([], $dead, 'no longer flagged there; drop the word from IssuedValue');
    }
}

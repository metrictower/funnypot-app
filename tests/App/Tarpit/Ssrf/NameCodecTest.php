<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\InternalNet;
use Funnypot\App\Tarpit\Ssrf\NameCodec;
use Funnypot\App\Tarpit\Ssrf\SsrfKeys;
use PHPUnit\Framework\TestCase;

final class NameCodecTest extends TestCase
{
    public function test_every_host_index_round_trips(): void
    {
        $c = new NameCodec('k1');
        $tags = [];
        for ($i = 0; $i < NameCodec::INDEXES; $i++) {
            $tag = $c->tag($i);
            self::assertSame($i, $c->index($tag), (string) $i);
            $tags[$tag] = true;
        }
        self::assertCount(NameCodec::INDEXES, $tags, 'tags are distinct');
    }

    /**
     * A single-character edit passes the 15-bit MAC about once in 32,768 tries; the stem and zone checks
     * (about 32 stems, 3 zones) cut the accept rate of a full name to about 3e-7. Over 10,000 mutants
     * the expected count is 0.003, and at most one is allowed.
     */
    public function test_one_character_edits_rarely_resolve(): void
    {
        $keys = new SsrfKeys(SsrfCorpus::KEY);
        $net = new InternalNet($keys->key('netname'), 77, 'eu-west-2');
        $alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
        mt_srand(816);
        $tried = 0;
        $accepted = 0;
        $tagAccepted = 0;
        $codec = new NameCodec($keys->key('netname'));
        for ($i = 0; $tried < 12000; $i++) {
            $name = $net->name($i % NameCodec::INDEXES);
            if ($name === null) {
                continue;
            }
            $pos = mt_rand(0, strlen($name) - 1);
            $ch = $alphabet[mt_rand(0, 35)];
            if ($name[$pos] === $ch || !ctype_alnum($name[$pos])) {
                continue;
            }
            $mut = substr_replace($name, $ch, $pos, 1);
            $tried++;
            if ($net->lookup($mut) !== null) {
                $accepted++;
            }
            if (preg_match('/-([0-9a-z]{6})\./', $mut, $m) === 1 && $codec->index($m[1]) !== null && $m[1] !== $codec->tag($i % NameCodec::INDEXES)) {
                $tagAccepted++;
            }
        }
        fwrite(STDERR, "\nNameCodec: {$accepted} of {$tried} one-character mutants resolved; {$tagAccepted} passed the tag MAC alone\n");
        self::assertLessThanOrEqual(1, $accepted);
        self::assertLessThan(10, $tagAccepted, 'the MAC alone rejects almost every edited tag');
    }

    public function test_names_depend_on_the_netname_key_not_the_persona_seed(): void
    {
        $a = SsrfCorpus::network(4242, true, true, 8 << 20, str_repeat("\x01", 32))['net']->generated();
        $b = SsrfCorpus::network(4242, true, true, 8 << 20, str_repeat("\x02", 32))['net']->generated();
        $sameA = SsrfCorpus::network(4242, true, true, 8 << 20, str_repeat("\x01", 32))['net']->generated();
        $diff = 0;
        for ($i = 1; $i < 500; $i++) {
            if ($a->name($i) !== null && $a->name($i) !== $b->name($i)) {
                $diff++;
            }
            self::assertSame($a->name($i), $sameA->name($i));
        }
        self::assertGreaterThan(50, $diff);
    }

    public function test_unclean_names_are_dead(): void
    {
        $net = SsrfCorpus::network()['net']->generated();
        $live = 0;
        for ($i = 0; $i < 3000; $i++) {
            $name = $net->name($i);
            if ($name !== null) {
                $live++;
                self::assertTrue(\Funnypot\App\Tarpit\InertSecret::isClean('"' . $name . '"'), $name);
                self::assertSame('g' . $i, $net->lookup($name)?->key);
            }
        }
        self::assertGreaterThan(600, $live, 'about 30% of addresses are live');
        self::assertLessThan(1200, $live);
    }
}

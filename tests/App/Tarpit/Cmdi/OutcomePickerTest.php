<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Cmdi;

use Funnypot\App\Tarpit\Cmdi\AshVocabulary;
use Funnypot\App\Tarpit\Cmdi\LexReport;
use Funnypot\App\Tarpit\Cmdi\Outcome;
use Funnypot\App\Tarpit\Cmdi\OutcomePicker;
use Funnypot\App\Tarpit\Cmdi\ShellLexer;
use Funnypot\App\Tarpit\Cmdi\SourceState;
use PHPUnit\Framework\TestCase;

/**
 * The picker's rules, each pinned: real errors are real, simple commands run, resends replay, new
 * shapes blame a feature that is really there (preferring the newest), accepts are rare and never
 * back to back, and there is never a dead end.
 */
final class OutcomePickerTest extends TestCase
{
    /** Compound lines an attacker plausibly sends while "fixing" a payload. */
    private const COMPOUNDS = [
        'ls; id', 'ls | cat', 'id && whoami', 'id || id', 'echo $(id)', 'echo `id`', "echo 'a b'", 'echo "a b"',
        'echo \\`id\\`', 'cat${IFS:-x}/etc/passwd', 'if id; then whoami; fi', 'id > /tmp/x', 'echo $((1+2))',
        "id\nwhoami", 'id &', '{ id; }', '(id)', 'cat /etc/passwd | grep root', 'id; cat /etc/shadow',
        "psql -c 'select 1'", 'echo $(cat /etc/passwd) | base64', 'id | base64 && wget x', 'for i in 1 2; do id; done',
        'case x in a) id;; esac', 'echo "$(id)"', 'echo `whoami`; id', 'ls -la /root; id', 'id 2>&1', 'cat /etc/hosts | head',
        'echo ${HOME:-/}', 'echo $HOME; id', "echo 'x' > /var/www/html/x.php", 'ls && ls', 'ls || ls', 'ls | grep a | wc -l',
        '(id; whoami)', 'id;whoami;hostname', 'echo "a";echo "b"', 'id | tee /tmp/o', '! id',
    ];

    private static function key(int $i): string
    {
        return hash('sha256', 'pick-key-' . $i, true);
    }

    /** @param list<string> $families @param array<string,list<string>> $tokens */
    private static function synthetic(array $families, array $tokens = [], string $shape = '00000000deadbeef'): LexReport
    {
        sort($families);

        return new LexReport($families, $tokens + ['keyword' => ['then', 'fi'], 'andor' => ['&&'], 'semicolon' => [';']], null, false, [], [], [], $shape, 1, 1, 1);
    }

    public function test_a_true_defect_gives_its_own_message_whatever_the_key(): void
    {
        $lex = ShellLexer::lex(';id');
        for ($i = 0; $i < 50; $i++) {
            $o = OutcomePicker::pick($lex, SourceState::empty(), self::key($i));
            self::assertSame(Outcome::ERROR, $o->kind);
            self::assertSame('unexpected_;', $o->msgId);
            self::assertSame('defect', $o->source);
        }
    }

    public function test_a_simple_command_is_accepted_whatever_the_key(): void
    {
        $lex = ShellLexer::lex('id');
        for ($i = 0; $i < 50; $i++) {
            $o = OutcomePicker::pick($lex, new SourceState([], ['quote'], ['pipe'], true), self::key($i));
            self::assertSame(Outcome::ACCEPT, $o->kind);
            self::assertSame(Outcome::FACTS, $o->sub);
        }
    }

    public function test_the_blamed_family_is_always_present(): void
    {
        foreach (self::COMPOUNDS as $line) {
            $lex = ShellLexer::lex($line);
            self::assertNull($lex->trueDefect, "{$line} is valid");
            self::assertFalse($lex->simple, "{$line} is compound");
            for ($i = 0; $i < 50; $i++) {
                $o = OutcomePicker::pick($lex, SourceState::empty(), self::key($i));
                if (!$o->isAccept()) {
                    self::assertContains($o->family, $lex->families, "{$line}: blamed {$o->family}");
                }
            }
        }
    }

    public function test_never_repeats_the_last_message(): void
    {
        $lex = self::synthetic(['squote', 'dquote', 'escape', 'pipe']);
        $state = new SourceState([], ['quote'], ['pipe'], true);
        for ($i = 0; $i < 200; $i++) {
            self::assertNotSame('quote', OutcomePicker::pick($lex, $state, self::key($i))->msgId, 'quote was just printed');
        }
    }

    public function test_prefers_blaming_the_newest_fix(): void
    {
        $lex = ShellLexer::lex('echo `id`; id');
        self::assertSame(['backtick', 'semicolon'], $lex->families);
        $state = new SourceState([], ['unexpected_;'], ['semicolon'], false);
        $backquote = 0;
        for ($i = 0; $i < 200; $i++) {
            if (OutcomePicker::pick($lex, $state, self::key($i))->msgId === 'backquote') {
                $backquote++;
            }
        }
        self::assertGreaterThanOrEqual(120, $backquote, 'the backtick the attacker just added is blamed most of the time');
    }

    public function test_accepts_are_rare_and_never_back_to_back(): void
    {
        $accepts = 0;
        for ($i = 0; $i < 1000; $i++) {
            if (OutcomePicker::pick(ShellLexer::lex(self::COMPOUNDS[$i % count(self::COMPOUNDS)] . str_repeat(' x', $i % 7)), SourceState::empty(), self::key($i))->isAccept()) {
                $accepts++;
            }
        }
        self::assertGreaterThanOrEqual(100, $accepts);
        self::assertLessThanOrEqual(300, $accepts);

        // A run of multi-feature lines threading one source's state.
        $run = ['echo "$(id)"; id', "echo 'a' | cat", 'echo `id` && id', 'id; echo $(whoami) | cat', "echo 'x'; echo \"y\" | cat"];
        $state = SourceState::empty();
        $prev = false;
        for ($i = 0; $i < 300; $i++) {
            $lex = ShellLexer::lex($run[$i % count($run)] . str_repeat(';id', $i % 11));
            $o = OutcomePicker::pick($lex, $state, self::key(7));
            self::assertFalse($prev && $o->isAccept() && $o->source === 'pick', "step {$i}: two accepts in a row");
            $prev = $o->isAccept();
            $state = $state->after($lex, $o);
        }
    }

    public function test_a_memo_hit_replays_exactly(): void
    {
        $lex = ShellLexer::lex('ls | cat');
        $first = OutcomePicker::pick($lex, SourceState::empty(), self::key(1));
        $state = SourceState::empty()->after($lex, $first);
        $again = OutcomePicker::pick(ShellLexer::lex('id | grep x'), $state, self::key(99));
        self::assertSame($first->descriptor(), $again->descriptor(), 'same shape, other words: the earlier answer');
        self::assertSame('memo', $again->source);
    }

    public function test_there_is_never_a_dead_end(): void
    {
        $lex = ShellLexer::lex('ls | cat');
        $state = new SourceState([], ['unexpected_|'], ['pipe'], true);
        for ($i = 0; $i < 20; $i++) {
            self::assertTrue(OutcomePicker::pick($lex, $state, self::key($i))->isAccept(), 'nothing left to blame: it runs');
        }
    }

    public function test_the_outcome_depends_on_history_not_on_who_sent_it(): void
    {
        $lex = ShellLexer::lex('echo "$(id)" | cat');
        $state = new SourceState([], ['quote'], ['dquote'], false);
        self::assertEquals(OutcomePicker::pick($lex, $state, self::key(3)), OutcomePicker::pick($lex, $state, self::key(3)));

        $seq = static function (SourceState $s): array {
            $out = [];
            foreach (self::COMPOUNDS as $line) {
                $lex = ShellLexer::lex($line);
                $o = OutcomePicker::pick($lex, $s, self::key(5));
                $out[] = $o->historyId();
                $s = $s->after($lex, $o);
            }

            return $out;
        };
        self::assertNotSame($seq(SourceState::empty()), $seq(new SourceState([], ['backquote'], ['backtick'], false)), 'different histories diverge');
    }

    public function test_every_subset_of_blameable_families_is_safe(): void
    {
        $all = OutcomePicker::BLAMEABLE;
        $state = new SourceState([], ['quote', 'unexpected_|'], ['pipe'], false);
        $n = count($all);
        for ($mask = 0; $mask < (1 << $n); $mask++) {
            $subset = [];
            for ($b = 0; $b < $n; $b++) {
                if ($mask & (1 << $b)) {
                    $subset[] = $all[$b];
                }
            }
            $o = OutcomePicker::pick(self::synthetic($subset, [], sprintf('%016x', $mask)), $state, self::key(1));
            if (!$o->isAccept()) {
                self::assertContains($o->family, $subset);
                self::assertNotNull(OutcomePicker::phantomFor((string) $o->family, self::synthetic($subset)), "{$o->family} has wording");
            }
        }

        mt_srand(814);
        for ($i = 0; $i < 5000; $i++) {
            $subset = array_values(array_filter($all, static fn () => mt_rand(0, 1) === 1));
            $recent = array_map(static fn () => ['quote', 'backquote', 'unexpected_|', 'accept', 'expect_paren'][mt_rand(0, 4)], range(0, mt_rand(0, 4)));
            $state = new SourceState([], array_slice($recent, -4), array_values(array_filter($all, static fn () => mt_rand(0, 3) === 0)), mt_rand(0, 1) === 1);
            $o = OutcomePicker::pick(self::synthetic($subset, [], sprintf('%016x', mt_rand())), $state, self::key(mt_rand()));
            if (!$o->isAccept()) {
                self::assertContains($o->family, $subset);
                self::assertNotSame($state->lastMsgId(), $o->msgId);
            }
        }
        self::assertSame(['quote', ''], OutcomePicker::phantomFor('escape', self::synthetic(['escape'])), 'an escape fix is blamed as a quoting error');
    }

    public function test_parser_errors_never_carry_a_line_prefix(): void
    {
        foreach (AshVocabulary::ids() as $id) {
            $line = AshVocabulary::render($id, 'eof', 'No such file or directory');
            self::assertDoesNotMatchRegularExpression('~sh: line \d+:~', $line, $id);
            if ($id !== 'cd_fail') {
                self::assertDoesNotMatchRegularExpression('~line \d+:~', $line, $id);
            }
        }
        self::assertSame("sh: cd: line 0: can't cd to /x: No such file or directory", AshVocabulary::render('cd_fail', '/x'), 'ash under sh -c says line 0');
        self::assertSame('sh: syntax error: unexpected end of file (expecting "then")', AshVocabulary::render('expect_then', 'eof'));
        self::assertSame('sh: syntax error: unexpected "fi" (expecting "then")', AshVocabulary::render('expect_then', 'fi'));
        self::assertSame('sh: syntax error: unexpected word', AshVocabulary::render('unexpected_<script>'), 'a token outside the closed set is never echoed');
    }

    // --- SourceState caps -----------------------------------------------------------------------

    public function test_source_state_is_capped_and_round_trips(): void
    {
        $s = SourceState::empty();
        for ($i = 0; $i < 100; $i++) {
            $lex = self::synthetic(['pipe'], [], sprintf('%016x', $i));
            $s = $s->after($lex, new Outcome(Outcome::ERROR, 'phantom', 'unexpected_|', '|', 'pipe', 'pick'));
        }
        self::assertCount(SourceState::MEMO_CAP, $s->memo);
        self::assertNotNull($s->memoFor(sprintf('%016x', 99)), 'newest kept');
        self::assertNull($s->memoFor(sprintf('%016x', 0)), 'oldest evicted');
        $digits = $s->after(self::synthetic(['pipe'], [], '7472259693434975'), new Outcome(Outcome::ERROR, 'phantom', 'unexpected_|', '|', 'pipe', 'pick'));
        self::assertNotNull(SourceState::fromJson($digits->toJson())->memoFor('7472259693434975'), 'an all-digit shape key survives the JSON round trip');
        self::assertCount(SourceState::RECENT_CAP, $s->recentMsgIds);

        for ($i = 0; $i < 12; $i++) {
            $s = $s->withSticky("/up/{$i}.php");
        }
        $s = $s->withSticky('/UP/./x/../11.php/');
        self::assertCount(SourceState::STICKY_CAP, $s->stickyPaths);
        self::assertTrue($s->isSticky('/up/11.PHP'));
        self::assertFalse($s->isSticky('/up/0.php'));
        self::assertSame('/up/11.php', $s->stickyPaths[SourceState::STICKY_CAP - 1], 'a re-used path moves to the newest slot');

        self::assertEquals($s, SourceState::fromJson($s->toJson()));
        self::assertEquals(SourceState::empty(), SourceState::fromJson('{"memo":{"zz":1},"recent":7}'), 'garbage reads as empty');
        self::assertEquals(SourceState::empty(), SourceState::fromJson('not json'));
    }
}

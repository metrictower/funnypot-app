<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\MintState;
use PHPUnit\Framework\TestCase;

final class MintStateTest extends TestCase
{
    private const NOW = 1763800000;

    /** A value of exactly $len bytes from the characters of a charset that encode longest in JSON. */
    private static function maximal(int $len, string $chars = '/+=@:'): string
    {
        return substr(str_repeat($chars, intdiv($len, strlen($chars)) + 1), 0, $len);
    }

    /** Every cap filled at once, every field at its longest encoded length. */
    private static function full(): MintState
    {
        $s = MintState::fresh(self::NOW, str_repeat('f', 16));
        $s->d['an'] = 4294967295;
        $s->d['rn'] = 4294967295;
        for ($a = 0; $a < MintState::MAX_ACCOUNTS; $a++) {
            $pos = $s->addAccount($a . self::maximal(38, 'Z9._-'), $a . self::maximal(63, '%+._') . '@' . self::maximal(63, 'a.-') . '.' . str_repeat('z', 24), str_repeat('A', 43) . '=', self::NOW);
            $acct = &$s->d['a'][$pos];
            $acct['nm'] = self::maximal(160);
            $acct['bi'] = self::maximal(160);
            $acct['tf'] = ['e' => 4294967295, 's' => 4294967295, 'rc' => array_fill(0, MintState::RECOVERY_CODES, str_repeat('f', 16))];
            foreach (['te', 'cu', 'ru', 'mn', 'apn', 'sn', 'cn', 'rn', 'jn', 'ce', 'ch'] as $k) {
                $acct[$k] = 4294967295;
            }
            $acct['rt'] = '/settings/applications/' . str_repeat('f', 12);
            $acct['fl'] = ['sc' => [4294967295, 4294967295]];
            $acct['rl'] = [4294967295, 4294967295];
            for ($t = 0; $t < MintState::MAX_TOKENS + MintState::MAX_OAUTH_TOKENS; $t++) {
                $pat = $t < MintState::MAX_TOKENS;
                // admin:org is refused at mint and never stored; every other scope can be.
                $acct['k'][] = ['n' => 4294967295, 'v' => 63, 'k' => $pat ? 'pat' : 'oat', 'id' => str_repeat('f', 12),
                    'nt' => $pat ? self::maximal(100) : '',
                    'sc' => ['orders:export', 'orders:read', 'read:org', 'read:user', 'user:write', 'users:read'],
                    'c' => 4294967295, 'x' => 4294967295, 'lu' => 4294967295, 'ap' => $pat ? null : 4294967295, 'rl' => [4294967295, 4294967295]];
            }
            for ($p = 0; $p < MintState::MAX_APPS; $p++) {
                $acct['ap'][] = ['n' => 4294967295, 'id' => str_repeat('f', 12), 'nm' => self::maximal(100), 'hp' => 'https://' . self::maximal(192, 'a/'),
                    'cb' => 'https://' . self::maximal(192, 'a/'), 'ds' => self::maximal(200), 'ci' => str_repeat('f', 20),
                    'sx' => array_fill(0, MintState::MAX_SECRETS, [4294967295, str_repeat('f', 40), 4294967295]), 'st' => 4294967295, 'c' => 4294967295];
            }
            for ($i = 0; $i < MintState::MAX_SIDS; $i++) {
                $acct['s'][] = ['id' => str_repeat('f', 16), 'c' => 4294967295, 'l' => 4294967295];
            }
            unset($acct);
        }
        for ($i = 0; $i < MintState::MAX_OUTCOMES; $i++) {
            $s->pushOutcome(4294967295, 'session_lapsed', 4294967295);
        }
        for ($i = 0; $i < MintState::MAX_MINT_TS; $i++) {
            $s->pushMintPost(4294967295, 4294967295);
        }
        for ($i = 0; $i < MintState::MAX_API_TS; $i++) {
            $s->pushApi(4294967295, 4294967295);
        }
        for ($i = 0; $i < MintState::MAX_REQUESTS; $i++) {
            $s->addRequest(['id' => str_repeat('f', 12), 'k' => 'approval', 'a' => 4294967295, 'ap' => 4294967295, 'sc' => ['orders:export', 'orders:read', 'users:read'], 'st' => self::maximal(128, '._~-'), 'c' => 4294967295]);
        }
        for ($i = 0; $i < MintState::MAX_IDP_FAILS; $i++) {
            $s->pushIdpFail(4294967295);
        }
        $s->d['sn'] = 4294967295;

        return $s;
    }

    public function test_the_worst_case_row_fits_the_cap_without_eviction(): void
    {
        $s = self::full();
        $json = $s->toJson();
        self::assertStringNotContainsString('\/', $json, 'slashes are written unescaped');
        self::assertStringNotContainsString('\u', $json, 'no stored character needs a JSON escape');
        self::assertLessThanOrEqual(MintState::ROW_CAP, strlen($json), 'worst case is ' . strlen($json) . ' bytes');
        $copy = MintState::fromJson($json);
        self::assertNotNull($copy);
        self::assertTrue($copy->fit(self::NOW));
        self::assertSame($json, $copy->toJson(), 'nothing was evicted');
        self::assertCount(MintState::MAX_ACCOUNTS, $copy->d['a']);
    }

    public function test_eviction_order_is_expired_tokens_then_dead_sessions_then_the_lru_account(): void
    {
        $s = self::full();
        $now = self::NOW;
        foreach ($s->d['a'] as $i => $a) {
            $s->d['a'][$i]['t'] = $now - 100 + $i;
            foreach ($a['k'] as $j => $t) {
                $s->d['a'][$i]['k'][$j]['x'] = $j % 2 === 0 ? $now - 1 : $now + 3600;
            }
            foreach ($a['s'] as $j => $sid) {
                $s->d['a'][$i]['s'][$j] = ['id' => str_repeat('f', 16), 'c' => $now - 10, 'l' => $j === 0 ? $now - 10 : $now - 99999];
            }
        }
        $size = strlen($s->toJson());
        self::assertTrue($s->fit($now, $size - 1));
        self::assertCount(MintState::MAX_ACCOUNTS, $s->d['a'], 'expired tokens went first');
        foreach ($s->d['a'] as $a) {
            foreach ($a['k'] as $t) {
                self::assertGreaterThan($now, $t['x']);
            }
            self::assertCount(MintState::MAX_SIDS, $a['s'], 'sessions untouched while tokens were enough');
        }
        $afterTokens = strlen($s->toJson());
        self::assertTrue($s->fit($now, $afterTokens - 1));
        self::assertCount(MintState::MAX_ACCOUNTS, $s->d['a'], 'dead sessions went next');
        self::assertCount(1, $s->d['a'][0]['s']);
        $lru = $s->d['a'][0]['u'];
        $budget = strlen($s->toJson()) - 1;
        self::assertTrue($s->fit($now, $budget));
        self::assertLessThanOrEqual($budget, strlen($s->toJson()));
        self::assertLessThan(MintState::MAX_ACCOUNTS, count($s->d['a']), 'then accounts');
        self::assertNotContains($lru, array_column($s->d['a'], 'u'), 'the least recently active account went first');
    }

    public function test_the_account_cap_evicts_by_least_recent_activity_and_indexes_stay_unique(): void
    {
        $s = MintState::fresh(self::NOW, str_repeat('0', 16));
        for ($i = 0; $i < 20; $i++) {
            $pos = $s->addAccount('user' . $i, "u{$i}@example.com", 'x', self::NOW + $i);
            $s->d['a'][$pos]['t'] = self::NOW + $i;
            if ($i === 2) {
                $s->d['a'][$pos]['t'] = self::NOW + 1000;
            }
        }
        self::assertCount(MintState::MAX_ACCOUNTS, $s->d['a']);
        self::assertNotNull($s->accountPosByUsername('user2'), 'recently active survives');
        self::assertNull($s->accountPosByUsername('user3'));
        $idx = array_map(static fn (array $a): int => ((int) $a['i']) % 256, $s->d['a']);
        self::assertSame($idx, array_values(array_unique($idx)));

        $w = MintState::fresh(self::NOW, str_repeat('0', 16));
        $w->d['an'] = 255;
        $p0 = $w->addAccount('first', 'f@example.com', 'x', self::NOW);
        $w->d['an'] = 511;
        $p1 = $w->addAccount('wrapped', 'w@example.com', 'x', self::NOW);
        self::assertNotSame(((int) $w->d['a'][$p0]['i']) % 256, ((int) $w->d['a'][$p1]['i']) % 256, 'a wrapped serial skips a live index');
    }
}

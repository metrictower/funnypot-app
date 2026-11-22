<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\FrictionPicker;
use PHPUnit\Framework\TestCase;

final class FrictionPickerTest extends TestCase
{
    private const STATE = ['csrf_epoch' => 2, 'two_factor_enabled' => false, 'confirm_active' => false, 'rate_active' => false, 'mint_posts_10min' => 1, 'successes_total' => 0, 'account_age_bucket' => 1];

    private static function facts(array $over = []): array
    {
        return $over + ['form_age' => 30, 'session_age' => 60, 'sensitive' => false, 'confirm_age' => null, 'mint_posts_10min' => 0, 'changed_since_form' => false];
    }

    public function test_pick_is_deterministic(): void
    {
        $p = new FrictionPicker('k');
        $all = FrictionPicker::eligible(self::facts(['form_age' => 500, 'session_age' => 900, 'mint_posts_10min' => 4, 'changed_since_form' => true]));
        $a = $p->pick(self::STATE, 'token_create|read:user|30|1', ['success'], $all, false);
        for ($i = 0; $i < 20; $i++) {
            self::assertSame($a, $p->pick(self::STATE, 'token_create|read:user|30|1', ['success'], $all, false));
        }
    }

    public function test_state_digest_reads_only_the_closed_field_list(): void
    {
        self::assertSame(
            ['csrf_epoch', 'two_factor_enabled', 'confirm_active', 'rate_active', 'mint_posts_10min', 'successes_total', 'account_age_bucket'],
            FrictionPicker::STATE_FIELDS
        );
        $extra = self::STATE + ['kref' => 'aa', 'serial' => 9, 'sid' => 'bb', 'username' => 'artex1'];
        $other = self::STATE + ['kref' => 'zz', 'serial' => 1, 'sid' => 'yy', 'username' => 'someone'];
        self::assertSame(FrictionPicker::stateDigest(self::STATE), FrictionPicker::stateDigest($extra));
        self::assertSame(FrictionPicker::stateDigest($extra), FrictionPicker::stateDigest($other));
        $p = new FrictionPicker('k');
        $all = FrictionPicker::eligible(self::facts(['form_age' => 500]));
        self::assertSame($p->pick($extra, 's', [], $all, false), $p->pick($other, 's', [], $all, false), 'the same history gives the same outcome on any source');
        $changed = self::STATE;
        $changed['csrf_epoch'] = 3;
        self::assertNotSame(FrictionPicker::stateDigest(self::STATE), FrictionPicker::stateDigest($changed));
    }

    public function test_eligibility_edges(): void
    {
        self::assertSame(['transient'], FrictionPicker::eligible(self::facts()));
        self::assertSame(['form_stale', 'transient'], FrictionPicker::eligible(self::facts(['form_age' => 120])));
        self::assertSame(['transient'], FrictionPicker::eligible(self::facts(['form_age' => 119])));
        self::assertSame(['session_lapsed', 'transient'], FrictionPicker::eligible(self::facts(['session_age' => 600])));
        self::assertSame(['transient'], FrictionPicker::eligible(self::facts(['confirm_age' => 500])), 'confirm lapse needs a sensitive scope');
        self::assertSame(['confirm_lapsed', 'transient'], FrictionPicker::eligible(self::facts(['sensitive' => true, 'confirm_age' => 120])));
        self::assertSame(['throttled', 'transient'], FrictionPicker::eligible(self::facts(['mint_posts_10min' => 3])));
        self::assertSame(['edit_conflict', 'transient'], FrictionPicker::eligible(self::facts(['changed_since_form' => true])));
    }

    public function test_no_immediate_repeat_and_success_when_nothing_else_is_eligible(): void
    {
        $p = new FrictionPicker('k');
        for ($i = 0; $i < 300; $i++) {
            $kind = $p->pick(self::STATE, 'shape' . $i, ['transient'], ['transient'], false);
            self::assertSame('success', $kind, 'the only eligible obstacle was the last one, so success');
        }
        self::assertSame('success', $p->pick(self::STATE, 's', [], [], false), 'no eligible obstacle → success');
        self::assertSame('success', (new FrictionPicker('k', false))->pick(self::STATE, 's', [], FrictionPicker::eligible(self::facts(['form_age' => 500])), false), 'friction off');
    }

    public function test_property_sweep_never_throws_and_returns_closed_kinds(): void
    {
        $p = new FrictionPicker('sweep');
        $kinds = array_merge(['success'], FrictionPicker::KINDS);
        $seen = [];
        $phantoms = ['form_stale', 'session_lapsed', 'confirm_lapsed', 'throttled', 'edit_conflict'];
        for ($mask = 0; $mask < 32; $mask++) {
            $eligible = ['transient'];
            foreach ($phantoms as $bit => $k) {
                if ($mask & (1 << $bit)) {
                    array_unshift($eligible, $k);
                }
            }
            for ($h = 0; $h < 64; $h++) {
                $history = [];
                for ($j = 0; $j < $h % 5; $j++) {
                    $history[] = $kinds[($h * 7 + $j * 3) % count($kinds)];
                }
                foreach ([[false, 'a'], [true, 'b'], [false, 'c'], [true, 'd']] as [$sensitive, $cls]) {
                    $k = $p->pick(self::STATE, "{$cls}|{$h}", $history, $eligible, $sensitive);
                    self::assertContains($k, $kinds);
                    self::assertTrue($k === 'success' || in_array($k, $eligible, true), 'only an eligible obstacle');
                    $last = null;
                    foreach (array_reverse($history) as $x) {
                        if ($x !== 'success') {
                            $last = $x;
                            break;
                        }
                    }
                    if ($k !== 'success') {
                        self::assertNotSame($last, $k, 'never the last obstacle again');
                    }
                    $seen[$k] = true;
                }
            }
        }
        self::assertCount(7, $seen, 'every kind is reachable');
    }
}

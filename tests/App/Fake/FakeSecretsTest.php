<?php
declare(strict_types=1);
namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FakeSecrets;
use Funnypot\App\Render\Fake\FrozenClock;
use PHPUnit\Framework\TestCase;

final class FakeSecretsTest extends TestCase
{
    public function test_deterministic_per_seed(): void
    {
        $a = FakeSecrets::fromSeed(4242);
        $b = FakeSecrets::fromSeed(4242);
        self::assertSame($a->keys(), $b->keys());
        self::assertSame($a->envVars(), $b->envVars());
    }

    public function test_different_seeds_diverge(): void
    {
        self::assertNotSame(FakeSecrets::fromSeed(1)->keys(), FakeSecrets::fromSeed(2)->keys());
        self::assertNotSame(FakeSecrets::fromSeed(1)->envVars(), FakeSecrets::fromSeed(2)->envVars());
    }

    public function test_keys_shape(): void
    {
        foreach ([7, 99, 500001] as $seed) {
            $rows = FakeSecrets::fromSeed($seed)->keys();
            self::assertGreaterThanOrEqual(6, count($rows));
            self::assertLessThanOrEqual(12, count($rows));
            foreach ($rows as $r) {
                self::assertSame(['label', 'masked', 'created', 'lastUsed', 'fullInert'], array_keys($r));
                foreach ($r as $v) {
                    self::assertIsString($v);
                    self::assertNotSame('', $v);
                }
                self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $r['created']);
                self::assertStringContainsString('****', $r['masked']);
                // masked ends with the same last-4 the full value ends with (prefix + last few chars).
                self::assertSame(substr($r['fullInert'], -4), substr($r['masked'], -4));
            }
        }
    }

    public function test_full_inert_values_have_correct_provider_shapes(): void
    {
        $rows = FakeSecrets::fromSeed(2026)->keys();
        $shapes = [
            'Stripe' => '/^sk_live_[A-Za-z0-9]{24}$/',
            'AWS' => '/^AKIA[A-Z0-9]{16}$/',
            'SendGrid' => '/^SG\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{43}$/',
            'GitHub' => '/^ghp_[A-Za-z0-9]{36}$/',
            'OpenAI' => '/^sk-[A-Za-z0-9]{48}$/',
            'Slack' => '/^xoxb-\d{11}-\d{12}-[A-Za-z0-9]{24}$/',
            'Twilio' => '/^SK[0-9a-f]{32}$/',
        ];
        foreach ($rows as $r) {
            $matched = false;
            foreach ($shapes as $provider => $re) {
                if (strpos($r['label'], '(' . $provider . ')') !== false) {
                    self::assertMatchesRegularExpression($re, $r['fullInert'], $provider . ' shape');
                    $matched = true;
                    break;
                }
            }
            self::assertTrue($matched, 'row carried a known provider: ' . $r['label']);
        }
    }

    public function test_env_vars_shape_and_required_keys(): void
    {
        $env = FakeSecrets::fromSeed(88)->envVars();
        $names = [];
        foreach ($env as $pair) {
            self::assertCount(2, $pair);
            self::assertIsString($pair[0]);
            self::assertIsString($pair[1]);
            self::assertNotSame('', $pair[1]);
            $names[] = $pair[0];
        }
        foreach (['DB_PASSWORD', 'JWT_SECRET', 'AWS_SECRET_ACCESS_KEY', 'STRIPE_SECRET_KEY'] as $required) {
            self::assertContains($required, $names);
        }
    }

    /** created must never be in the future; lastUsed must never be before created (or "Never"). */
    public function test_created_is_capped_at_today_and_last_used_is_never_before_created(): void
    {
        $today = FrozenClock::todayYmd();
        for ($seed = 1; $seed <= 100; $seed++) {
            foreach (FakeSecrets::fromSeed($seed)->keys() as $r) {
                self::assertLessThanOrEqual($today, $r['created'], "seed {$seed}: created is in the future");
                if ($r['lastUsed'] === 'Never') {
                    continue;
                }
                if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $r['lastUsed']) === 1) {
                    // An absolute lastUsed date must sit on/after created and on/before today.
                    self::assertGreaterThanOrEqual($r['created'], $r['lastUsed'], "seed {$seed}: lastUsed before created");
                    self::assertLessThanOrEqual($today, $r['lastUsed'], "seed {$seed}: lastUsed in the future");
                }
                // Relative labels ("N minutes/hours/days/weeks ago", "yesterday") are always "now or
                // later" by construction; only the absolute-date branch needs the explicit check above.
            }
        }
    }

    public function test_no_value_contains_example_placeholder(): void
    {
        foreach ([1, 7, 4242, 500001] as $seed) {
            $s = FakeSecrets::fromSeed($seed);
            foreach ($s->keys() as $r) {
                foreach ($r as $v) {
                    self::assertStringNotContainsStringIgnoringCase('EXAMPLE', $v);
                }
            }
            foreach ($s->envVars() as $pair) {
                self::assertStringNotContainsStringIgnoringCase('EXAMPLE', $pair[1]);
            }
        }
    }
}

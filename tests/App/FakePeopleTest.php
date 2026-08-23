<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;

use Funnypot\App\Render\FakePeople;
use PHPUnit\Framework\TestCase;

final class FakePeopleTest extends TestCase
{
    public function test_person_is_deterministic_for_same_seed_and_key(): void
    {
        $a = FakePeople::person(42, 'row-0');
        $b = FakePeople::person(42, 'row-0');
        self::assertSame($a, $b);
    }

    public function test_person_shape(): void
    {
        $p = FakePeople::person(1, 'x');
        self::assertSame(['first', 'last', 'full', 'userName'], array_keys($p));
        self::assertSame($p['first'] . ' ' . $p['last'], $p['full']);
        self::assertMatchesRegularExpression('/^[a-z0-9.]+$/', $p['userName']);
        self::assertNotSame('', $p['first']);
        self::assertNotSame('', $p['last']);
        self::assertTrue(mb_check_encoding($p['first'], 'ASCII'));
        self::assertTrue(mb_check_encoding($p['last'], 'ASCII'));
    }

    public function test_different_keys_yield_high_distinctness_across_a_batch(): void
    {
        $seed = 7;
        $fulls = [];
        for ($i = 0; $i < 50; $i++) {
            $fulls[] = FakePeople::person($seed, 'row-' . $i)['full'];
        }
        $distinct = count(array_unique($fulls));
        // 50 draws from an 80x80 name space: expect the large majority to be distinct people.
        self::assertGreaterThanOrEqual(40, $distinct);
    }

    public function test_first_and_last_vary_independently(): void
    {
        // Same seed, different keys: first name changing should not force last name to change in
        // lockstep (and vice versa) — i.e. the two draws are independent sub-hashes, not one.
        $seed = 99;
        $seenPairs = [];
        for ($i = 0; $i < 30; $i++) {
            $p = FakePeople::person($seed, 'k' . $i);
            $seenPairs[] = $p['first'] . '/' . $p['last'];
        }
        // If first/last were coupled to the same sub-hash they'd still vary per key, so instead
        // directly confirm two different keys can share a first name while differing on last
        // (or vice versa) somewhere in a modest sample — proving independence, not just variety.
        $byFirst = [];
        foreach (range(0, 29) as $i) {
            $p = FakePeople::person($seed, 'k' . $i);
            $byFirst[$p['first']][] = $p['last'];
        }
        $sharedFirstWithDifferentLast = false;
        foreach ($byFirst as $lasts) {
            if (count(array_unique($lasts)) > 1) {
                $sharedFirstWithDifferentLast = true;
                break;
            }
        }
        self::assertTrue($sharedFirstWithDifferentLast, 'expected at least one repeated first name paired with different last names');
    }

    public function test_person_differs_across_seeds_generally(): void
    {
        self::assertNotSame(FakePeople::person(1, 'x'), FakePeople::person(2, 'x'));
    }

    public function test_email_uses_persons_username_and_given_domain(): void
    {
        $p = FakePeople::person(3, 'row-1');
        $email = FakePeople::email($p, 'Example.COM');
        self::assertSame($p['userName'] . '@example.com', $email);
    }

    public function test_email_is_deterministic(): void
    {
        $p = FakePeople::person(3, 'row-1');
        self::assertSame(FakePeople::email($p, 'acme.dev'), FakePeople::email($p, 'acme.dev'));
    }

    public function test_email_sanitizes_domain_case(): void
    {
        $p = ['first' => 'Ann', 'last' => 'Lee', 'full' => 'Ann Lee', 'userName' => 'a.lee'];
        self::assertSame('a.lee@corp.example', FakePeople::email($p, 'CORP.example'));
    }

    public function test_job_title_and_city_are_deterministic_and_nonempty(): void
    {
        self::assertSame(FakePeople::jobTitle(5, 'row-0'), FakePeople::jobTitle(5, 'row-0'));
        self::assertSame(FakePeople::city(5, 'row-0'), FakePeople::city(5, 'row-0'));
        self::assertNotSame('', FakePeople::jobTitle(5, 'row-0'));
        self::assertNotSame('', FakePeople::city(5, 'row-0'));
    }

    public function test_ipv4_is_deterministic_and_private_shaped(): void
    {
        $ip = FakePeople::ipv4(8, 'row-0');
        self::assertSame($ip, FakePeople::ipv4(8, 'row-0'));
        self::assertMatchesRegularExpression('/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ip);
    }

    public function test_date_is_deterministic_and_well_formed(): void
    {
        $d = FakePeople::date(8, 'row-0');
        self::assertSame($d, FakePeople::date(8, 'row-0'));
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $d);
    }
}

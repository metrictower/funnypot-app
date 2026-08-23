<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\Org;
use PHPUnit\Framework\TestCase;

final class OrgTest extends TestCase
{
    /** Employee addressing is the RFC1918 employee VLAN only (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    public function test_deterministic_across_instances(): void
    {
        $a = Org::fromSeed(7);
        $b = Org::fromSeed(7);
        self::assertSame($a->headcount(), $b->headcount());
        self::assertSame($a->people($a->headcount()), $b->people($b->headcount()));
        self::assertSame($a->managerTree(), $b->managerTree());
        self::assertSame($a->magnitudes(), $b->magnitudes());
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(
            Org::fromSeed(1)->people(50),
            Org::fromSeed(2)->people(50)
        );
    }

    public function test_headcount_in_range(): void
    {
        for ($seed = 0; $seed < 40; $seed++) {
            $n = Org::fromSeed($seed)->headcount();
            self::assertGreaterThanOrEqual(90, $n, "seed $seed");
            self::assertLessThanOrEqual(270, $n, "seed $seed");
        }
    }

    public function test_people_clamps_to_headcount_and_ids_are_stable(): void
    {
        $org = Org::fromSeed(3);
        $n = $org->headcount();
        $all = $org->people($n + 1000);
        self::assertCount($n, $all, 'people() clamps to headcount');
        self::assertSame([], $org->people(0));
        self::assertSame([], $org->people(-5));

        foreach ($all as $i => $p) {
            self::assertSame('emp-' . (1001 + $i), $p['id'], 'ids are positional and stable');
        }
        // A prefix is exactly the first rows of the full roster.
        self::assertSame(array_slice($all, 0, 10), $org->people(10));
    }

    public function test_roster_keys_are_unique_and_coherent(): void
    {
        $org = Org::fromSeed(5);
        $people = $org->people($org->headcount());

        foreach (['id', 'email', 'badgeId', 'ext', 'ip', 'deskId'] as $key) {
            $vals = array_column($people, $key);
            self::assertSame(
                count($vals),
                count(array_unique($vals)),
                "$key must be unique across the roster"
            );
        }

        foreach ($people as $p) {
            self::assertSame(
                ['id', 'first', 'last', 'name', 'email', 'title', 'dept', 'location',
                 'managerId', 'badgeId', 'deskId', 'ext', 'ip', 'status', 'band', 'tenureMonths'],
                array_keys($p)
            );
            self::assertMatchesRegularExpression('/^[0-9]{6}$/', $p['badgeId']);
            self::assertMatchesRegularExpression('/^[0-9]{4}$/', $p['ext']);
            self::assertStringContainsString('@' . $org->domain(), $p['email']);
            self::assertContains($p['status'], ['Active', 'On leave', 'Notice']);
        }
    }

    public function test_ips_are_rfc1918(): void
    {
        for ($seed = 0; $seed < 20; $seed++) {
            $org = Org::fromSeed($seed);
            foreach ($org->people($org->headcount()) as $p) {
                self::assertStringStartsWith('10.0.', $p['ip'], "seed $seed");
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $p['ip'], "seed $seed");
            }
        }
    }

    public function test_person_lookup_matches_roster_and_rejects_unknown(): void
    {
        $org = Org::fromSeed(8);
        $people = $org->people($org->headcount());
        $n = count($people);

        self::assertSame($people[0], $org->person('emp-1001'));
        $mid = (int) ($n / 2);
        self::assertSame($people[$mid], $org->person('emp-' . (1001 + $mid)));
        self::assertSame($people[$n - 1], $org->person('emp-' . (1000 + $n)));

        self::assertNull($org->person('emp-' . (1001 + $n)), 'past the roster');
        self::assertNull($org->person('emp-1'), 'below the roster base');
        self::assertNull($org->person('emp-abc'));
        self::assertNull($org->person('admin'));
        self::assertNull($org->person(''));
    }

    public function test_manager_tree_is_acyclic_with_single_root(): void
    {
        $org = Org::fromSeed(6);
        $tree = $org->managerTree();
        self::assertCount($org->headcount(), $tree);

        $roots = 0;
        foreach ($tree as $id => $managerId) {
            if ($managerId === '') {
                $roots++;
                continue;
            }
            self::assertArrayHasKey($managerId, $tree, "manager $managerId must be a roster member");
        }
        self::assertSame(1, $roots, 'exactly one root (the CEO)');
        self::assertSame('', $tree['emp-1001'], 'emp-1001 is the root');

        // Walking managers from any node reaches the root without looping.
        foreach (array_keys($tree) as $id) {
            $seen = [];
            $cur = $id;
            while ($tree[$cur] !== '') {
                self::assertArrayNotHasKey($cur, $seen, "cycle detected at $cur");
                $seen[$cur] = true;
                $cur = $tree[$cur];
            }
        }
    }

    public function test_manager_field_agrees_with_tree_and_reports(): void
    {
        $org = Org::fromSeed(2);
        $tree = $org->managerTree();
        foreach ($org->people($org->headcount()) as $p) {
            self::assertSame($tree[$p['id']], $p['managerId'], 'profile managerId = tree edge');
            if ($p['managerId'] !== '') {
                self::assertContains(
                    $p['id'],
                    $org->directReports($p['managerId']),
                    'each person appears under their manager\'s direct reports'
                );
            }
        }
        self::assertSame([], $org->directReports('emp-999999'));
    }

    public function test_magnitudes_derive_from_headcount(): void
    {
        $org = Org::fromSeed(4);
        $n = $org->headcount();
        $m = $org->magnitudes();
        self::assertSame($n, $m['headcount']);
        self::assertSame($n, $m['mailboxes']);
        self::assertSame($n, $m['extensions']);
        self::assertGreaterThan($n, $m['assets'], 'assets scale above headcount');
        self::assertSame($m['assets'], $m['mdmEnrolled']);
        self::assertSame($n + $m['contractors'], $m['cardholders']);
        self::assertSame($m['auditRowsPerDay'] * $m['auditRetentionDays'], $m['auditRows']);
        // No 214-person company with 50,000 cardholders (spec E3/T3).
        self::assertLessThan($n * 3, $m['cardholders']);
    }
}

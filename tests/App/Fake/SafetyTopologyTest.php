<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Safety;
use PHPUnit\Framework\TestCase;

/**
 * The fire plane must never name a floor or room the shared Building topology lacks: a sprinkler zone
 * on "B1" of a basement-less stack, or an incident on a "Level 3" the site does not have, is an
 * incoherence an attacker cross-referencing the building map would spot.
 */
final class SafetyTopologyTest extends TestCase
{
    public function test_every_safety_floor_and_room_belongs_to_the_building(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $bld = Building::fromSeed($seed);
            $floorCodes = [];
            $roomIds = [];
            foreach ($bld->floors() as $f) {
                $floorCodes[$f['code']] = true;
                foreach ($bld->roomsFor($f['code']) as $r) {
                    $roomIds[$r['id']] = true;
                }
            }

            $safety = Safety::fromSeed($seed);

            // Suppression zones: real floor + real room.
            foreach ($safety->zones() as $z) {
                self::assertArrayHasKey($z['floor'], $floorCodes, "seed $seed zone {$z['id']} floor in Building");
                self::assertArrayHasKey($z['room'], $roomIds, "seed $seed zone {$z['id']} room in Building");
            }

            // Sprinkler zones: real floor code (derived, never a hardcoded B1/level-8).
            foreach ($safety->sprinklerZones() as $s) {
                self::assertArrayHasKey($s['floor'], $floorCodes, "seed $seed sprinkler {$s['id']} floor in Building");
            }

            // Incident buffer: real floor + real room.
            foreach ($safety->incidents(0, 60) as $inc) {
                self::assertArrayHasKey($inc['floor'], $floorCodes, "seed $seed incident {$inc['ref']} floor in Building");
                self::assertArrayHasKey($inc['room'], $roomIds, "seed $seed incident {$inc['ref']} room in Building");
            }
        }
    }

    public function test_topology_is_deterministic_per_seed(): void
    {
        $a = Safety::fromSeed(7);
        $b = Safety::fromSeed(7);
        self::assertSame($a->sprinklerZones(), $b->sprinklerZones());
        self::assertSame($a->incidents(0, 40), $b->incidents(0, 40));
    }
}

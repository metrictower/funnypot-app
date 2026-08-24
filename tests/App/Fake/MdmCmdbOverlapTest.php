<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\Cmdb;
use Funnypot\App\Render\Fake\ItServices;
use Funnypot\App\Render\Fake\Org;
use PHPUnit\Framework\TestCase;

/**
 * The MDM fleet is a managed VIEW over the CMDB asset inventory, not a second disjoint population. Every
 * enrolled endpoint's hostname and serial must be a real CMDB endpoint's, so a list-diff between the two
 * corpora overlaps rather than exposing two parallel fleets an attacker could tell apart.
 */
final class MdmCmdbOverlapTest extends TestCase
{
    public function test_mdm_hostnames_and_serials_are_a_subset_of_cmdb(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $it = ItServices::fromSeed($seed, 'example.test');
            $cmdb = Cmdb::fromSeed($seed, 'example.test');

            $hosts = [];
            $serials = [];
            foreach ($cmdb->assets() as $a) {
                if ($a['hostname'] !== '—') {
                    $hosts[$a['hostname']] = true;
                }
                $serials[$a['serial']] = true;
            }

            $count = $it->mdmCount();
            $scan = $count < 150 ? $count : 150;
            for ($i = 0; $i < $scan; $i++) {
                $d = $it->mdmDeviceAt($i);
                self::assertArrayHasKey($d['hostname'], $hosts, "seed $seed device $i hostname in CMDB");
                self::assertArrayHasKey($d['serial'], $serials, "seed $seed device $i serial in CMDB");
            }
        }
    }

    public function test_fleet_size_still_equals_asset_count(): void
    {
        // The subset change must not disturb the headline count invariant (mdmEnrolled == assets).
        for ($seed = 0; $seed < 6; $seed++) {
            $mags = Org::fromSeed($seed, 'example.test')->magnitudes();
            $it = ItServices::fromSeed($seed, 'example.test');
            $cmdb = Cmdb::fromSeed($seed, 'example.test');
            self::assertSame($mags['mdmEnrolled'], $it->mdmCount(), "seed $seed endpoints == assets magnitude");
            self::assertSame($cmdb->assetCount(), $it->mdmCount(), "seed $seed endpoints == CMDB estate size");
        }
    }

    public function test_hostname_class_matches_the_device_os(): void
    {
        // A drawn CMDB hostname must fit the device's OS class: a laptop/desktop tag (LT-/DT-) for a
        // desktop OS, a tablet tag (TB-) for iPadOS, a phone tag (PH-) for iOS/Android.
        $laptopOs = ['Windows 11 Pro' => true, 'macOS' => true];
        $tabletOs = ['iPadOS' => true];
        for ($seed = 0; $seed < 4; $seed++) {
            $it = ItServices::fromSeed($seed, 'example.test');
            $scan = $it->mdmCount() < 80 ? $it->mdmCount() : 80;
            for ($i = 0; $i < $scan; $i++) {
                $d = $it->mdmDeviceAt($i);
                if (isset($laptopOs[$d['os']])) {
                    self::assertMatchesRegularExpression('/-(LT|DT)-\d/', $d['hostname'], "seed $seed device $i laptop tag");
                } elseif (isset($tabletOs[$d['os']])) {
                    self::assertMatchesRegularExpression('/-TB-\d/', $d['hostname'], "seed $seed device $i tablet tag");
                } else {
                    self::assertMatchesRegularExpression('/-PH-\d/', $d['hostname'], "seed $seed device $i phone tag");
                }
            }
        }
    }

    public function test_mdm_device_is_deterministic_and_round_trips(): void
    {
        $a = ItServices::fromSeed(3, 'example.test');
        $b = ItServices::fromSeed(3, 'example.test');
        self::assertSame($a->mdmDeviceAt(5), $b->mdmDeviceAt(5));
        self::assertSame($a->mdmDeviceAt(5), $a->mdmDeviceById($a->mdmDeviceAt(5)['id']));
    }
}

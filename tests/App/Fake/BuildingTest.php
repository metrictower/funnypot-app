<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\Building;
use PHPUnit\Framework\TestCase;

final class BuildingTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    public function test_deterministic_across_instances(): void
    {
        $a = Building::fromSeed(7);
        $b = Building::fromSeed(7);
        self::assertSame($a->site(), $b->site());
        self::assertSame($a->floors(), $b->floors());
        self::assertSame($a->controllers(), $b->controllers());
        self::assertSame($a->devices(), $b->devices());
        self::assertSame($a->roomsFor('G'), $b->roomsFor('G'));
        self::assertSame($a->zonesFor('G'), $b->zonesFor('G'));
        self::assertSame($a->buildingName(), $b->buildingName());
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(
            Building::fromSeed(1)->devices(),
            Building::fromSeed(2)->devices()
        );
    }

    public function test_floors_shape_and_range(): void
    {
        for ($seed = 0; $seed < 30; $seed++) {
            $floors = Building::fromSeed($seed)->floors();
            self::assertGreaterThanOrEqual(4, count($floors), "seed $seed floor count");
            self::assertLessThanOrEqual(14, count($floors), "seed $seed floor count");
            $codes = [];
            foreach ($floors as $idx => $f) {
                self::assertSame(['code', 'label', 'index', 'zones', 'capacity'], array_keys($f));
                self::assertSame($idx, $f['index']);
                self::assertNotEmpty($f['zones']);
                self::assertGreaterThan(0, $f['capacity']);
                $codes[] = $f['code'];
            }
            self::assertContains('G', $codes, "seed $seed must have Ground");
            self::assertContains('Roof', $codes, "seed $seed must have Roof");
            // Floor codes must be slug-safe once lower-cased (they become href/id segments).
            foreach ($codes as $c) {
                self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', strtolower($c), "floor code $c");
            }
        }
    }

    public function test_rooms_shape_and_range(): void
    {
        $bld = Building::fromSeed(3);
        foreach ($bld->floors() as $f) {
            $rooms = $bld->roomsFor($f['code']);
            self::assertGreaterThanOrEqual(8, count($rooms), "floor {$f['code']} room count");
            self::assertLessThanOrEqual(40, count($rooms), "floor {$f['code']} room count");
            $ids = [];
            foreach ($rooms as $r) {
                self::assertSame(
                    ['id', 'name', 'floor', 'zone', 'type', 'capacity', 'areaSqm'],
                    array_keys($r)
                );
                self::assertSame($f['code'], $r['floor']);
                self::assertContains($r['zone'], $f['zones'], 'room zone must be a zone of its floor');
                self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $r['id'], 'room id must be a slug');
                $ids[] = $r['id'];
            }
            self::assertSame(count($ids), count(array_unique($ids)), 'room ids unique within a floor');
        }
    }

    public function test_controllers_are_rfc1918_and_prefixed_by_kind(): void
    {
        for ($seed = 0; $seed < 20; $seed++) {
            $ctrls = Building::fromSeed($seed)->controllers();
            self::assertNotEmpty($ctrls);
            foreach ($ctrls as $c) {
                self::assertSame(
                    ['id', 'kind', 'ip', 'protocol', 'port', 'firmware', 'health'],
                    array_keys($c)
                );
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $c['ip'], "seed $seed ctrl ip");
                if ($c['kind'] === 'BMS') {
                    self::assertStringStartsWith('10.0.50.', $c['ip']);
                } elseif ($c['kind'] === 'ACS') {
                    self::assertStringStartsWith('10.0.60.', $c['ip']);
                } elseif ($c['kind'] === 'NVR') {
                    self::assertStringStartsWith('10.0.70.', $c['ip']);
                } else {
                    self::fail("unexpected controller kind {$c['kind']}");
                }
            }
        }
    }

    public function test_devices_cross_reference_real_topology(): void
    {
        $bld = Building::fromSeed(5);

        $floorZones = [];
        $roomsByFloor = [];
        foreach ($bld->floors() as $f) {
            $floorZones[$f['code']] = $f['zones'];
            $roomsByFloor[$f['code']] = [];
            foreach ($bld->roomsFor($f['code']) as $r) {
                $roomsByFloor[$f['code']][$r['id']] = $r['zone'];
            }
        }
        $ctrlIds = [];
        foreach ($bld->controllers() as $c) {
            $ctrlIds[$c['id']] = $c['kind'];
        }

        $devices = $bld->devices();
        self::assertNotEmpty($devices);
        $ids = [];
        foreach ($devices as $d) {
            self::assertSame(
                ['id', 'type', 'domain', 'floor', 'zone', 'room', 'controller',
                 'busAddress', 'firmware', 'lastSeen', 'state'],
                array_keys($d)
            );
            self::assertArrayHasKey($d['floor'], $roomsByFloor, 'device floor must exist');
            self::assertArrayHasKey($d['room'], $roomsByFloor[$d['floor']], 'device room must exist on its floor');
            self::assertSame($roomsByFloor[$d['floor']][$d['room']], $d['zone'], 'device zone = its room zone');
            self::assertContains($d['zone'], $floorZones[$d['floor']]);
            self::assertArrayHasKey($d['controller'], $ctrlIds, 'device controller must exist');
            self::assertContains($d['state'], ['online', 'fault', 'offline']);
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $d['id'], 'device id must be a slug');
            $ids[] = $d['id'];
        }
        self::assertSame(count($ids), count(array_unique($ids)), 'device ids are unique');
    }

    public function test_device_controller_kind_matches_domain(): void
    {
        $bld = Building::fromSeed(9);
        $kindOf = [];
        foreach ($bld->controllers() as $c) {
            $kindOf[$c['id']] = $c['kind'];
        }
        foreach ($bld->devices() as $d) {
            $k = $kindOf[$d['controller']];
            if ($d['domain'] === 'lock') {
                self::assertSame('ACS', $k);
            } elseif ($d['domain'] === 'camera') {
                self::assertSame('NVR', $k);
            } else {
                self::assertSame('BMS', $k);
            }
        }
    }

    public function test_site_counts_reconcile(): void
    {
        $bld = Building::fromSeed(4);
        $site = $bld->site();
        self::assertSame(['name', 'code', 'street', 'city', 'timezone', 'grossAreaSqm',
                          'floors', 'rooms', 'occupancyDesign'], array_keys($site));
        self::assertSame('SITE-01', $site['code']);

        $floors = $bld->floors();
        self::assertSame(count($floors), $site['floors']);

        $rooms = 0;
        $occ = 0;
        foreach ($floors as $f) {
            $rooms += count($bld->roomsFor($f['code']));
            foreach ($bld->zonesFor($f['code']) as $z) {
                $occ += $z['capacity'];
            }
        }
        self::assertSame($rooms, $site['rooms'], 'site room total = sum of per-floor rooms');
        self::assertSame($occ, $site['occupancyDesign'], 'design occupancy = sum of zone capacities');
    }

    public function test_no_public_ip_anywhere(): void
    {
        for ($seed = 0; $seed < 15; $seed++) {
            $bld = Building::fromSeed($seed);
            $blob = json_encode([$bld->controllers(), $bld->devices(), $bld->site()]);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }
}

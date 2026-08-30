<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Render\Fake\DeviceConsole;
use PHPUnit\Framework\TestCase;

/**
 * The deterministic device-console fact generator (FP-0155): persona routing from the id, estate-coherent
 * site, determinism, inert facts, and the device-shape gate that decides which unregistered panel slugs
 * become consoles.
 */
final class DeviceConsoleTest extends TestCase
{
    private const SEED = 123456789;

    public function test_facts_are_deterministic_per_seed_and_id(): void
    {
        $a = DeviceConsole::forId(self::SEED, 'pos-dev-ams-08');
        $b = DeviceConsole::forId(self::SEED, 'pos-dev-ams-08');
        self::assertSame($a, $b, 'same seed + id must yield identical facts');

        $c = DeviceConsole::forId(self::SEED + 1, 'pos-dev-ams-08');
        self::assertNotSame($a['ip'], $c['ip'], 'a different seed should shift the facts');
    }

    /** @dataProvider personaCases */
    public function test_persona_is_routed_from_the_id(string $id, string $persona): void
    {
        $d = DeviceConsole::forId(self::SEED, $id);
        self::assertSame($persona, $d['persona'], "id '{$id}' should route to persona '{$persona}'");
    }

    /** @return array<int,array{0:string,1:string}> */
    public static function personaCases(): array
    {
        return [
            ['pos-dev-ams-08', 'pos'],
            ['till-14', 'pos'],
            ['mainframe07', 'mainframe'],
            ['as400-prod-02', 'mainframe'],
            ['plc-prod-iad-20', 'plc'],
            ['scada-hmi-3', 'plc'],
            ['gw-lon-04', 'embedded'], // no persona token -> embedded (deterministic fallback)
        ];
    }

    public function test_site_code_in_id_sets_the_reported_city(): void
    {
        self::assertSame('Amsterdam', DeviceConsole::forId(self::SEED, 'pos-dev-ams-08')['site']);
        self::assertSame('Ashburn', DeviceConsole::forId(self::SEED, 'plc-prod-iad-20')['site']);
        self::assertSame('London', DeviceConsole::forId(self::SEED, 'mf-lhr-01')['site']);
    }

    public function test_facts_are_inert_and_shaped(): void
    {
        $d = DeviceConsole::forId(self::SEED, 'pos-dev-ams-08');
        self::assertMatchesRegularExpression('/^10\.0\.\d+\.\d+$/', $d['ip'], 'management ip must be inert RFC1918');
        self::assertNotSame('', $d['banner']);
        self::assertNotEmpty($d['detail']);
        self::assertNotEmpty($d['activity']);
        self::assertContains($d['status'], ['ok', 'warn']);
    }

    public function test_never_throws_on_hostile_or_empty_ids(): void
    {
        foreach (['', '..', '<script>', str_repeat('a', 200), 'A B C', '../../etc/passwd'] as $id) {
            $d = DeviceConsole::forId(self::SEED, $id);
            self::assertArrayHasKey('persona', $d, "forId must produce facts for '{$id}'");
        }
    }

    /** @dataProvider deviceShapes */
    public function test_looks_like_device(string $slug, bool $expected): void
    {
        self::assertSame($expected, DeviceConsole::looksLikeDevice($slug), "looksLikeDevice('{$slug}')");
    }

    /** @return array<int,array{0:string,1:bool}> */
    public static function deviceShapes(): array
    {
        return [
            // The pentest ids + device-shaped names.
            ['pos-dev-ams-08', true],
            ['mainframe07', true],
            ['plc-prod-iad-20', true],
            ['gw-lon-04', true],
            ['till14', true],
            // Plain words / real module slugs must NOT be captured (they keep the Dashboard fallback).
            ['reports', false],
            ['settings', false],
            ['dashboard', false],
            ['overview', false],
            ['', false],
        ];
    }

    public function test_fleet_lists_reachable_devices(): void
    {
        $fleet = DeviceConsole::fleet(self::SEED);
        self::assertNotEmpty($fleet);
        foreach ($fleet as $row) {
            self::assertArrayHasKey('id', $row);
            self::assertTrue(DeviceConsole::looksLikeDevice($row['id']), "fleet id '{$row['id']}' must open as a device console");
            // The summary must match the console the id resolves to.
            self::assertSame(DeviceConsole::forId(self::SEED, $row['id'])['personaLabel'], $row['personaLabel']);
        }
        self::assertSame($fleet, DeviceConsole::fleet(self::SEED), 'the fleet roster is deterministic');
    }
}

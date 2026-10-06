<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol;

use Funnypot\Protocol\UdpReflect;
use PHPUnit\Framework\TestCase;

/** FP-0483: the UDP reflection kill-switch flag — capture-only by default, reply only on explicit opt-in. */
final class UdpReflectTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('FUNNYPOT_UDP_REFLECT');
    }

    public function test_default_unset_is_capture_only(): void
    {
        putenv('FUNNYPOT_UDP_REFLECT');
        self::assertFalse(UdpReflect::enabled(), 'absent env => capture-only');
    }

    /** @dataProvider falseyProvider */
    public function test_falsey_values_are_capture_only(string $v): void
    {
        putenv('FUNNYPOT_UDP_REFLECT=' . $v);
        self::assertFalse(UdpReflect::enabled(), "'{$v}' => capture-only");
    }

    public static function falseyProvider(): array
    {
        return [[''], ['0'], ['off'], ['OFF'], ['false'], ['no'], ['2'], ['disabled']];
    }

    /** @dataProvider truthyProvider */
    public function test_truthy_values_enable_reply(string $v): void
    {
        putenv('FUNNYPOT_UDP_REFLECT=' . $v);
        self::assertTrue(UdpReflect::enabled(), "'{$v}' => reply");
    }

    public static function truthyProvider(): array
    {
        return [['1'], ['true'], ['TRUE'], ['on'], ['ON'], ['yes'], [' 1 ']];
    }
}

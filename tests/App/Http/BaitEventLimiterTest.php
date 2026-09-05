<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\BaitEventLimiter;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

/**
 * The per-actor bait-row cap: the first N events in a window are kept, the rest are only counted and
 * the count is folded into the next kept row; windows roll over on the clock; actors are independent;
 * a counter fault or exception admits the event; the per-process fallback map stays bounded.
 */
final class BaitEventLimiterTest extends TestCase
{
    private int $now = 1_700_000_000;

    private function limiter(int $max = 3, int $window = 600): BaitEventLimiter
    {
        return new BaitEventLimiter($max, $window, fn (): int => $this->now);
    }

    public function testFirstEventsKeptThenSuppressedThenFoldedOnTheNextWindow(): void
    {
        $l = $this->limiter();
        for ($i = 1; $i <= 3; $i++) {
            self::assertSame(['keep' => true, 'suppressed' => 0], $l->admit('198.51.100.1'), "event {$i} kept");
        }
        self::assertSame(['keep' => false, 'suppressed' => 0], $l->admit('198.51.100.1'));
        self::assertSame(['keep' => false, 'suppressed' => 0], $l->admit('198.51.100.1'));
        // Same window: still suppressed.
        $this->now += 599;
        self::assertFalse($l->admit('198.51.100.1')['keep']);
        // Window rolled: kept again, carrying the three dropped events.
        $this->now += 2;
        self::assertSame(['keep' => true, 'suppressed' => 3], $l->admit('198.51.100.1'));
        // The fold is consumed once.
        self::assertSame(['keep' => true, 'suppressed' => 0], $l->admit('198.51.100.1'));
    }

    public function testActorsAreIndependent(): void
    {
        $l = $this->limiter(1);
        self::assertTrue($l->admit('a')['keep']);
        self::assertFalse($l->admit('a')['keep']);
        self::assertTrue($l->admit('b')['keep']);
    }

    public function testDefaultsAreTheCentralConstants(): void
    {
        $l = new BaitEventLimiter(clock: fn (): int => $this->now);
        for ($i = 0; $i < BaitEventLimiter::MAX_PER_WINDOW; $i++) {
            self::assertTrue($l->admit('x')['keep']);
        }
        self::assertFalse($l->admit('x')['keep']);
        $this->now += BaitEventLimiter::WINDOW_S;
        self::assertTrue($l->admit('x')['keep']);
    }

    public function testCounterFaultAdmits(): void
    {
        $zero = new BaitEventLimiter(1, 600, fn (): int => $this->now, static fn (): int => 0, static fn (): int => 0);
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(['keep' => true, 'suppressed' => 0], $zero->admit('x'));
        }
        $throwing = new BaitEventLimiter(1, 600, fn (): int => $this->now, static function (): int { throw new \RuntimeException('shm gone'); }, static fn (): int => 0);
        self::assertSame(['keep' => true, 'suppressed' => 0], $throwing->admit('x'));
    }

    public function testInjectedCounterBackendIsUsed(): void
    {
        $store = [];
        $incr = static function (string $key) use (&$store): int {
            $store[$key] = ($store[$key] ?? 0) + 1;

            return $store[$key];
        };
        $take = static function (string $key) use (&$store): int {
            $v = $store[$key] ?? 0;
            unset($store[$key]);

            return $v;
        };
        $l = new BaitEventLimiter(2, 600, null, $incr, $take);
        self::assertTrue($l->admit('ip')['keep']);
        self::assertTrue($l->admit('ip')['keep']);
        self::assertFalse($l->admit('ip')['keep']);
        self::assertSame(['n|ip' => 3, 's|ip' => 1], $store);
    }

    public function testLocalFallbackMapStaysBounded(): void
    {
        $l = $this->limiter(1);
        for ($i = 0; $i < 5000; $i++) {
            $l->admit('actor-' . $i);
        }
        $prop = new ReflectionProperty(BaitEventLimiter::class, 'local');
        $prop->setAccessible(true);
        self::assertLessThanOrEqual(4096, count($prop->getValue($l)));
        self::assertTrue($l->admit('one-more')['keep'], 'still admits after the bound trimmed the map');
    }
}

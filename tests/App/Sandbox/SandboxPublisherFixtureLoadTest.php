<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Sandbox\Projection\SandboxFileOps;
use Funnypot\Tests\Fixtures\SandboxPublisherFixtureOps;
use PHPUnit\Framework\TestCase;

final class SandboxPublisherFixtureLoadTest extends TestCase
{
    public function testHeavyClassLoadsWithoutExecutingItsOptInSetup(): void
    {
        self::assertTrue(class_exists(SandboxProjectionProcessHeavyTest::class));
        self::assertTrue(is_subclass_of(SandboxProjectionProcessHeavyTest::class, TestCase::class));
    }

    public function testPublisherDoesNotPutItsSimulatedHoldInsideFlockAcquisition(): void
    {
        self::assertSame(
            (new \ReflectionMethod(SandboxFileOps::class, 'flock'))->getDeclaringClass()->getName(),
            (new \ReflectionMethod(SandboxPublisherFixtureOps::class, 'flock'))->getDeclaringClass()->getName(),
            'The simulated hold must run from preparation, after the acquisition deadline check.',
        );
        $ops = new SandboxPublisherFixtureOps();
        $ops->afterAcquire(); // Zero hold, no marker: no lock, process, identity or UID operation.
        self::assertTrue(method_exists($ops, 'afterAcquire'));
    }

    public function testPublisherOperationsClassLoadsBeforeTheExecutableFixtureUsesIt(): void
    {
        define('FUNNYPOT_SANDBOX_PUBLISHER_LOAD_ONLY', true);
        require dirname(__DIR__, 2) . '/Fixtures/sandbox-publisher.php';
        self::assertTrue(class_exists(SandboxPublisherFixtureOps::class));
        self::assertInstanceOf(SandboxFileOps::class, new SandboxPublisherFixtureOps());
    }
}

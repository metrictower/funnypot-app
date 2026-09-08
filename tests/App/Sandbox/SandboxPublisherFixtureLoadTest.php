<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Sandbox\Projection\SandboxFileOps;
use Funnypot\Tests\Fixtures\SandboxPublisherFixtureOps;
use PHPUnit\Framework\TestCase;

final class SandboxPublisherFixtureLoadTest extends TestCase
{
    public function testPublisherOperationsClassLoadsBeforeTheExecutableFixtureUsesIt(): void
    {
        self::assertTrue(class_exists(SandboxPublisherFixtureOps::class));
        self::assertInstanceOf(SandboxFileOps::class, new SandboxPublisherFixtureOps());
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\ServicePaths;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ServicePathsTest extends TestCase
{
    public function testProductionStorageDerivesTheRecordedLiteralConstants(): void
    {
        $p = ServicePaths::forStorage(ServicePaths::PRODUCTION_STORAGE);
        self::assertSame(ServicePaths::PERSISTENT_MANIFEST, $p->persistentManifest());
        self::assertSame(ServicePaths::STATUS_FILE, $p->statusFile());
    }

    public function testTreeIsRedirectableForTests(): void
    {
        $p = ServicePaths::forStorage('/tmp/x/storage', '/tmp/x/run', '/tmp/x/status');
        self::assertSame('/tmp/x/storage/.funnypot/services', $p->persistentDir());
        self::assertSame('/tmp/x/storage/.funnypot/services/exposure-manifest.json', $p->persistentManifest());
        self::assertSame('/tmp/x/storage/.funnypot/services/runtime.sqlite', $p->runtimeDbPath());
        self::assertSame('/tmp/x/storage/.funnypot/service-profile/service-profile.sqlite', $p->desiredDbPath());
        self::assertSame('/tmp/x/status/effective.json', $p->statusFile());
        self::assertSame('/tmp/x/run/services-private/nginx-http-listens.conf', $p->runtimeNginxHttp());
    }

    public function testDesiredStoreDirIsDistinctFromRootOnlyPersistentDir(): void
    {
        $p = ServicePaths::forStorage('/srv/data');
        self::assertNotSame($p->persistentDir(), $p->desiredStoreDir());
    }

    public function testRelativeStorageRootIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        ServicePaths::forStorage('relative/path');
    }

    public function testTraversalInRuntimeRootIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        ServicePaths::forStorage('/ok', '/run/../etc');
    }

    public function testFromEnvironmentFollowsFunnypotDbDirectory(): void
    {
        $env = static fn (string $k) => match ($k) {
            'FUNNYPOT_DB' => '/data/vol/funnypot.sqlite',
            default => false,
        };
        $p = ServicePaths::fromEnvironment('/app/demo', $env);
        self::assertSame('/data/vol/.funnypot/services/exposure-manifest.json', $p->persistentManifest());
    }

    public function testFromEnvironmentDefaultsToDemoStorageWhenDbUnset(): void
    {
        $p = ServicePaths::fromEnvironment('/app/demo', static fn (string $k) => false);
        self::assertSame('/app/demo/storage/.funnypot/services/exposure-manifest.json', $p->persistentManifest());
    }
}

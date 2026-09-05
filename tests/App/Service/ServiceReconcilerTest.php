<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\ProtocolListenerRunner;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceReconciler;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ServiceReconcilerTest extends TestCase
{
    public function testAddRemoveKeep(): void
    {
        $plan = ServiceReconciler::plan(['a', 'b', 'c'], ['b', 'c', 'd'], false);
        self::assertSame(['d'], $plan['stop']);
        self::assertSame(['a'], $plan['start']);
        self::assertSame(['b', 'c'], $plan['keep']);
    }

    public function testBaseFamilyChangeRestartsCommonProcesses(): void
    {
        $plan = ServiceReconciler::plan(['a', 'b'], ['a', 'b'], true);
        self::assertSame(['a', 'b'], $plan['stop']);
        self::assertSame(['a', 'b'], $plan['start']);
        self::assertSame([], $plan['keep']);
    }

    public function testNoOpWhenIdentical(): void
    {
        $plan = ServiceReconciler::plan(['a', 'b'], ['a', 'b'], false);
        self::assertSame([], $plan['stop']);
        self::assertSame([], $plan['start']);
        self::assertSame(['a', 'b'], $plan['keep']);
    }

    public function testRunnerSupportedIdsEqualTheManifestProcessIds(): void
    {
        $runner = new ProtocolListenerRunner(ServiceCatalog::fromPackage());
        $ids = $runner->supportedProcessIds();
        self::assertContains('ssh', $ids);
        self::assertContains('sip', $ids);
        self::assertContains('cwmp-7547', $ids);
        self::assertContains('cwmp-7548', $ids);
        self::assertNotContains('rtp', $ids);         // media, no process
        self::assertNotContains('docker-api-2375', $ids); // nginx alias, no process
    }

    public function testRunnerResolvesFixedDispatchAndRejectsUnknown(): void
    {
        $runner = new ProtocolListenerRunner(ServiceCatalog::fromPackage());
        self::assertSame(['proto' => 'ssh', 'bind' => '0.0.0.0:2222'], $runner->dispatchFor('ssh'));
        self::assertSame(['proto' => 'cwmp', 'bind' => '0.0.0.0:7548'], $runner->dispatchFor('cwmp-7548'));
        $this->expectException(RuntimeException::class);
        $runner->dispatchFor('not-a-process');
    }

    public function testRunProcessIdRejectsAnUnknownIdBeforeAnyDispatch(): void
    {
        $runner = new ProtocolListenerRunner(ServiceCatalog::fromPackage());
        $called = false;
        try {
            $runner->runProcessId('bogus', function () use (&$called): void { $called = true; });
            self::fail('expected reject');
        } catch (RuntimeException $e) {
            self::assertFalse($called);
        }
    }
}

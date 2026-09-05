<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ServiceStatusPublisher;
use Funnypot\App\Service\ServiceStatusReader;
use Funnypot\App\Service\ServiceStatusSnapshot;
use PHPUnit\Framework\TestCase;

final class ServiceStatusReaderTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-status-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0755, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            exec('rm -rf ' . escapeshellarg($this->dir));
        }
    }

    private function file(): string
    {
        return $this->dir . '/effective.json';
    }

    private static function artifact(): EffectiveExposureArtifact
    {
        return EffectiveExposureArtifact::create(
            1, 1, 'deploy', 'exact', str_repeat('a', 64), 'fpph1_' . str_repeat('b', 64),
            str_repeat('c', 64), str_repeat('d', 64),
            ['mode' => 'named', 'bundle' => 'linux-web', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('e', 32)],
            ['ssh'], ['ssh'], ['tcp/2222'],
        );
    }

    private function publish(int $writtenAt, string $state = 'ready', string $mode = 'health'): void
    {
        $pub = new ServiceStatusPublisher($this->file());
        $pub->publish(self::artifact(), $state, $mode, ['ssh' => 'alive'], 1, $writtenAt);
    }

    public function testFreshHeartbeatReadsThroughToTheProfile(): void
    {
        $this->publish(1000);
        $reader = new ServiceStatusReader($this->file(), null, ServiceStatusPublisher::WRITER_UID, 1000);
        $view = $reader->current();
        self::assertSame(ServiceStatusSnapshot::FRESH, $view->freshness());
        self::assertSame('linux', $view->profile()->baseFamily());
        self::assertTrue($view->profile()->hasService('ssh'));
    }

    public function testStaleHeartbeatStillDecodesButIsMarkedStale(): void
    {
        $this->publish(1000);
        $reader = new ServiceStatusReader($this->file(), null, ServiceStatusPublisher::WRITER_UID, 1000 + 30);
        [$snap, $reason] = $reader->readVerified();
        self::assertNotNull($snap);
        self::assertSame(ServiceStatusSnapshot::STALE, $reason);
    }

    public function testMissingHeartbeatWithNoCacheYieldsFamilyNeutral(): void
    {
        $reader = new ServiceStatusReader($this->file(), null, ServiceStatusPublisher::WRITER_UID, 1000);
        $view = $reader->current();
        self::assertSame(ServiceStatusSnapshot::MISSING, $view->freshness());
        self::assertSame('neutral', $view->profile()->baseFamily());
    }

    public function testCorruptHeartbeatWithNoCacheYieldsFamilyNeutral(): void
    {
        $this->publish(1000);
        chmod($this->file(), 0644);
        file_put_contents($this->file(), '{"schema":"funnypot-effective-service-status/v1","envelope_hash":"deadbeef"}');
        chmod($this->file(), 0444);
        $reader = new ServiceStatusReader($this->file(), null, ServiceStatusPublisher::WRITER_UID, 1000);
        $view = $reader->current();
        self::assertSame(ServiceStatusSnapshot::CORRUPT, $view->freshness());
        self::assertSame('neutral', $view->profile()->baseFamily());
    }

    public function testStaleAfterAGoodReadServesTheCachedSnapshotNotFamilyNeutral(): void
    {
        $this->publish(1000);
        $reader = new ServiceStatusReader($this->file(), null, ServiceStatusPublisher::WRITER_UID, 1000);
        self::assertSame('linux', $reader->current()->profile()->baseFamily()); // caches

        // now the file goes missing but the reader keeps its cache
        chmod($this->file(), 0644);
        unlink($this->file());
        $view = $reader->current();
        self::assertSame(ServiceStatusSnapshot::STALE, $view->freshness());
        self::assertSame('linux', $view->profile()->baseFamily());
    }

    public function testUnchangedIdentityIsNotReopened(): void
    {
        $this->publish(1000);
        $counter = new class extends IdentityFileOps {
            public int $opens = 0;
            public function openRead(string $path)
            {
                $this->opens++;

                return parent::openRead($path);
            }
        };
        $reader = new ServiceStatusReader($this->file(), $counter, ServiceStatusPublisher::WRITER_UID, 1000);
        $reader->current();
        $reader->current();
        $reader->current();
        self::assertSame(1, $counter->opens, 'an unchanged file identity must not be reopened');
    }

    public function testReplacedInodeIsReVerifiedOnce(): void
    {
        $this->publish(1000);
        $reader = new ServiceStatusReader($this->file(), null, ServiceStatusPublisher::WRITER_UID, 1000);
        $reader->current();
        // republish (new content/inode)
        $this->publish(1001);
        $view = $reader->current();
        self::assertSame(ServiceStatusSnapshot::FRESH, $view->freshness());
    }
}

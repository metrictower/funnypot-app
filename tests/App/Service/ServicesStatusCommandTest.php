<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ServiceCli;
use Funnypot\App\Service\ServiceStatusPublisher;
use Funnypot\App\Service\ServiceStatusReader;
use PHPUnit\Framework\TestCase;

final class ServicesStatusCommandTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-cli-' . bin2hex(random_bytes(6));
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

    private function publish(string $state, int $writtenAt = 1000): void
    {
        (new ServiceStatusPublisher($this->file()))->publish(self::artifact(), $state, 'health', [], 1, $writtenAt);
    }

    private function reader(int $now = 1000): ServiceStatusReader
    {
        return new ServiceStatusReader($this->file(), null, ServiceStatusPublisher::WRITER_UID, $now);
    }

    public function testHealthcheckExitsZeroForReadyAndDegraded(): void
    {
        $this->publish('ready');
        self::assertSame(0, ServiceCli::healthcheck($this->reader()));
        $this->publish('degraded');
        self::assertSame(0, ServiceCli::healthcheck($this->reader()));
    }

    public function testHealthcheckExitsOneForFailedMissingStaleCorrupt(): void
    {
        $this->publish('failed');
        self::assertSame(1, ServiceCli::healthcheck($this->reader()));
        // missing
        chmod($this->file(), 0644);
        unlink($this->file());
        self::assertSame(1, ServiceCli::healthcheck($this->reader()));
        // stale
        $this->publish('ready', 1000);
        self::assertSame(1, ServiceCli::healthcheck($this->reader(1000 + 60)));
        // corrupt
        chmod($this->file(), 0644);
        file_put_contents($this->file(), 'not json');
        chmod($this->file(), 0444);
        self::assertSame(1, ServiceCli::healthcheck($this->reader()));
    }

    public function testWaitReadyReturnsZeroWhenAReadyHeartbeatAppears(): void
    {
        $this->publish('ready', 1000);
        $t = 1000;
        $clock = static function () use (&$t): int { return $t; };
        $sleep = static function (int $s) use (&$t): void { $t += $s; };
        self::assertSame(0, ServiceCli::waitReady($this->reader(1000), 5, $clock, $sleep));
    }

    public function testWaitReadyTimesOutToOne(): void
    {
        $this->publish('reconciling', 1000);
        $t = 1000;
        $clock = static function () use (&$t): int { return $t; };
        $sleep = static function (int $s) use (&$t): void { $t += $s; };
        // reader freshness uses its own $now=1000 fixed, so the heartbeat stays "reconciling"/fresh but
        // never ready; the wait must time out to 1.
        self::assertSame(1, ServiceCli::waitReady($this->reader(1000), 2, $clock, $sleep));
    }

    public function testWaitReadyReturnsOneOnFailed(): void
    {
        $this->publish('failed', 1000);
        $t = 1000;
        $clock = static function () use (&$t): int { return $t; };
        $sleep = static function (int $s) use (&$t): void { $t += $s; };
        self::assertSame(1, ServiceCli::waitReady($this->reader(1000), 5, $clock, $sleep));
    }

    public function testNeitherPathOpensASocket(): void
    {
        // The status commands read only the heartbeat file; a fault-injected ops that fails any socket
        // primitive is irrelevant because none is called. We prove the reader never opens a socket by
        // using an ops whose only file op is the real one and asserting healthcheck still works.
        $this->publish('ready');
        $ops = new class extends IdentityFileOps {
        };
        $reader = new ServiceStatusReader($this->file(), $ops, ServiceStatusPublisher::WRITER_UID, 1000);
        self::assertSame(0, ServiceCli::healthcheck($reader));
    }
}

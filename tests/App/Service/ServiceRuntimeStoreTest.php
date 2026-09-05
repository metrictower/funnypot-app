<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\ServiceExposureManifest;
use Funnypot\App\Service\ServiceRuntimeStore;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ServiceRuntimeStoreTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-srs-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            exec('rm -rf ' . escapeshellarg($this->dir));
        }
    }

    private function store(): ServiceRuntimeStore
    {
        return new ServiceRuntimeStore($this->dir . '/runtime.sqlite');
    }

    private static function manifest(int $effectiveRevision, int $desiredRevision, string $variant = 'v1'): ServiceExposureManifest
    {
        return ServiceExposureManifest::build(
            'deploy', 'exact', str_repeat('a', 64), 'fpph1_' . str_repeat('b', 64),
            $desiredRevision, hash('sha256', 'desired-' . $desiredRevision), $effectiveRevision,
            ['mode' => 'named', 'bundle' => 'linux-web', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat($variant === 'v1' ? 'd' : 'e', 32)],
            ['ssh'], ['ssh'],
            [['endpoint_id' => 'ssh-2222', 'transport' => 'tcp', 'container_port' => 2222]],
            ['tcp/2222'], ['deploy tcp/2222:2222'], [], [],
        );
    }

    public function testBootstrapAcceptCommitsRevisionOneInBootstrapMode(): void
    {
        $s = $this->store();
        self::assertTrue($s->isEmpty());
        $s->bootstrapAccept(self::manifest(1, 1));
        self::assertFalse($s->isEmpty());
        self::assertSame(ServiceRuntimeStore::MODE_BOOTSTRAP, $s->acceptanceMode());
        self::assertSame(1, $s->acceptedArtifact()->revision());
        self::assertSame(1, $s->acceptedArtifact()->desiredRevision());
    }

    public function testBootstrapAcceptOnNonEmptyStoreThrowsAndChangesNothing(): void
    {
        $s = $this->store();
        $s->bootstrapAccept(self::manifest(1, 1));
        $before = $s->acceptedArtifact()->hash();
        try {
            $s->bootstrapAccept(self::manifest(1, 1));
            self::fail('expected throw');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('non-empty', $e->getMessage());
        }
        self::assertSame($before, $s->acceptedArtifact()->hash());
    }

    public function testConfirmHealthFlipsOnlyTheModeAndKeepsArtifactBytesIdentical(): void
    {
        $s = $this->store();
        $m = self::manifest(1, 1);
        $s->bootstrapAccept($m);
        $before = $s->acceptedArtifact();
        $s->confirmHealth($m->effectiveArtifact());
        self::assertSame(ServiceRuntimeStore::MODE_HEALTH, $s->acceptanceMode());
        self::assertSame($before->canonicalBytes(), $s->acceptedArtifact()->canonicalBytes());
        self::assertSame($before->hash(), $s->acceptedArtifact()->hash());
        self::assertSame($before->generation(), $s->acceptedArtifact()->generation());
    }

    public function testConfirmHealthRejectsAMismatchedSet(): void
    {
        $s = $this->store();
        $s->bootstrapAccept(self::manifest(1, 1));
        $other = self::manifest(2, 2, 'v2');
        $this->expectException(RuntimeException::class);
        $s->confirmHealth($other->effectiveArtifact());
    }

    public function testCommitHealthReplacesTheAcceptedSet(): void
    {
        $s = $this->store();
        $s->bootstrapAccept(self::manifest(1, 1));
        $first = $s->acceptedArtifact()->hash();
        $s->commitHealth(self::manifest(2, 2, 'v2'));
        self::assertSame(ServiceRuntimeStore::MODE_HEALTH, $s->acceptanceMode());
        self::assertNotSame($first, $s->acceptedArtifact()->hash());
        self::assertSame(2, $s->acceptedArtifact()->revision());
    }

    public function testAcceptedManifestSurvivesReopen(): void
    {
        $s = $this->store();
        $s->bootstrapAccept(self::manifest(1, 1));
        $reopened = $this->store();
        self::assertSame(1, $reopened->acceptedArtifact()->revision());
        self::assertSame(ServiceRuntimeStore::MODE_BOOTSTRAP, $reopened->acceptanceMode());
    }
}

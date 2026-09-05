<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ServiceExposureManifest;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ServiceExposureManifestTest extends TestCase
{
    /** @var list<string> */
    private array $temps = [];

    protected function tearDown(): void
    {
        foreach ($this->temps as $dir) {
            if (is_dir($dir)) {
                exec('rm -rf ' . escapeshellarg($dir));
            }
        }
    }

    private static function sampleManifest(int $effectiveRevision = 1, int $desiredRevision = 1): ServiceExposureManifest
    {
        return ServiceExposureManifest::build(
            'deploy',
            'exact',
            str_repeat('a', 64),
            'fpph1_' . str_repeat('b', 64),
            $desiredRevision,
            str_repeat('c', 64),
            $effectiveRevision,
            ['mode' => 'named', 'bundle' => 'linux-web', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('d', 32)],
            ['ssh', 'mysql'],
            ['ssh', 'mysql'],
            [
                ['endpoint_id' => 'ssh-2222', 'transport' => 'tcp', 'container_port' => 2222],
                ['endpoint_id' => 'mysql-3306', 'transport' => 'tcp', 'container_port' => 3306],
            ],
            ['tcp/2222', 'tcp/3306'],
            ['deploy tcp/2222:2222', 'deploy tcp/3306:3306'],
            [],
            [],
        );
    }

    public function testEffectiveArtifactHasNoAcceptanceModeAndDerivedGenerationHash(): void
    {
        $m = self::sampleManifest();
        $art = $m->effectiveArtifact();
        self::assertSame(EffectiveExposureArtifact::SCHEMA, $art->schema());
        self::assertSame(1, $art->revision());
        self::assertSame(1, $art->desiredRevision());
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $art->generation());
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $art->hash());
        self::assertSame(substr($art->hash(), 0, 32), $art->generation());
        self::assertArrayNotHasKey('acceptance_mode', $art->toArray());
    }

    public function testShuffledInputSerializesToTheSameBytes(): void
    {
        $a = self::sampleManifest();
        $b = ServiceExposureManifest::build(
            'deploy', 'exact', str_repeat('a', 64), 'fpph1_' . str_repeat('b', 64), 1, str_repeat('c', 64), 1,
            ['mode' => 'named', 'bundle' => 'linux-web', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('d', 32)],
            ['mysql', 'ssh'], // reversed
            ['mysql', 'ssh'],
            [
                ['endpoint_id' => 'mysql-3306', 'transport' => 'tcp', 'container_port' => 3306],
                ['endpoint_id' => 'ssh-2222', 'transport' => 'tcp', 'container_port' => 2222],
            ],
            ['tcp/3306', 'tcp/2222'],
            ['deploy tcp/3306:3306', 'deploy tcp/2222:2222'],
            [], [],
        );
        self::assertSame($a->toJson(), $b->toJson());
        self::assertSame($a->planHash(), $b->planHash());
        self::assertSame($a->effectiveArtifact()->hash(), $b->effectiveArtifact()->hash());
    }

    public function testChangingAPublishTupleChangesPublishedAndPlanHash(): void
    {
        $a = self::sampleManifest();
        $b = ServiceExposureManifest::build(
            'deploy', 'exact', str_repeat('a', 64), 'fpph1_' . str_repeat('b', 64), 1, str_repeat('c', 64), 1,
            ['mode' => 'named', 'bundle' => 'linux-web', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('d', 32)],
            ['ssh', 'mysql'], ['ssh', 'mysql'],
            [
                ['endpoint_id' => 'ssh-2222', 'transport' => 'tcp', 'container_port' => 2222],
                ['endpoint_id' => 'mysql-3306', 'transport' => 'tcp', 'container_port' => 3306],
            ],
            ['tcp/2222', 'tcp/3306'],
            ['deploy tcp/2222:2222', 'deploy tcp/3307:3306'], // different host port
            [], [],
        );
        self::assertNotSame($a->publishedHash(), $b->publishedHash());
        self::assertNotSame($a->planHash(), $b->planHash());
    }

    public function testHealthOnlyChangeKeepsEffectiveArtifactWhenSetIsUnchanged(): void
    {
        // effective_revision equal to desired: same accepted set, same artifact bytes regardless of any
        // status the persistent file is asked to carry (it always carries fixed not-live status).
        $a = self::sampleManifest(1, 1);
        $b = self::sampleManifest(1, 1);
        self::assertSame($a->effectiveArtifact()->hash(), $b->effectiveArtifact()->hash());
    }

    public function testFromArrayRoundTrips(): void
    {
        $m = self::sampleManifest();
        $decoded = json_decode($m->toJson(), true);
        $back = ServiceExposureManifest::fromArray($decoded);
        self::assertSame($m->planHash(), $back->planHash());
        self::assertSame($m->effectiveArtifact()->hash(), $back->effectiveArtifact()->hash());
    }

    public function testCorruptPlanHashFailsClosed(): void
    {
        $decoded = json_decode(self::sampleManifest()->toJson(), true);
        $decoded['plan_hash'] = str_repeat('0', 64);
        $this->expectException(RuntimeException::class);
        ServiceExposureManifest::fromArray($decoded);
    }

    public function testCorruptEffectiveArtifactFailsClosed(): void
    {
        $decoded = json_decode(self::sampleManifest()->toJson(), true);
        $decoded['effective_artifact']['hash'] = str_repeat('0', 64);
        $this->expectException(RuntimeException::class);
        ServiceExposureManifest::fromArray($decoded);
    }

    public function testFromPersistentFileReadsAndVerifies(): void
    {
        [$path] = $this->writePersistent(self::sampleManifest());
        $m = ServiceExposureManifest::fromPersistentFile($path);
        self::assertSame(1, $m->effectiveArtifact()->revision());
    }

    public function testFromPersistentFileRejectsATamperedFile(): void
    {
        [$path] = $this->writePersistent(self::sampleManifest());
        $bytes = (string) file_get_contents($path);
        file_put_contents($path, str_replace('"revision":1', '"revision":2', $bytes));
        chmod($path, 0600);
        $this->expectException(RuntimeException::class);
        ServiceExposureManifest::fromPersistentFile($path);
    }

    public function testFromPersistentFileRejectsAGroupWritableFile(): void
    {
        [$path] = $this->writePersistent(self::sampleManifest());
        chmod($path, 0660); // violates the no g+o access rule
        $this->expectException(RuntimeException::class);
        ServiceExposureManifest::fromPersistentFile($path);
    }

    /** @return array{0:string,1:string} [file path, storage root] */
    private function writePersistent(ServiceExposureManifest $m): array
    {
        $root = sys_get_temp_dir() . '/fp-svc-' . bin2hex(random_bytes(6));
        $this->temps[] = $root;
        $servicesDir = $root . '/.funnypot/services';
        mkdir($servicesDir, 0700, true);
        chmod($root . '/.funnypot', 0700);
        chmod($servicesDir, 0700);
        $path = $servicesDir . '/exposure-manifest.json';
        file_put_contents($path, $m->toJson());
        chmod($path, 0600);

        return [$path, $root];
    }
}

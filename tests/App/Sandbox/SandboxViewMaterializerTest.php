<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Identity\PreparedIdentitySource;
use Funnypot\App\Identity\SourceOpenAttestation;
use Funnypot\App\Sandbox\Projection\ProjectionDestinationOwner;
use Funnypot\App\Sandbox\Projection\ProjectionEntryRegistry;
use Funnypot\App\Sandbox\Projection\ProjectionRegistryEntry;
use Funnypot\App\Sandbox\Projection\RestartConsumer;
use Funnypot\App\Sandbox\Projection\SandboxFileOps;
use Funnypot\App\Sandbox\Projection\SandboxProjection;
use Funnypot\App\Sandbox\Projection\SandboxProjectionEntry;
use Funnypot\App\Sandbox\Projection\SandboxProjectionException;
use Funnypot\App\Sandbox\Projection\SandboxProjectionSource;
use Funnypot\App\Sandbox\Projection\SandboxViewMaterializer;
use PHPUnit\Framework\TestCase;

final class SandboxViewMaterializerTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void { $this->dir = sys_get_temp_dir() . '/fp-materializer-' . bin2hex(random_bytes(6)); mkdir($this->dir, 0700); }
    protected function tearDown(): void { SandboxTestFiles::remove($this->dir); }

    public function testZeroAnonymousAcceptsOnlyAnUnlinkedOpenHandle(): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(true);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        $manifest = (new SandboxViewMaterializer($registry, new SandboxFileOps()))
            ->materialize($candidate, $projection, [$source->sourceClass => $source], 1234);
        self::assertSame(1234, $manifest['created_at']);
        self::assertFileExists($candidate . '/views/upload-sample/capability/sample.conf');
        self::assertSame('0400', substr(sprintf('%o', fileperms($candidate . '/views/upload-sample/capability/sample.conf')), -4));
        $source->close();
    }

    public function testZeroAnonymousRejectsALinkedHandle(): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(false);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        $this->expectException(SandboxProjectionException::class);
        (new SandboxViewMaterializer($registry, new SandboxFileOps()))
            ->materialize($candidate, $projection, [$source->sourceClass => $source], 1234);
    }

    /** @dataProvider invalidExactlyOneHandles */
    public function testExactlyOneRejectsAnonymousAndHardlinkedHandles(bool $unlink, bool $hardlink): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture($unlink, ProjectionRegistryEntry::EXACTLY_ONE, $hardlink);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('source-attestation-drift');
            (new SandboxViewMaterializer($registry, new SandboxFileOps()))->materialize(
                $candidate, $projection, [$source->sourceClass => $source], 1234,
            );
        } finally {
            $source->close();
        }
    }

    public static function invalidExactlyOneHandles(): iterable
    {
        yield 'anonymous nlink zero' => [true, false];
        yield 'hardlinked nlink two' => [false, true];
    }

    public function testDestinationMetadataIsFsyncedAfterFinalModeApplication(): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(true);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        $ops = new MetadataOrderOps();
        try {
            (new SandboxViewMaterializer($registry, $ops))->materialize(
                $candidate,
                $projection,
                [$source->sourceClass => $source],
                1234,
            );
            $mode = array_search('chmod:0400', $ops->events, true);
            $sync = array_search('fsync', $ops->events, true);
            self::assertIsInt($mode);
            self::assertIsInt($sync);
            self::assertGreaterThan($mode, $sync);
        } finally {
            $source->close();
        }
    }

    public function testDestinationMetadataFsyncFailureRejectsCandidate(): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(true);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('candidate-write-failed');
            (new SandboxViewMaterializer($registry, new FailingMetadataSyncOps()))->materialize(
                $candidate,
                $projection,
                [$source->sourceClass => $source],
                1234,
            );
        } finally {
            $source->close();
        }
    }

    public function testPreReadHandleMetadataDriftFailsClosed(): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(true);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('source-attestation-drift');
            (new SandboxViewMaterializer($registry, new FstatMutationOps(1)))->materialize(
                $candidate, $projection, [$source->sourceClass => $source], 1234,
            );
        } finally {
            $source->close();
        }
    }

    public function testPostReadHandleMetadataDriftFailsClosed(): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(true);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('projection-source-content-mismatch');
            (new SandboxViewMaterializer($registry, new FstatMutationOps(2)))->materialize(
                $candidate, $projection, [$source->sourceClass => $source], 1234,
            );
        } finally {
            $source->close();
        }
    }

    public function testSameLengthContentMutationFailsClosed(): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(true);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('projection-source-content-mismatch');
            (new SandboxViewMaterializer($registry, new ContentMutationOps()))->materialize(
                $candidate, $projection, [$source->sourceClass => $source], 1234,
            );
        } finally {
            $source->close();
        }
    }

    /** @dataProvider ownershipFailures */
    public function testFakedRootOwnershipFailureStopsBeforeCandidateCompletion(string $operation): void
    {
        [$registry, $projection, $source] = $this->anonymousFixture(true);
        $candidate = $this->dir . '/candidate';
        mkdir($candidate, 0700);
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('ownership-apply-failed');
            (new SandboxViewMaterializer($registry, new FailingRootOwnershipOps($operation)))->materialize(
                $candidate, $projection, [$source->sourceClass => $source], 1234,
            );
        } finally {
            $source->close();
        }
    }

    public static function ownershipFailures(): iterable
    {
        yield 'chown' => ['chown'];
        yield 'chgrp' => ['chgrp'];
    }

    /** @return array{ProjectionEntryRegistry,SandboxProjection,PreparedIdentitySource} */
    private function anonymousFixture(bool $unlink, string $linkPolicy = ProjectionRegistryEntry::ZERO_ANONYMOUS, bool $hardlink = false): array
    {
        $path = $this->dir . '/anonymous';
        $h = fopen($path, 'x+b');
        fwrite($h, 'fixed generated fixture');
        fflush($h);
        if ($hardlink) { link($path, $path . '-hardlink'); }
        if ($unlink) { unlink($path); }
        rewind($h);
        $st = fstat($h);
        $attestation = SourceOpenAttestation::fromStat(SourceOpenAttestation::GENERATED_ANONYMOUS, $st);
        $source = new PreparedIdentitySource('test-generated-source/v1', $h, $attestation, $st['size'], hash('sha256', 'fixed generated fixture'), []);
        $row = new ProjectionRegistryEntry(
            'test-generated-source/v1', 'test-generated', ProjectionRegistryEntry::REQUIRED,
            ProjectionDestinationOwner::UPLOAD_SAMPLE, 'upload-sample/capability/sample',
            'views/upload-sample/capability/sample.conf', 0500, 0400, 'private',
            [RestartConsumer::UPLOAD_SAMPLE], [SourceOpenAttestation::GENERATED_ANONYMOUS], $linkPolicy,
        );
        $registry = new ProjectionEntryRegistry([$row]);
        $projectionSource = new SandboxProjectionSource(
            $source->sourceClass, $attestation->id, $attestation->dev, $attestation->ino, $attestation->mode,
            $attestation->uid, $attestation->gid, $attestation->nlink, $source->byteLength, $source->sha256, [],
        );
        $effective = SandboxProjectionProducerTest::effective();
        $projection = new SandboxProjection(
            str_repeat('a', 32), 'fpph1_' . str_repeat('c', 64), 'fpkc1_' . str_repeat('d', 64), str_repeat('b', 64),
            $effective->schema(), $effective->revision(), $effective->generation(), $effective->hash(),
            $registry->registryHash(), [new SandboxProjectionEntry($row, $projectionSource)],
        );

        return [$registry, $projection, $source];
    }
}

class MetadataOrderOps extends SandboxFileOps
{
    /** @var list<string> */
    public array $events = [];

    public function fdatasync($h): bool
    {
        $this->events[] = 'fdatasync';
        return parent::fdatasync($h);
    }

    public function chmod(string $path, int $mode): bool
    {
        $this->events[] = 'chmod:' . sprintf('%04o', $mode);
        return parent::chmod($path, $mode);
    }

    public function fsync($h): bool
    {
        $this->events[] = 'fsync';
        return parent::fsync($h);
    }
}

final class FailingMetadataSyncOps extends MetadataOrderOps
{
    public function fsync($h): bool
    {
        $this->events[] = 'fsync';
        return false;
    }
}

final class FstatMutationOps extends SandboxFileOps
{
    private int $calls = 0;

    public function __construct(private int $mutateCall)
    {
    }

    public function fstat($h): array|false
    {
        $st = parent::fstat($h);
        ++$this->calls;
        if (is_array($st) && $this->calls === $this->mutateCall) { ++$st['ino']; }
        return $st;
    }
}

final class ContentMutationOps extends SandboxFileOps
{
    public function readAll($h, int $length): string|false
    {
        $bytes = parent::readAll($h, $length);
        if (is_string($bytes) && $bytes !== '') { $bytes[0] = $bytes[0] === 'x' ? 'y' : 'x'; }
        return $bytes;
    }
}

final class FailingRootOwnershipOps extends SandboxFileOps
{
    public function __construct(private string $operation)
    {
    }

    public function euid(): int { return 0; }

    public function lstat(string $path): array|false
    {
        $st = parent::lstat($path);
        if (is_array($st)) { $st['uid'] = 0; }
        return $st;
    }

    public function chown(string $path, int $uid): bool { return $this->operation !== 'chown'; }
    public function chgrp(string $path, int $gid): bool { return $this->operation !== 'chgrp'; }
}

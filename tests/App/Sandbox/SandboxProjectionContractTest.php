<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Identity\SourceOpenAttestation;
use Funnypot\App\Sandbox\Projection\ProjectionDestinationOwner;
use Funnypot\App\Sandbox\Projection\ProjectionEntryRegistry;
use Funnypot\App\Sandbox\Projection\ProjectionRegistryEntry;
use Funnypot\App\Sandbox\Projection\RestartConsumer;
use Funnypot\App\Sandbox\Projection\SandboxProjection;
use Funnypot\App\Sandbox\Projection\SandboxProjectionEntry;
use Funnypot\App\Sandbox\Projection\SandboxProjectionException;
use Funnypot\App\Sandbox\Projection\SandboxProjectionSource;
use Funnypot\App\Sandbox\Projection\SandboxViewMaterializer;
use Funnypot\App\Service\CanonicalJson;
use Funnypot\App\Service\EffectiveExposureArtifact;
use PHPUnit\Framework\TestCase;

final class SandboxProjectionContractTest extends TestCase
{
    public function testDescriptorOrderingAndDomainSeparatedDigestArePinned(): void
    {
        $a = self::row(0);
        $b = self::row(1);
        $registry = new ProjectionEntryRegistry([$a, $b]);
        $forward = self::projection($registry, [self::entry($a), self::entry($b)]);
        $reverse = self::projection($registry, [self::entry($b), self::entry($a)]);
        self::assertSame($forward->bytes(), $reverse->bytes());
        self::assertSame('d11ee5f20656fb7ee3ffee1ff8e66a5c585848638a137840575d55656e469fda', $forward->digest());
    }

    public function testManifestAndContentDigestVectorsArePinned(): void
    {
        $content = 'bounded content';
        self::assertSame('7c45c5205283aa023a84a6256ce627c6847706d1af6e8b5d0a0650779c884d7d', hash('sha256', $content));
        $manifest = [
            'schema' => SandboxViewMaterializer::MANIFEST_SCHEMA,
            'generation' => str_repeat('1', 32),
            'created_at' => 1700000000,
            'ownership_applied' => false,
            'effective_schema' => EffectiveExposureArtifact::SCHEMA,
            'effective_revision' => 1,
            'effective_generation' => str_repeat('2', 32),
            'effective_hash' => str_repeat('3', 64),
            'projection_registry_hash' => str_repeat('4', 64),
            'projection_sha256' => str_repeat('5', 64),
            'entries' => [[
                'entry_id' => 'test-entry-00',
                'destination_id' => 'upload-sample/test-00',
                'content_sha256' => hash('sha256', $content),
            ]],
        ];
        self::assertSame('84538f65e1f7c42d8a1f0d043105443ad6a75bc4d4f774bc9b309ad7de328ee4', CanonicalJson::digest(SandboxViewMaterializer::MANIFEST_HASH_DOMAIN, $manifest));
    }

    public function testRegistryAndDescriptorEnforceExactEntryCeiling(): void
    {
        $rows = [];
        for ($i = 0; $i < SandboxProjection::MAX_ENTRIES; ++$i) { $rows[] = self::row($i); }
        $registry = new ProjectionEntryRegistry($rows);
        self::assertCount(SandboxProjection::MAX_ENTRIES, $registry->entries());
        self::projection($registry, array_map(static fn (ProjectionRegistryEntry $row): SandboxProjectionEntry => self::entry($row), $rows));

        $this->expectException(SandboxProjectionException::class);
        new ProjectionEntryRegistry([...$rows, self::row(SandboxProjection::MAX_ENTRIES)]);
    }

    public function testPathCeilingAccepts512AndRejects513Bytes(): void
    {
        $prefix = 'views/upload-sample/';
        $atLimit = $prefix . str_repeat('a', SandboxProjection::MAX_PATH_BYTES - strlen($prefix));
        self::assertSame(SandboxProjection::MAX_PATH_BYTES, strlen($atLimit));
        self::row(0, $atLimit);

        $this->expectException(SandboxProjectionException::class);
        self::row(0, $atLimit . 'a');
    }

    public function testContentLengthCeilingAcceptsOneMiBAndRejectsOneByteMore(): void
    {
        $row = self::row(0);
        $registry = new ProjectionEntryRegistry([$row]);
        self::projection($registry, [self::entry($row, SandboxProjection::MAX_CONTENT_BYTES)]);

        $this->expectException(SandboxProjectionException::class);
        self::projection($registry, [self::entry($row, SandboxProjection::MAX_CONTENT_BYTES + 1)]);
    }

    public function testDescriptorCeilingAccepts256KiBAndRejectsOneByteMore(): void
    {
        $row = self::row(0);
        $registry = new ProjectionEntryRegistry([$row]);
        $base = self::projection($registry, [self::entry($row, 0, ['padding' => ''])]);
        $padding = SandboxProjection::MAX_BYTES - strlen($base->bytes());
        $exact = self::projection($registry, [self::entry($row, 0, ['padding' => str_repeat('x', $padding)])]);
        self::assertSame(SandboxProjection::MAX_BYTES, strlen($exact->bytes()));

        $this->expectException(SandboxProjectionException::class);
        self::projection($registry, [self::entry($row, 0, ['padding' => str_repeat('x', $padding + 1)])]);
    }

    public function testRuntimeAndProjectionNamespacesContainNoSecondCanonicalJsonWriter(): void
    {
        $root = dirname(__DIR__, 3) . '/src/App';
        $files = [...glob($root . '/Runtime/*.php'), ...glob($root . '/Sandbox/Projection/*.php')];
        self::assertNotEmpty($files);
        foreach ($files as $file) {
            $source = (string) file_get_contents($file);
            self::assertStringNotContainsString('json_encode(', $source, basename($file));
            self::assertStringNotContainsString('hash_hmac(', $source, basename($file));
            self::assertStringNotContainsString('"\\0"', $source, basename($file));
        }
    }

    private static function row(int $i, ?string $path = null): ProjectionRegistryEntry
    {
        $suffix = sprintf('%02d', $i);
        return new ProjectionRegistryEntry(
            'test-source-' . $suffix . '/v1', 'test-entry-' . $suffix, ProjectionRegistryEntry::REQUIRED,
            ProjectionDestinationOwner::UPLOAD_SAMPLE, 'upload-sample/test-' . $suffix,
            $path ?? 'views/upload-sample/test-' . $suffix . '/value.conf', 0500, 0400, 'private',
            [RestartConsumer::UPLOAD_SAMPLE], [SourceOpenAttestation::GENERATED_ANONYMOUS], ProjectionRegistryEntry::ZERO_ANONYMOUS,
        );
    }

    /** @param array<string,mixed> $envelope */
    private static function entry(ProjectionRegistryEntry $row, int $length = 0, array $envelope = []): SandboxProjectionEntry
    {
        return new SandboxProjectionEntry($row, new SandboxProjectionSource(
            $row->entrySchema, SourceOpenAttestation::GENERATED_ANONYMOUS, 1, 2, 0100600, 0, 0, 0,
            $length, str_repeat('6', 64), $envelope,
        ));
    }

    /** @param list<SandboxProjectionEntry> $entries */
    private static function projection(ProjectionEntryRegistry $registry, array $entries): SandboxProjection
    {
        return new SandboxProjection(
            str_repeat('1', 32), 'fpph1_' . str_repeat('7', 64), 'fpkc1_' . str_repeat('8', 64), str_repeat('9', 64),
            EffectiveExposureArtifact::SCHEMA, 1, str_repeat('2', 32), str_repeat('3', 64),
            $registry->registryHash(), $entries,
        );
    }
}

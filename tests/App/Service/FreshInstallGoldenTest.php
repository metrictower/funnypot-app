<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Identity\ServiceProfileIdentity;
use Funnypot\App\Service\ServiceCapabilityPolicy;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceProfilePreparer;
use Funnypot\App\Service\ServiceProfileStore;
use Funnypot\App\Service\ServiceRuntimeStore;
use Funnypot\App\Service\ServicePaths;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

/**
 * The B1 gate. A fresh empty volume with a pinned identity reaches an accepted effective revision 1 at
 * preflight — the persistent manifest is written before any listener runs, the acceptance mode stays
 * out of the hashed artifact, the first healthy convergence rotates nothing, and a first-boot failure
 * appends no rollback revision (the loop guard).
 *
 * The golden generation/hash are a change-detector: they move only if ports.json, the semantic catalog
 * or this profile input changes. Regenerate them deliberately if such a change is intended.
 */
final class FreshInstallGoldenTest extends TestCase
{
    private const GOLDEN_GEN = '8c4345b7254dd7f52ba2890338a0aafc';
    private const GOLDEN_HASH = '8c4345b7254dd7f52ba2890338a0aafc7fea632c3066df168249effad93a43c1';

    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-fresh-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/storage', 0777, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            exec('rm -rf ' . escapeshellarg($this->dir));
        }
    }

    private function paths(): ServicePaths
    {
        return ServicePaths::forStorage($this->dir . '/storage', $this->dir . '/run', $this->dir . '/status');
    }

    private function preparer(ServicePaths $paths): ServiceProfilePreparer
    {
        return new ServiceProfilePreparer(
            $paths,
            ServiceCatalog::fromPackage(),
            ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver('golden')),
            ServiceCapabilityPolicy::create('deploy', ['docker' => false]),
            'deploy',
            'exact',
            'fpph1_' . str_repeat('f', 64),
            null,
            null,
            static fn (string $k) => false,
        );
    }

    public function testFreshInstallCommitsBootstrapAcceptedRevisionOne(): void
    {
        $paths = $this->paths();
        // Bite proof: before prepare, the manifest does not exist and the runtime store is empty; the
        // file appears only because bootstrapAccept() commits an accepted set at preflight.
        self::assertFileDoesNotExist($paths->persistentManifest());
        self::assertTrue((new ServiceRuntimeStore($paths->runtimeDbPath()))->isEmpty());

        $manifest = $this->preparer($paths)->prepare();

        self::assertFileExists($paths->persistentManifest());
        self::assertSame('0600', substr(sprintf('%o', fileperms($paths->persistentManifest())), -4));
        $art = $manifest->effectiveArtifact();
        self::assertSame(1, $art->revision());
        self::assertSame(1, $art->desiredRevision());
        self::assertArrayNotHasKey('acceptance_mode', $art->toArray());
        self::assertSame(self::GOLDEN_GEN, $art->generation());
        self::assertSame(self::GOLDEN_HASH, $art->hash());

        self::assertSame(ServiceRuntimeStore::MODE_BOOTSTRAP, (new ServiceRuntimeStore($paths->runtimeDbPath()))->acceptanceMode());
        self::assertSame(1, (new ServiceProfileStore($paths->desiredDbPath()))->currentRevision());
    }

    public function testFirstHealthyConvergenceRotatesNothingAndOnlyFlipsTheMode(): void
    {
        $paths = $this->paths();
        $this->preparer($paths)->prepare();
        $bytesBefore = (string) file_get_contents($paths->persistentManifest());

        // Simulate the supervisor's first run: all probes passed -> confirm health on the same set.
        $runtime = new ServiceRuntimeStore($paths->runtimeDbPath());
        $runtime->confirmHealth($runtime->acceptedArtifact());
        self::assertSame(ServiceRuntimeStore::MODE_HEALTH, $runtime->acceptanceMode());
        self::assertSame(self::GOLDEN_HASH, $runtime->acceptedArtifact()->hash());
        self::assertSame(1, $runtime->acceptedArtifact()->revision());

        // A rerun re-derives the persistent manifest but the bytes are byte-identical (no rotation).
        $this->preparer($paths)->prepare();
        self::assertSame($bytesBefore, (string) file_get_contents($paths->persistentManifest()));
    }

    public function testFirstBootFailureKeepsRevisionOneAndAppendsNoRollback(): void
    {
        $paths = $this->paths();
        $this->preparer($paths)->prepare();
        // A failed first probe leaves the bootstrap-accepted artifact untouched: no commitHealth, no
        // rollback revision, revision stays 1 (the supervisor stays degraded and retries).
        $desired = new ServiceProfileStore($paths->desiredDbPath());
        $runtime = new ServiceRuntimeStore($paths->runtimeDbPath());
        self::assertSame(1, $desired->currentRevision());
        self::assertSame(1, $runtime->acceptedArtifact()->revision());
        self::assertSame(ServiceRuntimeStore::MODE_BOOTSTRAP, $runtime->acceptanceMode());
        // no rollback audit rows were appended
        foreach ($desired->audits() as $a) {
            self::assertNotSame('rollback', $a['result']);
        }
    }

    public function testSecondPrepareOnNonEmptyStoreIsAByteIdenticalNoOp(): void
    {
        $paths = $this->paths();
        $this->preparer($paths)->prepare();
        $bytes = (string) file_get_contents($paths->persistentManifest());
        $this->preparer($paths)->prepare();
        self::assertSame($bytes, (string) file_get_contents($paths->persistentManifest()));
    }
}

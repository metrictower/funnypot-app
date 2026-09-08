<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Runtime\RuntimePolicy;
use Funnypot\App\Sandbox\Projection\CandidateGenerationFactory;
use Funnypot\App\Sandbox\Projection\ProjectionEntryRegistry;
use Funnypot\App\Sandbox\Projection\SandboxFileOps;
use Funnypot\App\Sandbox\Projection\SandboxPaths;
use Funnypot\App\Sandbox\Projection\SandboxProjection;
use Funnypot\App\Sandbox\Projection\SandboxProjectionStore;
use Funnypot\App\Sandbox\Projection\SandboxViewMaterializer;
use Funnypot\App\Service\CanonicalJson;
use Funnypot\Tests\App\Identity\PreparedIdentityFixture;
use PHPUnit\Framework\TestCase;

final class SandboxProjectionStoreTest extends TestCase
{
    private string $dir = '';
    private CountingGenerationFactory $factory;
    private SandboxProjectionStore $store;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-store-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/sandbox', 0700, true);
        chmod($this->dir . '/sandbox', 0700);
        $ops = new SandboxFileOps();
        $registry = ProjectionEntryRegistry::v1();
        $this->factory = new CountingGenerationFactory($ops);
        $this->store = new SandboxProjectionStore(SandboxPaths::forRoot($this->dir . '/sandbox'), $registry, RuntimePolicy::fromPackage(), $ops, $this->factory);
    }

    protected function tearDown(): void
    {
        SandboxTestFiles::remove($this->dir);
    }

    public function testFirstPublicationThenUnchangedDoesNotMintASecondCandidate(): void
    {
        $prepare = fn () => PreparedIdentityFixture::prepare($this->dir, tag: 'a')['result'];
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        $first = $this->store->publish($prepare, $effective);
        self::assertSame('selected-new', $first->code);
        self::assertSame(str_repeat('1', 32), $first->generation);
        self::assertSame(1, $this->factory->calls);
        $selector = (string) file_get_contents($this->dir . '/sandbox/current.json');

        $second = $this->store->publish($prepare, $effective);
        self::assertSame('unchanged-current', $second->code);
        self::assertSame(1, $this->factory->calls);
        self::assertSame($selector, (string) file_get_contents($this->dir . '/sandbox/current.json'));
        self::assertCount(1, glob($this->dir . '/sandbox/generations/[0-9a-f]*', GLOB_ONLYDIR));
    }

    public function testChangedIdentityPublishesNewAndPreservesPreviousSelector(): void
    {
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir, tag: 'a')['result'], $effective)->code);
        $old = (string) file_get_contents($this->dir . '/sandbox/current.json');
        mkdir($this->dir . '/changed', 0700);
        $next = $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir . '/changed', tag: 'b')['result'], $effective);
        self::assertSame('selected-new', $next->code);
        self::assertSame(str_repeat('2', 32), $next->generation);
        self::assertSame($old, (string) file_get_contents($this->dir . '/sandbox/previous.json'));
    }

    public function testSelectedContentCorruptionFailsBeforePreparationOrMint(): void
    {
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selector = json_decode((string) file_get_contents($this->dir . '/sandbox/current.json'), true);
        $path = $this->dir . '/sandbox/generations/' . $selector['generation'] . '/views/web/identity/http.json';
        $bytes = (string) file_get_contents($path);
        $bytes[0] = $bytes[0] === '{' ? '[' : '{';
        chmod($path, 0600);
        file_put_contents($path, $bytes);
        chmod($path, 0400);
        $prepareCalls = 0;
        $result = $this->store->publish(function () use (&$prepareCalls) { ++$prepareCalls; return PreparedIdentityFixture::prepare($this->dir)['result']; }, $effective);
        self::assertSame('selected-generation-invalid', $result->code);
        self::assertSame(0, $prepareCalls);
        self::assertSame(1, $this->factory->calls);
    }

    public function testMissingEffectiveArtifactSelectsNothing(): void
    {
        $prepareCalls = 0;
        $result = $this->store->publish(function () use (&$prepareCalls) { ++$prepareCalls; return PreparedIdentityFixture::prepare($this->dir)['result']; }, static function () { throw new \RuntimeException('missing'); });
        self::assertSame('effective-artifact-missing', $result->code);
        self::assertSame(0, $prepareCalls);
        self::assertFileDoesNotExist($this->dir . '/sandbox/current.json');
    }

    public function testPublicationLockIsHeldBeforePreparationBegins(): void
    {
        $ops = new TrackingLockOps();
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $preparedWhileLocked = false;
        $result = $store->publish(function () use ($ops, &$preparedWhileLocked) {
            $preparedWhileLocked = $ops->exclusiveHeld;
            return PreparedIdentityFixture::prepare($this->dir)['result'];
        }, static fn () => SandboxProjectionProducerTest::effective());
        self::assertSame('selected-new', $result->code);
        self::assertTrue($preparedWhileLocked);
        self::assertFalse($ops->exclusiveHeld);
    }

    public function testPublicationLockTimeoutDoesNoPreparationOrCandidateMint(): void
    {
        $ops = new LockTimeoutOps();
        $factory = new CountingGenerationFactory($ops);
        $store = $this->newStore($ops, $factory);
        $prepareCalls = 0;
        $result = $store->publish(function () use (&$prepareCalls) {
            ++$prepareCalls;
            return PreparedIdentityFixture::prepare($this->dir)['result'];
        }, static fn () => SandboxProjectionProducerTest::effective());
        self::assertSame('publication-lock-timeout', $result->code);
        self::assertSame(0, $prepareCalls);
        self::assertSame(0, $factory->calls);
        self::assertSame(201, $ops->attempts);
    }

    public function testStatusIsNotReadyWhenNonRootOwnershipWasNotApplied(): void
    {
        if (posix_geteuid() === 0) { self::markTestSkipped('non-root semantics'); }
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => SandboxProjectionProducerTest::effective())->code);
        $status = $this->store->status(static fn () => SandboxProjectionProducerTest::effective());
        self::assertFalse($status['ready']);
        self::assertSame('ownership-not-applied', $status['code']);
    }

    public function testGenerationNameCollisionNeverReplacesTheExistingDirectory(): void
    {
        mkdir($this->dir . '/sandbox/generations', 0700);
        $collision = $this->dir . '/sandbox/generations/' . str_repeat('1', 32);
        mkdir($collision, 0700);
        file_put_contents($collision . '/owner-marker', 'untouched');
        $result = $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => SandboxProjectionProducerTest::effective());
        self::assertSame('generation-name-collision', $result->code);
        self::assertSame('untouched', file_get_contents($collision . '/owner-marker'));
        self::assertFileDoesNotExist($this->dir . '/sandbox/current.json');
    }

    public function testPreCommitFdatasyncFailurePreservesExactPriorSelector(): void
    {
        $ops = new FailingSyncOps();
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selector = (string) file_get_contents($this->dir . '/sandbox/current.json');
        $ops->failNextDataSync = true;
        $changed = $this->dir . '/sync-change'; mkdir($changed, 0700);
        $result = $store->publish(fn () => PreparedIdentityFixture::prepare($changed, tag: 'b')['result'], $effective);
        self::assertSame('preserved-prior', $result->code);
        self::assertSame($selector, (string) file_get_contents($this->dir . '/sandbox/current.json'));
    }

    public function testFirstInstallPreCommitFailureSelectsNothing(): void
    {
        $ops = new FailingSyncOps();
        $ops->failNextDataSync = true;
        $factory = new CountingGenerationFactory($ops);
        $store = $this->newStore($ops, $factory);
        $result = $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => SandboxProjectionProducerTest::effective());
        self::assertSame('nothing-selected', $result->code);
        self::assertFileDoesNotExist($this->dir . '/sandbox/current.json');
        self::assertSame(1, $factory->calls);
    }

    public function testEveryPreparedSourceHandleClosesOnFailure(): void
    {
        $ops = new FailingSyncOps();
        $ops->failNextDataSync = true;
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $identity = null;
        $result = $store->publish(function () use (&$identity) {
            $identity = PreparedIdentityFixture::prepare($this->dir)['result'];
            return $identity;
        }, static fn () => SandboxProjectionProducerTest::effective());
        self::assertSame('nothing-selected', $result->code);
        self::assertNotNull($identity);
        foreach ($identity->sources() as $source) { self::assertFalse(is_resource($source->handle)); }
    }

    public function testPositiveShortWritesAreRetriedUntilTheExactSelectorIsDurable(): void
    {
        $ops = new ShortWriteOps();
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $result = $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => SandboxProjectionProducerTest::effective());
        self::assertSame('selected-new', $result->code);
        self::assertGreaterThan(10, $ops->writes);
        self::assertSame('recovered-selected', $store->recover()->code);
    }

    /** @dataProvider preCommitFaults */
    public function testPreCommitWriteFlushAndCandidateRenameFaultsPreserveExactPriorSelector(string $fault): void
    {
        $ops = new PublicationFaultOps($this->dir . '/sandbox');
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selector = (string) file_get_contents($this->dir . '/sandbox/current.json');
        $ops->fault = $fault;
        $changed = $this->dir . '/fault-change-' . $fault; mkdir($changed, 0700);
        $result = $store->publish(fn () => PreparedIdentityFixture::prepare($changed, tag: 'b')['result'], $effective);
        self::assertSame('preserved-prior', $result->code);
        self::assertSame($selector, (string) file_get_contents($this->dir . '/sandbox/current.json'));
    }

    public static function preCommitFaults(): iterable
    {
        yield 'zero write' => ['write'];
        yield 'flush' => ['flush'];
        yield 'candidate rename' => ['candidate-rename'];
    }

    /** @dataProvider postRenameFaults */
    public function testPostCandidateRenameFaultIsUncertain(string $fault): void
    {
        $ops = new PublicationFaultOps($this->dir . '/sandbox');
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $prior = json_decode((string) file_get_contents($this->dir . '/sandbox/current.json'), true)['generation'];
        $ops->fault = $fault;
        $changed = $this->dir . '/fsync-change'; mkdir($changed, 0700);
        $result = $store->publish(fn () => PreparedIdentityFixture::prepare($changed, tag: 'b')['result'], $effective);
        self::assertSame('publication-uncertain', $result->code);
        self::assertSame($prior, $store->recover()->generation);
    }

    public static function postRenameFaults(): iterable
    {
        yield 'generations fsync' => ['generation-fsync'];
        yield 'selector rename' => ['selector-rename'];
    }

    public function testPostSelectorRenameFailureIsUncertainThenFixedPathRecoverySucceeds(): void
    {
        $ops = new PostCommitFsyncOps($this->dir . '/sandbox/current.json');
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $changed = $this->dir . '/post-change'; mkdir($changed, 0700);
        $ops->arm = true;
        $result = $store->publish(fn () => PreparedIdentityFixture::prepare($changed, tag: 'b')['result'], $effective);
        self::assertSame('publication-uncertain', $result->code);
        self::assertSame('recovered-selected', $store->recover()->code);
    }

    public function testEffectiveAuthorityChangeAtCasLeavesCandidateUnselected(): void
    {
        $calls = 0;
        $loader = function () use (&$calls) {
            ++$calls;
            return $calls === 1 ? SandboxProjectionProducerTest::effective() : self::effectiveFor('changed', 2);
        };
        $result = $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $loader);
        self::assertSame('exposure-generation-changed', $result->code);
        self::assertFileDoesNotExist($this->dir . '/sandbox/current.json');
        self::assertDirectoryExists($this->dir . '/sandbox/generations/' . str_repeat('1', 32));
    }

    public function testNoArgumentRollbackValidatesAndSwapsCurrentAndPrevious(): void
    {
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        $first = $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective);
        $changed = $this->dir . '/rollback-change'; mkdir($changed, 0700);
        $second = $this->store->publish(fn () => PreparedIdentityFixture::prepare($changed, tag: 'b')['result'], $effective);
        self::assertSame('selected-new', $second->code);
        $rollback = $this->store->rollback($effective);
        self::assertSame('selected-new', $rollback->code);
        self::assertSame($first->generation, $rollback->generation);
        $current = json_decode((string) file_get_contents($this->dir . '/sandbox/current.json'), true);
        $previous = json_decode((string) file_get_contents($this->dir . '/sandbox/previous.json'), true);
        self::assertSame($first->generation, $current['generation']);
        self::assertSame($second->generation, $previous['generation']);
    }

    public function testCoherentlyRehashedDuplicateManifestEntryFailsBeforePreparation(): void
    {
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selectorPath = $this->dir . '/sandbox/current.json';
        $selector = json_decode((string) file_get_contents($selectorPath), true);
        $manifestPath = $this->dir . '/sandbox/generations/' . $selector['generation'] . '/manifest.json';
        $manifest = json_decode((string) file_get_contents($manifestPath), true);
        $manifest['entries'][] = $manifest['entries'][0];
        chmod($manifestPath, 0600); file_put_contents($manifestPath, CanonicalJson::encode($manifest)); chmod($manifestPath, 0600);
        $selector['manifest_sha256'] = CanonicalJson::digest(SandboxViewMaterializer::MANIFEST_HASH_DOMAIN, $manifest);
        chmod($selectorPath, 0600); file_put_contents($selectorPath, CanonicalJson::encode($selector)); chmod($selectorPath, 0600);
        $prepareCalls = 0;
        $result = $this->store->publish(function () use (&$prepareCalls) { ++$prepareCalls; return PreparedIdentityFixture::prepare($this->dir)['result']; }, $effective);
        self::assertSame('selected-generation-invalid', $result->code);
        self::assertSame(0, $prepareCalls);
    }

    public function testCoherentlyRehashedTopLevelIdentityHashMismatchFailsBeforePreparation(): void
    {
        $this->assertCoherentlyRehashedProjectionMutationFails(static function (array &$projection): void {
            $projection['identity_public_hash'] = 'fpph1_' . str_repeat('0', 64);
        });
    }

    public function testCoherentlyRehashedTopLevelKeysetCommitmentMismatchFailsBeforePreparation(): void
    {
        $this->assertCoherentlyRehashedProjectionMutationFails(static function (array &$projection): void {
            $projection['identity_keyset_commitment'] = 'fpkc1_' . str_repeat('0', 64);
        });
    }

    public function testCoherentlyRehashedWrongEffectiveSchemaFailsBeforePreparation(): void
    {
        $this->assertCoherentlyRehashedProjectionMutationFails(static function (array &$projection): void {
            $projection['effective_schema'] = 'funnypot-effective-service-exposure/v2';
        });
    }

    public function testCoherentlyRehashedStaleRuntimePolicyFailsBeforePreparation(): void
    {
        $this->assertCoherentlyRehashedProjectionMutationFails(static function (array &$projection): void {
            $projection['runtime_policy_hash'] = str_repeat('0', 64);
        });
    }

    public function testCoherentlyRehashedCrossBundleIdentitySubstitutionFailsBeforePreparation(): void
    {
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selectorPath = $this->dir . '/sandbox/current.json';
        $selector = json_decode((string) file_get_contents($selectorPath), true);
        $generationDir = $this->dir . '/sandbox/generations/' . $selector['generation'];
        $projectionPath = $generationDir . '/projection.json';
        $manifestPath = $generationDir . '/manifest.json';
        $projection = json_decode((string) file_get_contents($projectionPath), true);
        $manifest = json_decode((string) file_get_contents($manifestPath), true);
        $rows = [];
        foreach ($projection['entries'] as $i => $row) { $rows[$row['entry_id']] = $i; }
        $http = $rows['web-http-identity'];
        $shell = $rows['protocol-shell-identity'];
        $shellBytes = (string) file_get_contents($generationDir . '/views/protocols/identity/shell.json');
        $httpPath = $generationDir . '/views/web/identity/http.json';
        chmod($httpPath, 0600);
        file_put_contents($httpPath, $shellBytes);
        chmod($httpPath, 0400);
        $projection['entries'][$http]['envelope'] = $projection['entries'][$shell]['envelope'];
        $projection['entries'][$http]['byte_length'] = strlen($shellBytes);
        $projection['entries'][$http]['content_sha256'] = hash('sha256', $shellBytes);
        foreach ($manifest['entries'] as &$entry) {
            if ($entry['entry_id'] === 'web-http-identity') { $entry['content_sha256'] = hash('sha256', $shellBytes); }
        }
        unset($entry);
        $this->rewriteProjectionAuthority($projectionPath, $manifestPath, $selectorPath, $projection, $manifest, $selector);
        $prepareCalls = 0;
        $result = $this->store->publish(function () use (&$prepareCalls) {
            ++$prepareCalls;
            return PreparedIdentityFixture::prepare($this->dir)['result'];
        }, $effective);
        self::assertSame('selected-generation-invalid', $result->code);
        self::assertSame(0, $prepareCalls);
    }

    public function testLockBypassingSelectorChangeIsDetectedByCas(): void
    {
        $ops = new SelectorBypassOps($this->dir . '/sandbox/current.json');
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $changed = $this->dir . '/cas-change'; mkdir($changed, 0700);
        $ops->arm = true;
        $result = $store->publish(fn () => PreparedIdentityFixture::prepare($changed, tag: 'b')['result'], $effective);
        self::assertSame('publication-lost-race', $result->code);
        self::assertSame(2, count(glob($this->dir . '/sandbox/generations/[0-9a-f]*', GLOB_ONLYDIR)));
    }

    public function testEightGenerationCeilingFailsBeforeNinthCandidateIsMinted(): void
    {
        for ($revision = 1; $revision <= 8; ++$revision) {
            $effective = self::effectiveFor('ceiling-' . $revision, $revision);
            $result = $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => $effective);
            self::assertSame('selected-new', $result->code);
        }
        $ninth = self::effectiveFor('ceiling-9', 9);
        $result = $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => $ninth);
        self::assertSame('preserved-prior', $result->code);
        self::assertSame(8, $this->factory->calls);
        self::assertCount(8, glob($this->dir . '/sandbox/generations/[0-9a-f]*', GLOB_ONLYDIR));
    }

    public function testCleanupRemovesAtMostTwoOldExactResiduesUsingTrustedCreationTimes(): void
    {
        $ops = new MutableClockOps();
        $factory = new CountingGenerationFactory($ops);
        $store = $this->newStore($ops, $factory);
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selector = (string) file_get_contents($this->dir . '/sandbox/current.json');
        $id = json_decode($selector, true)['generation'];
        $candidateId = str_repeat('a', 32);
        $candidate = $this->dir . '/sandbox/generations/.candidate-' . $candidateId;
        mkdir($candidate, 0700);
        file_put_contents($candidate . '/.created-at.json', CanonicalJson::encode(['schema' => 'sandbox-candidate-residue/v1', 'generation' => $candidateId, 'created_at' => 1000]));
        chmod($candidate . '/.created-at.json', 0600);
        $temp = $this->dir . '/sandbox/.current-' . $id . '.tmp';
        file_put_contents($temp, $selector); chmod($temp, 0600);
        $thirdId = str_repeat('b', 32);
        $third = $this->dir . '/sandbox/generations/.candidate-' . $thirdId;
        mkdir($third, 0700);
        file_put_contents($third . '/.created-at.json', CanonicalJson::encode(['schema' => 'sandbox-candidate-residue/v1', 'generation' => $thirdId, 'created_at' => 1000]));
        chmod($third . '/.created-at.json', 0600);
        $ops->now = 1000 + SandboxProjectionStore::RETENTION_SECONDS;
        $changed = self::effectiveFor('cleanup', 2);
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => $changed)->code);
        $remaining = array_filter([$candidate, $temp, $third], static fn (string $path): bool => file_exists($path));
        self::assertCount(1, $remaining, 'one of three eligible residues remains because cleanup is bounded to two');
    }

    public function testRetentionAlwaysProtectsCurrentAndPreviousBeforeRemovingOlderGeneration(): void
    {
        $ops = new MutableClockOps();
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        for ($revision = 1; $revision <= 2; ++$revision) {
            $effective = self::effectiveFor('protected-' . $revision, $revision);
            self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => $effective)->code);
        }
        $gen1 = $this->dir . '/sandbox/generations/' . str_repeat('1', 32);
        $gen2 = $this->dir . '/sandbox/generations/' . str_repeat('2', 32);
        $ops->now += SandboxProjectionStore::RETENTION_SECONDS;
        $third = self::effectiveFor('protected-3', 3);
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => $third)->code);
        self::assertDirectoryExists($gen1, 'the prior previous generation was protected during cleanup');
        self::assertDirectoryExists($gen2);

        $fourth = self::effectiveFor('protected-4', 4);
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => $fourth)->code);
        self::assertDirectoryDoesNotExist($gen1);
        self::assertDirectoryExists($gen2, 'the current previous generation remains protected');
    }

    public function testCleanupIgnoresDirectoryMtimeAndNeverRemovesFutureOrRecentRecords(): void
    {
        $ops = new MutableClockOps();
        $store = $this->newStore($ops, new CountingGenerationFactory($ops));
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => SandboxProjectionProducerTest::effective())->code);
        $ops->now = 200000;
        $future = $this->candidateResidue(str_repeat('a', 32), $ops->now + 1);
        $recent = $this->candidateResidue(str_repeat('b', 32), $ops->now - SandboxProjectionStore::RETENTION_SECONDS + 1);
        touch($future, 1);
        touch($recent, 1);
        $changed = self::effectiveFor('mtime-is-not-authority', 2);
        self::assertSame('selected-new', $store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], static fn () => $changed)->code);
        self::assertDirectoryExists($future);
        self::assertDirectoryExists($recent);
    }

    public function testRootReadbackRejectsWrongDestinationFileGroup(): void
    {
        if (posix_geteuid() !== 0) { self::markTestSkipped('root-only ownership acceptance'); }
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selector = json_decode((string) file_get_contents($this->dir . '/sandbox/current.json'), true);
        $path = $this->dir . '/sandbox/generations/' . $selector['generation'] . '/views/web/identity/http.json';
        chgrp($path, 0);
        self::assertSame('selected-generation-invalid', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
    }

    public function testRootReadbackRejectsWrongDestinationDirectoryGroup(): void
    {
        if (posix_geteuid() !== 0) { self::markTestSkipped('root-only ownership acceptance'); }
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selector = json_decode((string) file_get_contents($this->dir . '/sandbox/current.json'), true);
        $path = $this->dir . '/sandbox/generations/' . $selector['generation'] . '/views/web/identity';
        chgrp($path, 0);
        self::assertSame('selected-generation-invalid', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
    }

    private function newStore(SandboxFileOps $ops, CandidateGenerationFactory $factory): SandboxProjectionStore
    {
        $registry = ProjectionEntryRegistry::v1();
        return new SandboxProjectionStore(SandboxPaths::forRoot($this->dir . '/sandbox'), $registry, RuntimePolicy::fromPackage(), $ops, $factory);
    }

    /** @param callable(array<string,mixed>&):void $mutate */
    private function assertCoherentlyRehashedProjectionMutationFails(callable $mutate): void
    {
        $effective = static fn () => SandboxProjectionProducerTest::effective();
        self::assertSame('selected-new', $this->store->publish(fn () => PreparedIdentityFixture::prepare($this->dir)['result'], $effective)->code);
        $selectorPath = $this->dir . '/sandbox/current.json';
        $selector = json_decode((string) file_get_contents($selectorPath), true);
        $generationDir = $this->dir . '/sandbox/generations/' . $selector['generation'];
        $projectionPath = $generationDir . '/projection.json';
        $manifestPath = $generationDir . '/manifest.json';
        $projection = json_decode((string) file_get_contents($projectionPath), true);
        $manifest = json_decode((string) file_get_contents($manifestPath), true);
        $mutate($projection);
        $this->rewriteProjectionAuthority($projectionPath, $manifestPath, $selectorPath, $projection, $manifest, $selector);
        $prepareCalls = 0;
        $result = $this->store->publish(function () use (&$prepareCalls) {
            ++$prepareCalls;
            return PreparedIdentityFixture::prepare($this->dir)['result'];
        }, $effective);
        self::assertSame('selected-generation-invalid', $result->code);
        self::assertSame(0, $prepareCalls);
    }

    /** @param array<string,mixed> $projection @param array<string,mixed> $manifest @param array<string,mixed> $selector */
    private function rewriteProjectionAuthority(string $projectionPath, string $manifestPath, string $selectorPath, array $projection, array $manifest, array $selector): void
    {
        file_put_contents($projectionPath, CanonicalJson::encode($projection));
        chmod($projectionPath, 0600);
        $projectionHash = CanonicalJson::digest(SandboxProjection::HASH_DOMAIN, $projection);
        $manifest['projection_sha256'] = $projectionHash;
        file_put_contents($manifestPath, CanonicalJson::encode($manifest));
        chmod($manifestPath, 0600);
        $selector['projection_sha256'] = $projectionHash;
        $selector['manifest_sha256'] = CanonicalJson::digest(SandboxViewMaterializer::MANIFEST_HASH_DOMAIN, $manifest);
        file_put_contents($selectorPath, CanonicalJson::encode($selector));
        chmod($selectorPath, 0600);
    }

    private function candidateResidue(string $id, int $createdAt): string
    {
        $path = $this->dir . '/sandbox/generations/.candidate-' . $id;
        mkdir($path, 0700);
        $record = $path . '/.created-at.json';
        file_put_contents($record, CanonicalJson::encode([
            'schema' => 'sandbox-candidate-residue/v1', 'generation' => $id, 'created_at' => $createdAt,
        ]));
        chmod($record, 0600);
        return $path;
    }

    private static function effectiveFor(string $tag, int $revision): \Funnypot\App\Service\EffectiveExposureArtifact
    {
        return \Funnypot\App\Service\EffectiveExposureArtifact::create(
            $revision, $revision, 'deploy', 'exact', str_repeat('a', 64), 'fpph1_' . str_repeat('b', 64),
            hash('sha256', 'plan-' . $tag), hash('sha256', 'published-' . $tag),
            ['mode' => 'named', 'bundle' => 'web-only', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('e', 32)],
            [], [], [],
        );
    }
}

final class CountingGenerationFactory extends CandidateGenerationFactory
{
    public int $calls = 0;

    public function mint(): string
    {
        ++$this->calls;
        return str_repeat((string) $this->calls, 32);
    }
}

class FailingSyncOps extends SandboxFileOps
{
    public bool $failNextDataSync = false;

    public function fdatasync($h): bool
    {
        if ($this->failNextDataSync) { $this->failNextDataSync = false; return false; }
        return parent::fdatasync($h);
    }
}

final class PostCommitFsyncOps extends FailingSyncOps
{
    public bool $arm = false;
    private bool $failNextFsync = false;

    public function __construct(private string $currentPath) {}

    public function rename(string $from, string $to): bool
    {
        $ok = parent::rename($from, $to);
        if ($ok && $this->arm && $to === $this->currentPath) { $this->failNextFsync = true; $this->arm = false; }
        return $ok;
    }

    public function fsync($h): bool
    {
        if ($this->failNextFsync) { $this->failNextFsync = false; return false; }
        return parent::fsync($h);
    }
}

final class SelectorBypassOps extends SandboxFileOps
{
    public bool $arm = false;
    public function __construct(private string $currentPath) {}
    public function rename(string $from, string $to): bool
    {
        $ok = parent::rename($from, $to);
        if ($ok && $this->arm && str_contains($from, '/.candidate-')) {
            chmod($this->currentPath, 0600);
            file_put_contents($this->currentPath, (string) file_get_contents($this->currentPath) . "\n");
            chmod($this->currentPath, 0600);
            $this->arm = false;
        }
        return $ok;
    }
}

final class MutableClockOps extends SandboxFileOps
{
    public int $now = 1000;
    public function time(): int { return $this->now; }
}

final class ShortWriteOps extends SandboxFileOps
{
    public int $writes = 0;

    public function write($h, string $bytes)
    {
        ++$this->writes;
        return parent::write($h, substr($bytes, 0, max(1, intdiv(strlen($bytes), 2))));
    }
}

final class PublicationFaultOps extends SandboxFileOps
{
    public ?string $fault = null;
    /** @var array<int,string> */
    private array $directoryHandles = [];

    public function __construct(private string $root)
    {
    }

    public function write($h, string $bytes)
    {
        if ($this->fault === 'write') { $this->fault = null; return 0; }
        return parent::write($h, $bytes);
    }

    public function flush($h): bool
    {
        if ($this->fault === 'flush') { $this->fault = null; return false; }
        return parent::flush($h);
    }

    public function rename(string $from, string $to): bool
    {
        if ($this->fault === 'candidate-rename' && str_contains($from, '/.candidate-')) {
            $this->fault = null;
            return false;
        }
        if ($this->fault === 'selector-rename' && $to === $this->root . '/current.json') {
            $this->fault = null;
            return false;
        }
        return parent::rename($from, $to);
    }

    public function openDir(string $path)
    {
        $h = parent::openDir($path);
        if (is_resource($h)) { $this->directoryHandles[(int) $h] = $path; }
        return $h;
    }

    public function fsync($h): bool
    {
        if ($this->fault === 'generation-fsync' && ($this->directoryHandles[(int) $h] ?? null) === $this->root . '/generations') {
            $this->fault = null;
            return false;
        }
        return parent::fsync($h);
    }
}

final class TrackingLockOps extends SandboxFileOps
{
    public bool $exclusiveHeld = false;

    public function flock($h, int $op): bool
    {
        $ok = parent::flock($h, $op);
        if ($ok && ($op & LOCK_EX) === LOCK_EX) { $this->exclusiveHeld = true; }
        if ($ok && $op === LOCK_UN) { $this->exclusiveHeld = false; }
        return $ok;
    }
}

final class LockTimeoutOps extends SandboxFileOps
{
    public int $attempts = 0;

    public function flock($h, int $op): bool
    {
        if (($op & LOCK_EX) === LOCK_EX) { ++$this->attempts; return false; }
        return parent::flock($h, $op);
    }

    public function sleepMs(int $ms): void
    {
    }
}

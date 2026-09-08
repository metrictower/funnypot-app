<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Runtime\RuntimePolicy;
use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Sandbox\Projection\ProjectionEntryRegistry;
use Funnypot\App\Sandbox\Projection\SandboxProjection;
use Funnypot\App\Sandbox\Projection\SandboxProjectionException;
use Funnypot\App\Sandbox\Projection\SandboxProjectionProducer;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\Tests\App\Identity\PreparedIdentityFixture;
use PHPUnit\Framework\TestCase;

final class SandboxProjectionProducerTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void { $this->dir = sys_get_temp_dir() . '/fp-producer-' . bin2hex(random_bytes(6)); mkdir($this->dir, 0700); }
    protected function tearDown(): void { SandboxTestFiles::remove($this->dir); }

    public function testDescriptorIsCanonicalBoundedPathFreeAndUsesAllRequiredSources(): void
    {
        $identity = PreparedIdentityFixture::prepare($this->dir)['result'];
        try {
            $producer = new SandboxProjectionProducer(ProjectionEntryRegistry::v1(), RuntimePolicy::fromPackage());
            $projection = $producer->produce(str_repeat('1', 32), $identity, self::effective());
            self::assertCount(7, $projection->entries); // seven required rows; absent admin pair is valid
            self::assertLessThanOrEqual(SandboxProjection::MAX_BYTES, strlen($projection->bytes()));
            self::assertSame($projection->bytes(), \Funnypot\App\Service\CanonicalJson::encode($projection->toArray()));
            self::assertStringNotContainsString($this->dir, $projection->bytes());
            self::assertStringNotContainsString('source_path', $projection->bytes());
            self::assertSame($identity->publicPersonaHash, $projection->identityPublicHash);
        } finally { $identity->close(); }
    }

    public function testProducerComparesLiveHandleAgainstAttestation(): void
    {
        $identity = PreparedIdentityFixture::prepare($this->dir)['result'];
        fclose($identity->httpBundle->handle);
        $this->expectException(SandboxProjectionException::class);
        $this->expectExceptionMessage('source-attestation-drift');
        (new SandboxProjectionProducer(ProjectionEntryRegistry::v1(), RuntimePolicy::fromPackage()))
            ->produce(str_repeat('2', 32), $identity, self::effective());
    }

    public function testProducerRejectsEffectiveArtifactForAnotherPublicIdentity(): void
    {
        $identity = PreparedIdentityFixture::prepare($this->dir)['result'];
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('effective-artifact-mismatch');
            (new SandboxProjectionProducer(ProjectionEntryRegistry::v1(), RuntimePolicy::fromPackage()))
                ->produce(str_repeat('2', 32), $identity, self::effective('fpph1_' . str_repeat('0', 64)));
        } finally {
            $identity->close();
        }
    }

    /** @dataProvider attestationFields */
    public function testProducerRejectsEveryChangedAttestationField(string $field): void
    {
        $identity = PreparedIdentityFixture::prepare($this->dir)['result'];
        try {
            $this->expectException(SandboxProjectionException::class);
            $this->expectExceptionMessage('source-attestation-drift');
            (new SandboxProjectionProducer(ProjectionEntryRegistry::v1(), RuntimePolicy::fromPackage(), new ProducerFstatDriftOps($field)))
                ->produce(str_repeat('3', 32), $identity, self::effective());
        } finally {
            $identity->close();
        }
    }

    public static function attestationFields(): iterable
    {
        foreach (['dev', 'ino', 'mode', 'uid', 'gid', 'nlink'] as $field) { yield $field => [$field]; }
    }

    public static function effective(string $identityPublicHash = 'fpph1_c5b906a8c87e9125c06409a9c69784b14ee0e62578ea0759f9b59b7c4a989fe6'): EffectiveExposureArtifact
    {
        return EffectiveExposureArtifact::create(
            1, 1, 'deploy', 'exact', str_repeat('a', 64), $identityPublicHash,
            str_repeat('c', 64), str_repeat('d', 64),
            ['mode' => 'named', 'bundle' => 'web-only', 'base_family' => 'linux', 'variant_id' => 'spv1_' . str_repeat('e', 32)],
            [], [], [],
        );
    }
}

final class ProducerFstatDriftOps extends IdentityFileOps
{
    public function __construct(private string $field)
    {
    }

    public function fstat($h): array|false
    {
        $st = parent::fstat($h);
        if (is_array($st)) { ++$st[$this->field]; }
        return $st;
    }
}

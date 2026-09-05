<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityKeyDeriver;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\ServiceProfileIdentity;
use PHPUnit\Framework\TestCase;

final class ServiceProfileIdentityTest extends TestCase
{
    private string $base = '';

    protected function setUp(): void
    {
        $this->base = (string) realpath(sys_get_temp_dir()) . '/fp_svcid_' . bin2hex(random_bytes(5));
    }

    protected function tearDown(): void
    {
        if ($this->base !== '' && is_dir($this->base)) {
            exec('rm -rf ' . escapeshellarg($this->base));
        }
    }

    public function testRankingKeyIsTheServiceProfileDomainKey(): void
    {
        $d = IdentityTestSupport::deriver('a');
        $id = ServiceProfileIdentity::fromDeriver($d);
        self::assertSame(32, strlen($id->rankingKey()));
        self::assertSame($d->serviceProfileKey(), $id->rankingKey());
    }

    public function testDifferentMastersProduceDifferentRankingKeys(): void
    {
        $a = ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver('a'))->rankingKey();
        $b = ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver('b'))->rankingKey();
        self::assertNotSame($a, $b);
    }

    public function testPayloadRoundTripPreservesRankingKey(): void
    {
        $id = ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver('a'));
        $back = ServiceProfileIdentity::fromPayload($id->toPayload(), 'fpph1_x');
        self::assertSame($id->rankingKey(), $back->rankingKey());
        self::assertSame('fpph1_x', $back->publicPersonaHash());
    }

    public function testLoadReadsTheScopedBundleFromTheRuntimeRoot(): void
    {
        $d = IdentityTestSupport::deriver('a');
        $id = ServiceProfileIdentity::fromDeriver($d);
        $runtime = $this->base . '/run';
        $paths = IdentityPaths::forStorage($this->base . '/storage', $runtime);
        mkdir($paths->httpRuntimeDir(), 0750, true);
        chmod($runtime, 0755);
        chmod($paths->httpRuntimeDir(), 0750);
        $persona = IdentityKeyDeriver::publicPersonaHash('httptest');
        $bundle = [
            'envelope' => [
                'schema' => 'funnypot-identity-bundle/v1',
                'bundle' => ServiceProfileIdentity::BUNDLE,
                'source' => 'generated',
                'public_persona_hash' => $persona,
                'keyset_commitment' => $d->keysetCommitment(),
            ],
            'payload' => $id->toPayload(),
        ];
        file_put_contents($paths->serviceProfileBundlePath(), json_encode($bundle));
        chmod($paths->serviceProfileBundlePath(), 0640);

        $loaded = ServiceProfileIdentity::load($paths);
        self::assertSame($id->rankingKey(), $loaded->rankingKey());
        self::assertSame($persona, $loaded->publicPersonaHash());
    }
}

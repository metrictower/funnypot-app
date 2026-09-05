<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Identity\ServiceProfileIdentity;
use Funnypot\App\Service\ServiceCapabilityPolicy;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceProfileInput;
use Funnypot\App\Service\ServiceProfileResolver;
use Funnypot\App\Service\ServiceResolutionReason;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

final class ServiceProfileResolverTest extends TestCase
{
    private ServiceCatalog $catalog;
    private ServiceProfileResolver $resolver;

    protected function setUp(): void
    {
        $this->catalog = ServiceCatalog::fromPackage();
        $this->resolver = new ServiceProfileResolver();
    }

    private function identity(string $tag = 'a'): ServiceProfileIdentity
    {
        return ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver($tag));
    }

    private function policy(bool $docker = false, string $target = 'deploy', bool $protocolsDisabled = false, ?int $ceiling = null): ServiceCapabilityPolicy
    {
        return ServiceCapabilityPolicy::create($target, ['docker' => $docker], $protocolsDisabled, null, $ceiling);
    }

    public function testNamedLinuxWebResolvesSshOneDatastoreAndOneHttpAlias(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 10]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity());
        self::assertTrue($p->ok, implode(',', $p->errorCodes()));
        $r = $p->resolved;
        self::assertContains('ssh', $r->serviceIds);
        self::assertContains('web-alt-http', $r->serviceIds);
        $datastores = array_intersect($r->serviceIds, ['mysql', 'postgresql', 'redis', 'mongodb']);
        self::assertCount(1, $datastores);
        self::assertSame(3, $r->logicalServiceCount());
        self::assertSame(2, $r->processCount()); // ssh + one datastore; web-alt-http has no process
        self::assertSame(3, $r->exposureCount());
        self::assertSame('linux', $r->baseFamily);
        self::assertStringStartsWith('spv1_', $r->variantId);
    }

    public function testWindowsBusinessHasNoAdAndOneMgmtService(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'windows-business', 'max_exposure' => 10]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity());
        self::assertTrue($p->ok);
        $r = $p->resolved;
        self::assertContains('smb', $r->serviceIds);
        self::assertContains('rdp', $r->serviceIds);
        self::assertNotContains('kerberos', $r->serviceIds);
        self::assertNotContains('ldap', $r->serviceIds);
        self::assertCount(1, array_intersect($r->serviceIds, ['mssql', 'winrm']));
    }

    public function testVoipPbxReservesRtpMediaSeparatelyFromExposures(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'voip-pbx', 'max_exposure' => 20]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity());
        self::assertTrue($p->ok, implode(',', $p->errorCodes()));
        $r = $p->resolved;
        self::assertContains('sip', $r->serviceIds);
        self::assertContains('stun', $r->serviceIds);
        self::assertNotContains('rtp', $r->serviceIds); // media is not a selectable service
        self::assertSame(['udp/10000'], $r->reservedMediaTuples);
        self::assertNotContains('udp/10000', $r->exposures);
        self::assertContains('tcp/5060', $r->exposures);
        self::assertContains('udp/5060', $r->exposures); // tcp+udp on one number count separately
    }

    public function testManualUnusualMixIsAllowedWithAWarningNotARejection(): void
    {
        // A Windows base family with a linux service selected: coherence warning, still resolves.
        $input = ServiceProfileInput::fromArray(['mode' => 'manual', 'base_family' => 'windows', 'manual_service_ids' => ['smb', 'ftp'], 'max_exposure' => 10]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity());
        self::assertTrue($p->ok, implode(',', $p->errorCodes()));
        $codes = array_map(static fn (array $w): string => $w['code'], $p->warnings);
        self::assertContains(ServiceResolutionReason::FAMILY_COHERENCE, $codes);
    }

    public function testManualNeverSilentlyOpensACompanion(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'manual', 'base_family' => 'devops', 'manual_service_ids' => ['docker-api-2375'], 'max_exposure' => 10]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(true), $this->identity());
        self::assertFalse($p->ok);
        self::assertTrue($p->hasError(ServiceResolutionReason::MISSING_COMPANION));
    }

    public function testManualDockerApiRequiresTheDockerCapability(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'manual', 'base_family' => 'devops', 'manual_service_ids' => ['ssh', 'docker-api-2375'], 'max_exposure' => 10]);
        $off = $this->resolver->preview($input, $this->catalog, $this->policy(false), $this->identity());
        self::assertFalse($off->ok);
        self::assertTrue($off->hasError(ServiceResolutionReason::CAPABILITY_MISSING));
        $on = $this->resolver->preview($input, $this->catalog, $this->policy(true), $this->identity());
        self::assertTrue($on->ok, implode(',', $on->errorCodes()));
    }

    public function testManualNonSelectableMediaIsRejected(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'manual', 'base_family' => 'voip', 'manual_service_ids' => ['sip', 'rtp'], 'max_exposure' => 20]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity());
        self::assertFalse($p->ok);
        self::assertTrue($p->hasError(ServiceResolutionReason::NON_SELECTABLE_ID));
    }

    public function testAllModeRequiresAndHonoursAConflictVariant(): void
    {
        $missing = ServiceProfileInput::fromArray(['mode' => 'all', 'base_family' => 'devops', 'max_exposure' => 65535]);
        $p = $this->resolver->preview($missing, $this->catalog, $this->policy(true), $this->identity());
        self::assertFalse($p->ok);
        self::assertTrue($p->hasError(ServiceResolutionReason::CONFLICT_VARIANT_MISSING));

        $chosen = ServiceProfileInput::fromArray(['mode' => 'all', 'base_family' => 'devops', 'conflict_variants' => ['docker-api' => 'docker-api-2375'], 'max_exposure' => 65535]);
        $ok = $this->resolver->preview($chosen, $this->catalog, $this->policy(true), $this->identity());
        self::assertTrue($ok->ok, implode(',', $ok->errorCodes()));
        self::assertContains('docker-api-2375', $ok->resolved->serviceIds);
        self::assertNotContains('docker-api-4243', $ok->resolved->serviceIds);
        self::assertSame(40, $ok->resolved->processCount()); // the process ceiling exactly
    }

    public function testAllModeCarriesTheHighFingerprintWarning(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'all', 'base_family' => 'devops', 'conflict_variants' => ['docker-api' => 'docker-api-2375'], 'max_exposure' => 65535]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(true), $this->identity());
        $codes = array_map(static fn (array $w): string => $w['code'], $p->warnings);
        self::assertContains(ServiceResolutionReason::HIGH_FINGERPRINT_ALL, $codes);
    }

    public function testAllModeRejectsABudgetBelowTheResolvedCount(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'all', 'base_family' => 'devops', 'conflict_variants' => ['docker-api' => 'docker-api-2375'], 'max_exposure' => 3]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(true), $this->identity());
        self::assertFalse($p->ok);
        self::assertTrue($p->hasError(ServiceResolutionReason::BUDGET_BELOW_REQUIRED));
    }

    public function testBudgetBoundaries(): void
    {
        $under = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 2]);
        self::assertFalse($this->resolver->preview($under, $this->catalog, $this->policy(), $this->identity())->ok);
        $at = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 3]);
        self::assertTrue($this->resolver->preview($at, $this->catalog, $this->policy(), $this->identity())->ok);
        $over = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 50]);
        self::assertTrue($this->resolver->preview($over, $this->catalog, $this->policy(), $this->identity())->ok);
    }

    public function testUnknownBundleAndBaseFamilyAreRejected(): void
    {
        $b = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'nope', 'max_exposure' => 5]);
        self::assertTrue($this->resolver->preview($b, $this->catalog, $this->policy(), $this->identity())->hasError(ServiceResolutionReason::BUNDLE_UNKNOWN));
        $f = ServiceProfileInput::fromArray(['mode' => 'manual', 'base_family' => 'martian', 'manual_service_ids' => ['ssh'], 'max_exposure' => 5]);
        self::assertTrue($this->resolver->preview($f, $this->catalog, $this->policy(), $this->identity())->hasError(ServiceResolutionReason::BASE_FAMILY_UNKNOWN));
    }

    public function testProtocolsDisabledCeilingRejectsAnyService(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 10]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(false, 'deploy', true), $this->identity());
        self::assertFalse($p->ok);
        self::assertTrue($p->hasError(ServiceResolutionReason::PROTOCOLS_DISABLED));
    }

    public function testMaxExposureCeilingIsAHardWall(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 10]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy(false, 'deploy', false, 2), $this->identity());
        self::assertFalse($p->ok);
        self::assertTrue($p->hasError(ServiceResolutionReason::MAX_EXPOSURE_CEILING));
    }

    public function testSameKeyAndInputIsByteIdenticalAcrossRepeatedCalls(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 10]);
        $first = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity('seed7'))->resolved->toArray();
        for ($i = 0; $i < 8; $i++) {
            $again = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity('seed7'))->resolved->toArray();
            self::assertSame($first, $again);
        }
    }

    public function testPinnedKeysProduceAtLeastTwoDistinctVariantsForAnOptionalSlot(): void
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 10]);
        $picks = [];
        foreach (['k0', 'k1', 'k2', 'k3', 'k4', 'k5', 'k6', 'k7', 'k8', 'k9', 'k10', 'k11', 'k12', 'k13', 'k14', 'k15'] as $tag) {
            $r = $this->resolver->preview($input, $this->catalog, $this->policy(), $this->identity($tag))->resolved;
            $ds = array_values(array_intersect($r->serviceIds, ['mysql', 'postgresql', 'redis', 'mongodb']));
            $picks[$ds[0]] = true;
        }
        self::assertGreaterThanOrEqual(2, count($picks), 'the deploy-seed ranking must be able to select different datastores');
    }
}

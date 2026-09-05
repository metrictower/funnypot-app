<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Composer\InstalledVersions;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\App\Http\CoreConfigFactory;
use Funnypot\Core\Config;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * The app/core identity seam, against the Composer-INSTALLED core: the engine Config receives an
 * exact non-empty private seedSalt and the exact visible deploySeed, its deploySeed() integer is
 * stable across restarts of one install and different on a fresh install, and an explicit persona
 * override keeps today's integer (continuity for every fixture written against `httptest`).
 */
final class CoreConfigFactoryTest extends TestCase
{
    /** seedFromMaterial('httptest') as AppConfig::fromEnv() yielded it before identity moved out of config. */
    private const HTTPTEST_SEED = 1137404178250321592;

    private function build(CoreConfigFactory $f): Config
    {
        $config = AppConfig::fromEnv(sys_get_temp_dir());
        $policy = EmulationPolicy::fromCatalog(\Funnypot\App\Emulation\EmulationCatalog::fromPackage(), null);

        return $f->build($config, $policy, static fn (RequestContext $r): string => 'anon');
    }

    public function test_it_builds_the_installed_core_config_with_exact_identity_inputs(): void
    {
        $rc = new ReflectionClass(Config::class);
        $root = dirname(__DIR__, 3);
        self::assertStringStartsWith($root . '/vendor/metrictower/funnypot-core/', (string) $rc->getFileName(), 'must exercise the INSTALLED core, not an adjacent checkout');
        self::assertSame('v0.6.3', InstalledVersions::getPrettyVersion('metrictower/funnypot-core'));

        $identity = IdentityTestSupport::httpIdentity();
        $f = new CoreConfigFactory($identity, 'PHP/8.1.2');
        $cfg = $this->build($f);

        self::assertInstanceOf(Config::class, $cfg);
        self::assertSame($identity->coreRenderSalt(), $cfg->seedSalt);
        self::assertSame(32, strlen($cfg->seedSalt), 'seedSalt is the private 32-byte render salt, never empty');
        self::assertSame('httptest', $cfg->deploySeed, 'deploySeed is the visible persona material, verbatim');
        self::assertNotSame($cfg->seedSalt, $cfg->deploySeed);
        self::assertSame('PHP/8.1.2', $cfg->poweredBy);
        self::assertSame('respond', $cfg->mode);
        self::assertTrue($cfg->isolatedOrigin);
    }

    public function test_explicit_persona_override_keeps_the_historical_seed_integer(): void
    {
        $identity = IdentityTestSupport::httpIdentity('httptest');
        self::assertSame(self::HTTPTEST_SEED, $identity->personaSeed());
        self::assertSame(self::HTTPTEST_SEED, PersonaIdentity::seedFromMaterial($identity->personaMaterial()));
        self::assertSame(self::HTTPTEST_SEED, $this->build(new CoreConfigFactory($identity, 'x'))->deploySeed(), 'core resolves the SAME persona integer as the app tier');
    }

    public function test_deploy_seed_is_stable_per_install_and_differs_on_a_fresh_root(): void
    {
        $derivedA = IdentityTestSupport::deriver('a')->personaMaterial();
        $derivedA2 = IdentityTestSupport::deriver('a')->personaMaterial();
        $derivedB = IdentityTestSupport::deriver('b')->personaMaterial();
        $a = $this->build(IdentityTestSupport::coreConfigFactory($derivedA, 'a'));
        $a2 = $this->build(IdentityTestSupport::coreConfigFactory($derivedA2, 'a'));
        $b = $this->build(IdentityTestSupport::coreConfigFactory($derivedB, 'b'));

        self::assertSame($a->deploySeed(), $a2->deploySeed(), 'same master ⇒ same persona across restarts');
        self::assertSame($a->seedSalt, $a2->seedSalt);
        self::assertNotSame($a->deploySeed(), $b->deploySeed(), 'fresh install ⇒ different persona');
        self::assertNotSame($a->seedSalt, $b->seedSalt, 'fresh install ⇒ different render salt');
        self::assertNotSame(PersonaIdentity::seedFromMaterial('funnypot'), $a->deploySeed(), 'never the retired fleet literal');
    }

    public function test_same_override_two_masters_same_persona_different_salt(): void
    {
        $a = $this->build(IdentityTestSupport::coreConfigFactory('httptest', 'a'));
        $b = $this->build(IdentityTestSupport::coreConfigFactory('httptest', 'b'));
        self::assertSame($a->deploySeed(), $b->deploySeed(), 'the visible persona follows the override');
        self::assertNotSame($a->seedSalt, $b->seedSalt, 'the private salt follows the master');
    }
}

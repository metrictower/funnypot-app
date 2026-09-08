<?php

declare(strict_types=1);

use Funnypot\App\Identity\IdentityPreparer;
use Funnypot\App\Runtime\ExposureRuntimeAdapter;
use Funnypot\App\Runtime\RuntimePolicy;
use Funnypot\App\Sandbox\Projection\CandidateGenerationFactory;
use Funnypot\App\Sandbox\Projection\ProjectionEntryRegistry;
use Funnypot\App\Sandbox\Projection\SandboxPaths;
use Funnypot\App\Sandbox\Projection\SandboxProjectionStore;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceExposureManifest;
use Funnypot\App\Service\ServicePaths;
use Funnypot\Tests\Fixtures\SandboxPublisherFixtureOps;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';
if (defined('FUNNYPOT_SANDBOX_PUBLISHER_LOAD_ONLY')) {
    new SandboxPublisherFixtureOps();
    return;
}
$env = static fn (string $key) => getenv($key);
$ops = new SandboxPublisherFixtureOps(
    (int) (getenv('FP_SANDBOX_TEST_HOLD_MS') ?: 0),
    (string) (getenv('FP_SANDBOX_TEST_MARKER') ?: ''),
    (string) (getenv('FP_SANDBOX_TEST_CRASH') ?: ''),
);
$paths = SandboxPaths::fromEnvironment($env, $ops);
$registry = ProjectionEntryRegistry::v1();
$store = new SandboxProjectionStore($paths, $registry, RuntimePolicy::fromPackage(), $ops, new CandidateGenerationFactory($ops));
$loadEffective = static function () use ($root, $env) {
    $servicePaths = ServicePaths::fromEnvironment($root . '/demo', $env);
    $manifest = ServiceExposureManifest::fromPersistentFile($servicePaths->persistentManifest());
    (new ExposureRuntimeAdapter())->bindings($manifest, ServiceCatalog::fromPackage());
    return $manifest->effectiveArtifact();
};
if (getenv('FP_SANDBOX_TEST_ACTION') === 'recover') {
    $result = $store->recover();
} else {
    $result = $store->publish(
        static fn () => IdentityPreparer::fromEnvironment($root . '/demo', $env)->prepare(),
        $loadEffective,
    );
}
fwrite(STDOUT, $result->code . "\n");
exit($result->successful() ? 0 : 1);

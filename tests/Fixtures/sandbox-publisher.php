<?php

declare(strict_types=1);

use Funnypot\App\Identity\IdentityPreparer;
use Funnypot\App\Runtime\ExposureRuntimeAdapter;
use Funnypot\App\Runtime\RuntimePolicy;
use Funnypot\App\Sandbox\Projection\CandidateGenerationFactory;
use Funnypot\App\Sandbox\Projection\ProjectionEntryRegistry;
use Funnypot\App\Sandbox\Projection\SandboxFileOps;
use Funnypot\App\Sandbox\Projection\SandboxPaths;
use Funnypot\App\Sandbox\Projection\SandboxProjectionStore;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceExposureManifest;
use Funnypot\App\Service\ServicePaths;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';
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

final class SandboxPublisherFixtureOps extends SandboxFileOps
{
    private bool $held = false;

    public function __construct(private int $holdMs, private string $marker, private string $crash)
    {
    }

    public function flock($h, int $op): bool
    {
        $ok = parent::flock($h, $op);
        if ($ok && !$this->held && ($op & LOCK_EX) === LOCK_EX) {
            $this->held = true;
            if ($this->marker !== '') { file_put_contents($this->marker, "held\n"); }
            if ($this->holdMs > 0) { usleep($this->holdMs * 1000); }
        }
        return $ok;
    }

    public function rename(string $from, string $to): bool
    {
        $candidate = str_contains($from, '/.candidate-');
        $current = str_ends_with($to, '/current.json');
        if ($candidate && $this->crash === 'before-candidate-rename') { exit(75); }
        $ok = parent::rename($from, $to);
        if ($ok && $candidate && $this->crash === 'after-candidate-rename') { exit(75); }
        if ($ok && $current && $this->crash === 'after-current-rename') { exit(75); }
        return $ok;
    }
}

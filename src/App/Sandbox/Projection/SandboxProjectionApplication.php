<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Identity\IdentityPreparer;
use Funnypot\App\Runtime\ExposureRuntimeAdapter;
use Funnypot\App\Runtime\RuntimePolicy;
use Funnypot\App\Service\EffectiveExposureArtifact;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceExposureManifest;
use Funnypot\App\Service\ServicePaths;

final class SandboxProjectionApplication
{
    /** @param callable(string):(string|false)|null $env */
    public static function fromEnvironment(string $demoDir, ?callable $env = null): self
    {
        $env ??= static fn (string $key) => getenv($key);
        $ops = new SandboxFileOps();
        $paths = SandboxPaths::fromEnvironment($env, $ops);
        $registry = ProjectionEntryRegistry::v1();
        $policy = RuntimePolicy::fromPackage();

        return new self(
            new SandboxProjectionStore($paths, $registry, $policy, $ops, new CandidateGenerationFactory($ops)),
            $demoDir,
            $env,
        );
    }

    /** @param callable(string):(string|false) $env */
    public function __construct(private SandboxProjectionStore $store, private string $demoDir, private $env)
    {
    }

    public function materialize(): SandboxPublicationResult
    {
        return $this->store->publish(
            fn () => IdentityPreparer::fromEnvironment($this->demoDir, $this->env)->prepare(),
            fn () => $this->loadEffective(),
        );
    }

    public function rollback(): SandboxPublicationResult
    {
        return $this->store->rollback(fn () => $this->loadEffective());
    }

    /** @return array<string,mixed> */
    public function status(): array
    {
        return $this->store->status(fn () => $this->loadEffective());
    }

    private function loadEffective(): EffectiveExposureArtifact
    {
        $paths = ServicePaths::fromEnvironment($this->demoDir, $this->env);
        $manifest = ServiceExposureManifest::fromPersistentFile($paths->persistentManifest());
        (new ExposureRuntimeAdapter())->bindings($manifest, ServiceCatalog::fromPackage());

        return $manifest->effectiveArtifact();
    }
}

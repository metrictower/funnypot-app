<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Closure;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\App\Identity\HttpIdentity;
use Funnypot\Core\Config;
use Funnypot\Core\RequestContext;

/**
 * Builds the engine Config from the app's config plus the web tier's identity. The two identity
 * inputs the engine takes are made explicit and observable here instead of living in a local
 * variable inside the controller: `seedSalt` is the private core render salt (so template-tier fakes
 * are keyed per install, never by an empty salt), and `deploySeed` is the visible persona material
 * (so the template tier resolves the SAME PersonaIdentity the app's own pages show). The effective
 * X-Powered-By is resolved once by the composition root and reused here, so the live header and the
 * engine's chrome never disagree.
 */
final class CoreConfigFactory
{
    public function __construct(private HttpIdentity $identity, private string $poweredBy)
    {
    }

    public function seedSalt(): string
    {
        return $this->identity->coreRenderSalt();
    }

    public function deploySeed(): string
    {
        return $this->identity->personaMaterial();
    }

    public function poweredBy(): string
    {
        return $this->poweredBy;
    }

    /**
     * @param Closure(RequestContext):string $personaSeed the per-REQUEST fake-secret seed (distinct
     *        from the per-deploy identity: it keys request-scoped fakes, not the persona)
     */
    public function build(AppConfig $config, EmulationPolicy $policy, Closure $personaSeed): Config
    {
        return new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true, // standalone honeypot: everything hostile-looking gets a fake
            severityCeiling: $config->severityCeiling,
            responseStyle: $config->httpStyle(), // core supports realistic|taunt; 'malformed' (protocol-only) -> realistic here
            personaSeed: $personaSeed,
            seedSalt: $this->seedSalt(),
            deploySeed: $this->deploySeed(),
            latencyMs: $config->latencyMs,
            latencyJitterMs: $config->jitterMs,
            attackEmulation: $config->attackEmulation,
            poweredBy: $this->poweredBy,
            exclude: $policy->disabledIds(),
            nucleiReflection: $policy->nucleiEnabled(),
            isolatedOrigin: true, // standalone honeypot owns its origin — reflecting decoys (XSS/open-redirect) are safe bait here (FP-0159; requires core >= 0.6.1)
        );
    }
}

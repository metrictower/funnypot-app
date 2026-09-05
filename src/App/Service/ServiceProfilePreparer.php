<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\ServiceProfileIdentity;
use RuntimeException;

/**
 * The no-network preflight: resolve the desired profile, commit the bootstrap-accepted effective
 * revision 1 on an empty runtime store (B1), and write the persistent exposure manifest — the only
 * downstream binding source — before any listener runs. It reruns idempotently at every container
 * start: it re-derives the persistent manifest from the authoritative runtime store and rewrites it
 * only when the on-disk nested hash disagrees, so a downstream generation never binds a superseded
 * manifest. It makes no DNS/socket/HTTP call.
 *
 * Desired precedence on an empty store: a complete startup environment aggregate, else a seeded
 * eligible named bundle chosen by the scoped ranking key (never `all`); a resolved profile that is
 * capability-ineligible or protocols-disabled falls back to the non-bootstrap `web-only` profile.
 */
final class ServiceProfilePreparer
{
    public const DESIRED_HASH_DOMAIN = 'funnypot/service-desired/v1';
    public const PREVIEW_HASH_DOMAIN = 'funnypot/service-preview/v1';
    public const BOOTSTRAP_RANK_DOMAIN = 'funnypot/bootstrap-bundle/v1';

    private ServiceProfileResolver $resolver;

    public function __construct(
        private ServicePaths $paths,
        private ServiceCatalog $catalog,
        private ServiceProfileIdentity $identity,
        private ServiceCapabilityPolicy $policy,
        private string $target,
        private string $publishMode,
        private string $identityPublicHash,
        private ?IdentityFileOps $ops = null,
        ?ServiceProfileResolver $resolver = null,
        /** @var callable(string):(string|false)|null */
        private mixed $env = null,
    ) {
        $this->ops ??= new IdentityFileOps();
        $this->resolver = $resolver ?? new ServiceProfileResolver();
        $this->env ??= static fn (string $k) => getenv($k);
    }

    /** Run the preflight, returning the persistent manifest it wrote or re-derived. */
    public function prepare(): ServiceExposureManifest
    {
        $this->ensureDirs();
        $desired = new ServiceProfileStore($this->paths->desiredDbPath(), $this->ops);
        $runtime = new ServiceRuntimeStore($this->paths->runtimeDbPath(), $this->ops);

        // 1. Establish the desired aggregate (stored wins; else env; else seeded bundle).
        if ($desired->isEmpty()) {
            [$input, $resolved] = $this->chooseInitialDesired();
            $fields = $this->fields($input, $resolved, 1);
            $desired->initializeIfEmpty($fields, 'system');
        }
        $row = $desired->snapshot();
        if ($row === null) {
            throw new RuntimeException('preparer: desired store is empty after initialization');
        }
        $input = ServiceProfileInput::fromJson((string) $row['input_json']);
        $preview = $this->resolver->preview($input, $this->catalog, $this->policy, $this->identity);
        if (!$preview->ok) {
            throw new RuntimeException('preparer: stored desired profile no longer resolves: ' . implode(',', $preview->errorCodes()));
        }
        $resolved = $preview->resolved;
        $desiredRevision = (int) $row['revision'];

        // 2. Bootstrap acceptance on an empty runtime store: effective revision 1 == desired revision 1.
        if ($runtime->isEmpty()) {
            $manifest = $this->buildManifest($resolved, $desiredRevision, $desiredRevision);
            $runtime->bootstrapAccept($manifest);
        }

        // 3. Re-derive the persistent manifest from the authoritative runtime store; rewrite on disagreement.
        $accepted = $runtime->acceptedManifest();
        if ($accepted === null) {
            throw new RuntimeException('preparer: runtime store has no accepted set');
        }
        $this->writePersistentIfChanged($accepted);
        $this->writeNginxFragments($resolved);

        return $accepted;
    }

    /**
     * @return array{0:ServiceProfileInput,1:ResolvedServiceProfile}
     */
    private function chooseInitialDesired(): array
    {
        // Hard ceiling: protocols disabled -> web-only, never a listener bundle.
        if (!$this->policy->protocolsDisabled()) {
            $envInput = ServiceProfileInput::fromEnvironment($this->env);
            if ($envInput !== null) {
                $p = $this->resolver->preview($envInput, $this->catalog, $this->policy, $this->identity);
                if ($p->ok) {
                    return [$envInput, $p->resolved];
                }
                throw new RuntimeException('preparer: startup service environment is invalid: ' . implode(',', $p->errorCodes()));
            }
            $seeded = $this->seededBundle();
            if ($seeded !== null) {
                return $seeded;
            }
        }

        return $this->webOnly();
    }

    /** @return array{0:ServiceProfileInput,1:ResolvedServiceProfile}|null */
    private function seededBundle(): ?array
    {
        $eligible = [];
        foreach ($this->catalog->bundles() as $id => $bundle) {
            if (!$bundle->bootstrap) {
                continue;
            }
            $probe = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => $id, 'max_exposure' => 65535]);
            $p = $this->resolver->preview($probe, $this->catalog, $this->policy, $this->identity);
            if ($p->ok) {
                $eligible[$id] = $p->resolved;
            }
        }
        if ($eligible === []) {
            return null;
        }
        $ids = array_keys($eligible);
        sort($ids);
        $bestId = null;
        $bestMac = '';
        foreach ($ids as $id) {
            $mac = hash_hmac('sha256', self::BOOTSTRAP_RANK_DOMAIN . "\0" . $id, $this->identity->rankingKey());
            if ($bestId === null || strcmp($mac, $bestMac) < 0) {
                $bestId = $id;
                $bestMac = $mac;
            }
        }
        $resolved = $eligible[$bestId];
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => $bestId, 'max_exposure' => $resolved->exposureCount()]);

        return [$input, $resolved];
    }

    /** @return array{0:ServiceProfileInput,1:ResolvedServiceProfile} */
    private function webOnly(): array
    {
        $input = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'web-only', 'max_exposure' => 0]);
        $p = $this->resolver->preview($input, $this->catalog, $this->policy, $this->identity);
        if (!$p->ok) {
            throw new RuntimeException('preparer: web-only failsafe did not resolve: ' . implode(',', $p->errorCodes()));
        }

        return [$input, $p->resolved];
    }

    public function buildManifest(ResolvedServiceProfile $resolved, int $desiredRevision, int $effectiveRevision): ServiceExposureManifest
    {
        [$bindEndpoints, $published] = $this->publishedAndBinds($resolved);
        $desiredHash = CanonicalJson::digest(self::DESIRED_HASH_DOMAIN, $resolved->toArray());

        return ServiceExposureManifest::build(
            $this->target,
            $this->publishMode,
            $this->catalog->catalogHash(),
            $this->identityPublicHash,
            $desiredRevision,
            $desiredHash,
            $effectiveRevision,
            $resolved->profileTuple(),
            $resolved->serviceIds,
            $resolved->processIds,
            $bindEndpoints,
            $resolved->exposures,
            $published,
            $resolved->nginxHttpAliasEndpointIds,
            $resolved->nginxHttpsAliasEndpointIds,
        );
    }

    /**
     * @return array{input_json:string,resolved_json:string,preview_hash:string,desired_hash:string,catalog_hash:string,published_hash:string}
     */
    public function fields(ServiceProfileInput $input, ResolvedServiceProfile $resolved, int $revision): array
    {
        $manifest = $this->buildManifest($resolved, $revision, $revision);
        $desiredHash = CanonicalJson::digest(self::DESIRED_HASH_DOMAIN, $resolved->toArray());
        $previewHash = CanonicalJson::digest(self::PREVIEW_HASH_DOMAIN, [
            'input' => $input->toArray(),
            'resolved' => $resolved->toArray(),
            'catalog_hash' => $this->catalog->catalogHash(),
            'published_hash' => $manifest->publishedHash(),
            'identity_public_hash' => $this->identityPublicHash,
        ]);

        return [
            'input_json' => $input->canonicalJson(),
            'resolved_json' => CanonicalJson::encode($resolved->toArray()),
            'preview_hash' => $previewHash,
            'desired_hash' => $desiredHash,
            'catalog_hash' => $this->catalog->catalogHash(),
            'published_hash' => $manifest->publishedHash(),
        ];
    }

    /**
     * @return array{0:list<array{endpoint_id:string,transport:string,container_port:int}>,1:list<string>}
     */
    private function publishedAndBinds(ResolvedServiceProfile $resolved): array
    {
        $endpointIds = [];
        // canonical web is always published
        foreach (['http-80', 'https-443'] as $cid) {
            if ($this->catalog->endpoint($cid) !== null) {
                $endpointIds[$cid] = true;
            }
        }
        foreach ($resolved->serviceIds as $sid) {
            $desc = $this->catalog->descriptor($sid);
            foreach ($desc->endpoints as $ep) {
                $endpointIds[$ep->endpointId] = true;
            }
            $media = $this->catalog->mediaFor($sid);
            if ($media !== null) {
                foreach ($media->endpoints as $ep) {
                    $endpointIds[$ep->endpointId] = true;
                }
            }
        }
        $binds = [];
        $published = [];
        foreach (array_keys($endpointIds) as $eid) {
            $ep = $this->catalog->endpoint($eid);
            if ($ep === null) {
                continue;
            }
            if ($ep->isBind()) {
                $binds[$ep->endpointId] = ['endpoint_id' => $ep->endpointId, 'transport' => $ep->transport, 'container_port' => $ep->containerPort];
            }
            if ($ep->inBasePublishSet($this->target)) {
                $published[] = $ep->hostPort . ':' . $ep->containerPort . ($ep->transport === 'udp' ? '/udp' : '');
            }
        }
        $binds = array_values($binds);
        $published = array_values(array_unique($published));

        return [$binds, $published];
    }

    private function writePersistentIfChanged(ServiceExposureManifest $manifest): void
    {
        $path = $this->paths->persistentManifest();
        $bytes = $manifest->toJson();
        $existing = @file_get_contents($path);
        if ($existing !== false && $existing === $bytes) {
            return;
        }
        $this->atomicWrite($path, $bytes, 0600);
    }

    private function writeNginxFragments(ResolvedServiceProfile $resolved): void
    {
        $aliasEndpoints = [];
        foreach ([...$resolved->nginxHttpAliasEndpointIds, ...$resolved->nginxHttpsAliasEndpointIds] as $eid) {
            $ep = $this->catalog->endpoint($eid);
            if ($ep !== null) {
                $aliasEndpoints[] = $ep;
            }
        }
        [$http, $https] = NginxProfileRenderer::render($aliasEndpoints);
        $this->atomicWrite($this->paths->persistentNginxHttp(), $http, 0600);
        $this->atomicWrite($this->paths->persistentNginxHttps(), $https, 0600);
    }

    private function ensureDirs(): void
    {
        $this->ensureDir($this->paths->privateRoot(), 0700);
        $this->ensureDir($this->paths->persistentDir(), 0700);
        $this->ensureDir($this->paths->desiredStoreDir(), 02770);
    }

    private function ensureDir(string $dir, int $mode): void
    {
        if ($this->ops->lstat($dir) === false) {
            $this->ops->mkdir($dir, $mode);
        }
        $this->ops->chmod($dir, $mode);
    }

    private function atomicWrite(string $path, string $bytes, int $mode): void
    {
        $tmp = $path . '.tmp.' . $this->ops->randomHex(6);
        $h = $this->ops->openExclusive($tmp);
        if ($h === false) {
            throw new RuntimeException('preparer: temp open failed for ' . basename($path));
        }
        try {
            if ($this->ops->write($h, $bytes) !== strlen($bytes) || !$this->ops->flush($h) || !$this->ops->fsync($h)) {
                throw new RuntimeException('preparer: write failed for ' . basename($path));
            }
            $this->ops->close($h);
            $this->ops->chmod($tmp, $mode);
            if (!$this->ops->rename($tmp, $path)) {
                throw new RuntimeException('preparer: rename failed for ' . basename($path));
            }
        } catch (\Throwable $e) {
            $this->ops->close($h);
            $this->ops->unlink($tmp);
            throw $e;
        }
        $d = $this->ops->openDir(dirname($path));
        if ($d !== false) {
            $this->ops->fsync($d);
            $this->ops->close($d);
        }
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

use Funnypot\App\Tls\DecoyCertificateManager;
use Funnypot\App\Tls\DnsName;
use Funnypot\App\Tls\TlsSelection;
use Funnypot\Core\Support\VisualPersona;

/**
 * The one ordered identity transaction the entrypoint and deploy preflight run before any public
 * listener exists:
 *
 *   1. resolve the install master (protected explicit file > canonical env value > persisted file >
 *      one CSPRNG creation) and derive the closed keyset in memory;
 *   2. select and verify the TLS pair (never touching an operator/legacy pair);
 *   3. atomically publish the secret-free persistent manifest;
 *   4. atomically write the scoped runtime bundles (root-only listener bundles, the 0640 HTTP bundle,
 *      the root-only post-exploit source) and the runtime TLS links / admin vhost;
 *   5. root-read every bundle back and compare its envelope with the manifest before returning.
 *
 * A prior manifest pins the source class and keyset commitment: a configured explicit master that
 * goes missing or changes, or an explicit master appearing over a generated one, fails rather than
 * silently re-identifying the install. Rotation is an explicit offline procedure. Every failure is an
 * {@see IdentityBootstrapException} with a stable code and no secret or path.
 */
final class IdentityPreparer
{
    public const MANIFEST_SCHEMA = 'funnypot-identity-manifest/v1';
    public const HTTP_GROUP = 'www-data';

    /** Manifest source classes (the persistent file is always recorded as `generated`). */
    private const MANIFEST_GENERATED = 'generated';

    /** Explicit persona overrides that are visibly weak; a warning, never a rejection. */
    public const WEAK_OVERRIDES = ['funnypot', 'changeme', 'change-me', 'default', 'test', 'example'];
    public const WEAK_MIN_LEN = 16;
    private const OVERRIDE_MAX_LEN = 512;

    public const WARN_PERSONA_WEAK = 'persona-override-weak';
    public const WARN_PERSONA_LEGACY_VAR = 'persona-override-legacy-var';
    public const WARN_PERSONA_FIRST_DERIVED = 'persona-derived-first-preparation';
    public const WARN_LEGACY_FS_SECRET_FILE = 'legacy-fs-secret-file-ignored';
    public const WARN_LEGACY_FS_SECRET_ENV = 'legacy-fs-secret-env-ignored';
    public const WARN_HTTP_GROUP_NOT_APPLIED = 'http-group-not-applied';

    private const MAX_MANIFEST_BYTES = 65536;

    private IdentityFileOps $ops;
    private SourceOpener $opener;
    private DecoyCertificateManager $tls;

    /** @var list<string> warning codes the master store raised during this preparation */
    private array $storeWarnings = [];

    public function __construct(
        private IdentityPaths $paths,
        private IdentityInputs $inputs,
        ?IdentityFileOps $ops = null,
        ?DecoyCertificateManager $tls = null,
    ) {
        $this->ops = $ops ?? new IdentityFileOps();
        $this->opener = new SourceOpener($this->ops);
        $this->tls = $tls ?? new DecoyCertificateManager($this->paths, $this->ops, $this->inputs);
    }

    /** Production construction: paths and inputs from the environment, read once. */
    public static function fromEnvironment(string $demoDir, ?callable $env = null): self
    {
        return new self(IdentityPaths::fromEnvironment($demoDir, $env), IdentityInputs::fromEnvironment($env));
    }

    public function paths(): IdentityPaths
    {
        return $this->paths;
    }

    public function prepare(): IdentityPreparationResult
    {
        // One exclusive lock across the whole transaction: concurrent preparers (32 at once is the
        // proven case) serialize on the master, the generated TLS pair, the manifest and the bundles.
        $store = new InstallSecretStore($this->paths, $this->ops);
        $store->ensurePrivateDirectories();
        $lock = $store->acquireLock();
        try {
            return $this->prepareLocked($store);
        } finally {
            $store->releaseLock($lock);
        }
    }

    private function prepareLocked(InstallSecretStore $store): IdentityPreparationResult
    {
        $warnings = [];
        $prior = $this->readManifest();

        // 1. master + keyset
        [$master, $sourceClass] = $this->resolveMaster($prior, $store);
        $deriver = IdentityKeyDeriver::fromMaster($master);
        $commitment = $deriver->keysetCommitment();
        if (is_array($prior) && in_array($prior['source'] ?? null, [IdentityPreparationResult::SOURCE_EXPLICIT_FILE, IdentityPreparationResult::SOURCE_EXPLICIT_ENV], true)
            && ($prior['keyset_commitment'] ?? null) !== $commitment) {
            throw IdentityBootstrapException::withCode('explicit-source-changed', IdentityBootstrapException::REMEDY_CONFIG);
        }
        [$personaMaterial, $personaSource, $personaWarnings] = $this->resolvePersona($deriver, $prior);
        $warnings = [...$warnings, ...$this->storeWarnings, ...$personaWarnings, ...$this->legacyWarnings()];
        $this->storeWarnings = [];
        $publicHash = IdentityKeyDeriver::publicPersonaHash($personaMaterial);

        (new ReservedPrincipals($this->ops))->verify();

        // 2. TLS (before anything is published, so a failed selection leaves the prior state intact)
        $personaHostname = VisualPersona::fromSeed(\Funnypot\Core\Support\PersonaIdentity::seedFromMaterial($personaMaterial))->domain();
        $tls = $this->tls->select(DnsName::isValid($personaHostname) ? $personaHostname : 'srv-' . substr(hash('sha256', $publicHash), 0, 10) . '.internal', $prior['tls'] ?? null);
        $warnings = [...$warnings, ...$tls->warnings];

        $httpGroupApplied = $this->ensureRuntimeDirectories();
        if (!$httpGroupApplied) {
            $warnings[] = self::WARN_HTTP_GROUP_NOT_APPLIED;
        }
        $warnings = array_values(array_unique($warnings));

        $manifestSource = in_array($sourceClass, [IdentityPreparationResult::SOURCE_GENERATED, IdentityPreparationResult::SOURCE_PERSISTED], true)
            ? self::MANIFEST_GENERATED
            : $sourceClass;

        // 3. manifest
        $manifest = [
            'schema' => self::MANIFEST_SCHEMA,
            'source' => $manifestSource,
            'persona_source' => $personaSource,
            'public_persona_hash' => $publicHash,
            'keyset_commitment' => $commitment,
            'http_group_applied' => $httpGroupApplied,
            'prepared_at' => $this->ops->time(),
            'warnings' => $warnings,
            'tls' => $tls->manifestRecord(),
        ];
        $this->writeAtomic($this->paths->manifestPath(), self::canonicalJson($manifest), 0600, null, 'manifest');

        // 4. bundles + runtime TLS
        $envelopeBase = [
            'schema' => IdentityBundleReader::SCHEMA,
            'source' => $manifestSource,
            'public_persona_hash' => $publicHash,
            'keyset_commitment' => $commitment,
        ];
        $http = HttpIdentity::fromDeriver($deriver, $personaMaterial);
        $shell = ShellIdentity::fromDeriver($deriver, $personaMaterial);
        $sip = SipIdentity::fromDeriver($deriver, $personaMaterial);
        $redis = RedisIdentity::fromDeriver($deriver, $personaMaterial);
        $post = PostExploitIdentity::fromDeriver($deriver, $personaMaterial);
        $httpGid = $httpGroupApplied ? $this->ops->groupByName(self::HTTP_GROUP)['gid'] ?? null : null;
        $this->writeAtomic($this->paths->httpBundlePath(), self::bundleJson($envelopeBase, HttpIdentity::BUNDLE, $http->toPayload()), 0640, is_int($httpGid) ? $httpGid : null, 'bundle');
        $this->writeAtomic($this->paths->shellBundlePath(), self::bundleJson($envelopeBase, ShellIdentity::BUNDLE, $shell->toPayload()), 0600, null, 'bundle');
        $this->writeAtomic($this->paths->sipBundlePath(), self::bundleJson($envelopeBase, SipIdentity::BUNDLE, $sip->toPayload()), 0600, null, 'bundle');
        $this->writeAtomic($this->paths->redisBundlePath(), self::bundleJson($envelopeBase, RedisIdentity::BUNDLE, $redis->toPayload()), 0600, null, 'bundle');
        $this->writeAtomic($this->paths->postExploitBundlePath(), self::bundleJson($envelopeBase, PostExploitIdentity::BUNDLE, $post->toPayload()), 0600, null, 'bundle');
        $this->publishRuntimeTls($tls);

        // 5. root-read + compare
        $verified = [];
        foreach ([
            PreparedIdentitySource::HTTP => [HttpIdentity::BUNDLE, 'identity-http', IdentityPaths::HTTP_BUNDLE],
            PreparedIdentitySource::SHELL => [ShellIdentity::BUNDLE, 'identity-private', IdentityPaths::SHELL_BUNDLE],
            PreparedIdentitySource::SIP => [SipIdentity::BUNDLE, 'identity-private', IdentityPaths::SIP_BUNDLE],
            PreparedIdentitySource::REDIS => [RedisIdentity::BUNDLE, 'identity-private', IdentityPaths::REDIS_BUNDLE],
            PreparedIdentitySource::POST_EXPLOIT => [PostExploitIdentity::BUNDLE, 'identity-private', IdentityPaths::POST_EXPLOIT_BUNDLE],
        ] as $class => [$bundle, $dir, $file]) {
            $verified[$class] = $this->verifyBundle($class, $bundle, $dir, $file, $envelopeBase);
        }

        $tlsEnvelope = ['fingerprint_sha256' => $tls->fingerprintSha256, 'selection' => $tls->selection];
        $result = new IdentityPreparationResult(
            $sourceClass,
            $personaSource,
            $publicHash,
            $commitment,
            $tls,
            $httpGroupApplied,
            $warnings,
            $verified[PreparedIdentitySource::HTTP],
            $verified[PreparedIdentitySource::SHELL],
            $verified[PreparedIdentitySource::SIP],
            $verified[PreparedIdentitySource::REDIS],
            PreparedIdentitySource::fromOpened(PreparedIdentitySource::TLS_CERTIFICATE, $tls->cert, $tlsEnvelope),
            PreparedIdentitySource::fromOpened(PreparedIdentitySource::TLS_PRIVATE_KEY, $tls->key, $tlsEnvelope),
            $tls->hasAdminPair() ? PreparedIdentitySource::fromOpened(PreparedIdentitySource::ADMIN_TLS_CERTIFICATE, $tls->adminCert, ['fingerprint_sha256' => (string) $tls->adminFingerprintSha256, 'domain' => (string) $tls->adminDomain]) : null,
            $tls->hasAdminPair() ? PreparedIdentitySource::fromOpened(PreparedIdentitySource::ADMIN_TLS_PRIVATE_KEY, $tls->adminKey, ['fingerprint_sha256' => (string) $tls->adminFingerprintSha256, 'domain' => (string) $tls->adminDomain]) : null,
            $verified[PreparedIdentitySource::POST_EXPLOIT],
        );
        sodium_memzero($master);

        return $result;
    }

    /**
     * Secret-free readiness: source class, schema, public identity hash, warning codes and whether
     * every runtime bundle agrees with the manifest. Never the commitment, an override or a path.
     *
     * @return array<string,mixed>
     */
    public function status(): array
    {
        $out = ['ready' => false, 'schema' => null, 'source' => null, 'persona_source' => null, 'public_identity' => null, 'tls' => null, 'warnings' => [], 'checks' => []];
        try {
            $m = $this->readManifest();
        } catch (IdentityBootstrapException $e) {
            $out['checks']['manifest'] = $e->errorCode();

            return $out;
        }
        if ($m === null) {
            $out['checks']['manifest'] = 'absent';

            return $out;
        }
        $out['schema'] = $m['schema'];
        $out['source'] = $m['source'];
        $out['persona_source'] = $m['persona_source'];
        $out['public_identity'] = $m['public_persona_hash'];
        $out['tls'] = ['selection' => $m['tls']['selection'] ?? null, 'fingerprint_sha256' => $m['tls']['fingerprint_sha256'] ?? null];
        $out['warnings'] = array_values(array_filter((array) ($m['warnings'] ?? []), 'is_string'));
        $ready = true;
        foreach ([
            HttpIdentity::BUNDLE, ShellIdentity::BUNDLE, SipIdentity::BUNDLE, RedisIdentity::BUNDLE, PostExploitIdentity::BUNDLE,
        ] as $bundle) {
            try {
                $doc = (new IdentityBundleReader($this->paths, $this->ops))->read($bundle);
                $env = $doc['envelope'];
                $ok = $env['public_persona_hash'] === $m['public_persona_hash']
                    && $env['keyset_commitment'] === $m['keyset_commitment']
                    && $env['source'] === $m['source'];
                $out['checks'][$bundle] = $ok ? 'ok' : 'envelope-mismatch';
                $ready = $ready && $ok;
            } catch (IdentityBootstrapException $e) {
                $out['checks'][$bundle] = $e->errorCode();
                $ready = false;
            }
        }
        $out['ready'] = $ready;

        return $out;
    }

    // --- master ------------------------------------------------------------------------------------

    /**
     * @param array<string,mixed>|null $prior
     * @return array{0:string,1:string} [master, source class]
     */
    private function resolveMaster(?array $prior, InstallSecretStore $store): array
    {
        $priorSource = is_array($prior) ? ($prior['source'] ?? null) : null;
        $explicit = $this->inputs->secretFile !== null || $this->inputs->secretEnv !== null;
        if (in_array($priorSource, [IdentityPreparationResult::SOURCE_EXPLICIT_FILE, IdentityPreparationResult::SOURCE_EXPLICIT_ENV], true) && !$explicit) {
            throw IdentityBootstrapException::withCode('explicit-source-missing', IdentityBootstrapException::REMEDY_CONFIG);
        }
        if ($priorSource === self::MANIFEST_GENERATED && $explicit) {
            throw IdentityBootstrapException::withCode('identity-source-conflict', IdentityBootstrapException::REMEDY_CONFIG);
        }
        if ($this->inputs->secretFile !== null) {
            $src = $this->opener->openCanonicalPath($this->inputs->secretFile, 'install-secret-file', 256, SourceOpener::MODE_PRIVATE);
            $this->ops->close($src->handle);

            return [InstallSecretStore::parse($src->bytes, 'install-secret-file'), IdentityPreparationResult::SOURCE_EXPLICIT_FILE];
        }
        if ($this->inputs->secretEnv !== null) {
            return [InstallSecretStore::parse($this->inputs->secretEnv, 'install-secret-env'), IdentityPreparationResult::SOURCE_EXPLICIT_ENV];
        }
        [$master, $source] = $store->resolveOrCreateLocked();
        foreach ($store->warnings() as $w) {
            $this->storeWarnings[] = $w;
        }

        return [$master, $source === InstallSecretStore::SOURCE_GENERATED ? IdentityPreparationResult::SOURCE_GENERATED : IdentityPreparationResult::SOURCE_PERSISTED];
    }

    // --- persona -----------------------------------------------------------------------------------

    /**
     * Explicit FUNNYPOT_PERSONA_SEED, else legacy FUNNYPOT_PERSONA_SECRET, else install-derived. An
     * override is returned VERBATIM (cosmetic continuity only: security keys never derive from it).
     *
     * @param array<string,mixed>|null $prior
     * @return array{0:string,1:string,2:list<string>}
     */
    private function resolvePersona(IdentityKeyDeriver $deriver, ?array $prior): array
    {
        $warnings = [];
        $override = $this->inputs->personaSeed;
        if ($override === null && $this->inputs->personaSecret !== null) {
            $override = $this->inputs->personaSecret;
            $warnings[] = self::WARN_PERSONA_LEGACY_VAR;
        }
        if ($override === null) {
            if ($prior === null) {
                $warnings[] = self::WARN_PERSONA_FIRST_DERIVED;
            }

            return [$deriver->personaMaterial(), IdentityPreparationResult::PERSONA_DERIVED, $warnings];
        }
        if (strlen($override) > self::OVERRIDE_MAX_LEN || preg_match('/[\x00-\x1f\x7f]/', $override) === 1) {
            throw IdentityBootstrapException::withCode('persona-override-invalid', IdentityBootstrapException::REMEDY_CONFIG);
        }
        if (self::isWeakOverride($override)) {
            $warnings[] = self::WARN_PERSONA_WEAK;
        }

        return [$override, IdentityPreparationResult::PERSONA_OVERRIDE, $warnings];
    }

    /** ASCII trim + lowercase, then length below 16 or exact membership in the placeholder list. */
    public static function isWeakOverride(string $override): bool
    {
        $t = strtolower(trim($override, " \t\n\r\0\x0B"));

        return strlen($t) < self::WEAK_MIN_LEN || in_array($t, self::WEAK_OVERRIDES, true);
    }

    /** @return list<string> */
    private function legacyWarnings(): array
    {
        $w = [];
        if ($this->ops->lstat($this->paths->storageRoot() . '/fs_secret') !== false) {
            $w[] = self::WARN_LEGACY_FS_SECRET_FILE;
        }
        if ($this->inputs->legacyFsSecretEnvSet) {
            $w[] = self::WARN_LEGACY_FS_SECRET_ENV;
        }

        return $w;
    }

    // --- runtime tree ------------------------------------------------------------------------------

    /**
     * Create (or validate, never repair) the runtime tree. Returns whether the HTTP parent could be
     * given the www-data group: only a root preparer can, and only when the group exists; otherwise the
     * parent stays owner-only, which is recorded (non-secret) in the manifest.
     */
    private function ensureRuntimeDirectories(): bool
    {
        $root = $this->paths->runtimeRoot();
        $this->ensureDir($root, 0755, SourceOpener::MODE_NO_GO_WRITE);
        $this->ensureDir($this->paths->privateRuntimeDir(), 0700, SourceOpener::MODE_PRIVATE);
        $this->ensureDir($this->paths->runtimeTlsDir(), 0700, SourceOpener::MODE_PRIVATE);
        $this->ensureDir($this->paths->runtimeNginxDir(), 0700, SourceOpener::MODE_PRIVATE);

        $isRoot = $this->ops->euid() === 0;
        $gid = null;
        if ($isRoot) {
            $g = $this->ops->groupByName(self::HTTP_GROUP);
            if ($g === null || !isset($g['gid'])) {
                throw IdentityBootstrapException::withCode('http-group-missing', IdentityBootstrapException::REMEDY_RUNTIME);
            }
            $gid = (int) $g['gid'];
        }
        $http = $this->paths->httpRuntimeDir();
        $this->ensureDir($http, $gid !== null ? 0750 : 0700, SourceOpener::MODE_NO_GO_WRITE);
        if ($gid !== null) {
            if (!$this->ops->chgrp($http, $gid) || !$this->ops->chmod($http, 0750)) {
                throw IdentityBootstrapException::withCode('http-dir-group', IdentityBootstrapException::REMEDY_RUNTIME);
            }

            return true;
        }

        return false;
    }

    private function ensureDir(string $dir, int $mode, int $forbiddenMask): void
    {
        if ($this->ops->lstat($dir) === false) {
            $this->ops->mkdir($dir, $mode);
            $this->ops->chmod($dir, $mode);
        }
        $this->opener->requireDirectory($dir, 'runtime-dir', $forbiddenMask);
    }

    // --- artifacts ---------------------------------------------------------------------------------

    /** @return array<string,mixed>|null */
    private function readManifest(): ?array
    {
        if ($this->ops->lstat($this->paths->manifestPath()) === false) {
            return null;
        }
        $src = $this->opener->openDirect($this->paths->storageRoot(), ['.funnypot', 'identity', IdentityPaths::MANIFEST_FILE], 'manifest', self::MAX_MANIFEST_BYTES, SourceOpener::MODE_PRIVATE, SourceOpener::MODE_PRIVATE);
        $this->ops->close($src->handle);
        $m = json_decode($src->bytes, true, 8);
        if (!is_array($m) || ($m['schema'] ?? null) !== self::MANIFEST_SCHEMA) {
            throw IdentityBootstrapException::withCode('manifest-malformed', IdentityBootstrapException::REMEDY_STORAGE);
        }
        foreach (['source', 'persona_source', 'public_persona_hash', 'keyset_commitment'] as $k) {
            if (!is_string($m[$k] ?? null) || $m[$k] === '') {
                throw IdentityBootstrapException::withCode('manifest-malformed', IdentityBootstrapException::REMEDY_STORAGE);
            }
        }

        return $m;
    }

    /** @param array<string,string> $envelopeBase */
    private function verifyBundle(string $class, string $bundle, string $dir, string $file, array $envelopeBase): PreparedIdentitySource
    {
        $root = $this->paths->runtimeRoot();
        $src = $this->opener->openDirect(dirname($root), [basename($root), $dir, $file], 'bundle', IdentityBundleReader::MAX_BYTES, SourceOpener::MODE_NO_GO_WRITE, SourceOpener::MODE_NO_GO_WRITE);
        try {
            $doc = IdentityBundleReader::decode($src->bytes, $bundle);
        } catch (IdentityBootstrapException $e) {
            $this->ops->close($src->handle);
            throw $e;
        }
        $env = $doc['envelope'];
        foreach ($envelopeBase as $k => $v) {
            if (($env[$k] ?? null) !== $v) {
                $this->ops->close($src->handle);
                throw IdentityBootstrapException::withCode('bundle-verify-failed', IdentityBootstrapException::REMEDY_STORAGE);
            }
        }

        return PreparedIdentitySource::fromOpened($class, $src, [
            'schema' => $env['schema'],
            'bundle' => $env['bundle'],
            'public_persona_hash' => $env['public_persona_hash'],
            'keyset_commitment' => $env['keyset_commitment'],
        ]);
    }

    private function publishRuntimeTls(TlsSelection $tls): void
    {
        $this->replaceLink($this->paths->runtimeTlsCertPath(), $tls->certPath);
        $this->replaceLink($this->paths->runtimeTlsKeyPath(), $tls->keyPath);

        $vhost = $this->paths->adminVhostPath();
        if ($tls->hasAdminPair() && $tls->adminDomain !== null) {
            $domain = DnsName::validate($tls->adminDomain, 'tls-letsencrypt-domain-invalid');
            $live = DecoyCertificateManager::DEFAULT_LETSENCRYPT_ROOT . '/live/' . $domain;
            $conf = "server {\n"
                . "    listen 443 ssl;\n"
                . "    server_name {$domain};\n"
                . "    server_tokens off;\n"
                . "    access_log off;\n"
                . "    ssl_certificate {$live}/fullchain.pem;\n"
                . "    ssl_certificate_key {$live}/privkey.pem;\n"
                . "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                . "    set \$funnypot_https on;\n"
                . "    include /etc/nginx/funnypot-location.conf;\n"
                . "}\n";
            $this->writeAtomic($vhost, $conf, 0600, null, 'nginx-conf');
        } elseif ($this->ops->lstat($vhost) !== false) {
            $this->ops->unlink($vhost);
        }
    }

    /** Symlink swap through a temp name so the fixed nginx path never dangles. */
    private function replaceLink(string $link, string $target): void
    {
        $tmp = $link . '.tmp.' . $this->ops->randomHex(6);
        if (!$this->ops->symlink($target, $tmp) || !$this->ops->rename($tmp, $link)) {
            $this->ops->unlink($tmp);
            throw IdentityBootstrapException::withCode('tls-runtime-link', IdentityBootstrapException::REMEDY_RUNTIME);
        }
    }

    /**
     * O_EXCL 0600 temp beside the target, full write + flush + fsync, mode/group set on the temp (its
     * directory is root/owner-only, so nobody else can swap it), rename over the target, directory
     * fsync. Bundles/manifests are regenerated idempotently, so an overwrite here is correct — unlike
     * the master, which is only ever link()-published.
     */
    private function writeAtomic(string $path, string $bytes, int $mode, ?int $gid, string $code): void
    {
        $tmp = $path . '.tmp.' . $this->ops->randomHex(6);
        $h = $this->ops->openExclusive($tmp);
        if ($h === false) {
            throw IdentityBootstrapException::withCode($code . '-write', IdentityBootstrapException::REMEDY_STORAGE);
        }
        try {
            if ($this->ops->write($h, $bytes) !== strlen($bytes) || !$this->ops->flush($h) || !$this->ops->fsync($h)) {
                throw IdentityBootstrapException::withCode($code . '-write', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $this->ops->close($h);
            if ($gid !== null && !$this->ops->chgrp($tmp, $gid)) {
                throw IdentityBootstrapException::withCode($code . '-group', IdentityBootstrapException::REMEDY_RUNTIME);
            }
            if (!$this->ops->chmod($tmp, $mode)) {
                throw IdentityBootstrapException::withCode($code . '-mode', IdentityBootstrapException::REMEDY_STORAGE);
            }
            if (!$this->ops->rename($tmp, $path)) {
                throw IdentityBootstrapException::withCode($code . '-write', IdentityBootstrapException::REMEDY_STORAGE);
            }
        } catch (\Throwable $e) {
            $this->ops->close($h);
            $this->ops->unlink($tmp);
            throw $e;
        }
        $d = $this->ops->openDir(dirname($path));
        if ($d === false || !$this->ops->fsync($d)) {
            $this->ops->close($d);
            throw IdentityBootstrapException::withCode('directory-fsync', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $this->ops->close($d);
    }

    /** @param array<string,mixed> $envelopeBase @param array<string,string> $payload */
    private static function bundleJson(array $envelopeBase, string $bundle, array $payload): string
    {
        return self::canonicalJson(['envelope' => $envelopeBase + ['bundle' => $bundle], 'payload' => $payload]);
    }

    /** Sorted keys, unescaped slashes, final LF — the same bytes for the same facts. @param array<string,mixed> $doc */
    public static function canonicalJson(array $doc): string
    {
        $doc = self::ksortDeep($doc);

        return json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n";
    }

    /** @param array<mixed> $a @return array<mixed> */
    private static function ksortDeep(array $a): array
    {
        if (array_is_list($a)) {
            return array_map(static fn ($v) => is_array($v) ? self::ksortDeep($v) : $v, $a);
        }
        ksort($a);
        foreach ($a as $k => $v) {
            if (is_array($v)) {
                $a[$k] = self::ksortDeep($v);
            }
        }

        return $a;
    }
}

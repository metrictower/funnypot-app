<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * Every fixed path of the install identity. Callers pick a trusted root (the persisted storage
 * mount, the runtime directory) — never an internal file name — so no configuration value can
 * redirect the master, the manifest or a bundle to an attacker-chosen file.
 *
 * Persistent (survives container recreate, beneath the storage volume, private 0700):
 *   <storage>/.funnypot/identity/{install.secret,install.lock,manifest.json,tls/}
 * Runtime (per boot, root-written before any child starts):
 *   <runtime>/identity-private/{shell,sip,redis,post-exploit-state}.json   0700 / 0600 root-only
 *   <runtime>/identity-http/http.json                                     0750 root:www-data / 0640
 *   <runtime>/tls/{cert,key}.pem                                          links to the selected pair
 *   <runtime>/nginx/admin-ssl.conf                                        rendered Let's Encrypt vhost
 *
 * The runtime root defaults to /run/funnypot; FUNNYPOT_IDENTITY_RUNTIME_DIR relocates it (a path,
 * not a secret — it is how php-fpm and the php -S fixtures find their bundle). The persistent root
 * follows the hit-store db (FUNNYPOT_DB) exactly as the config store does, so redirecting the db for a
 * test isolates the identity store too, with no second knob.
 */
final class IdentityPaths
{
    public const RUNTIME_ENV = 'FUNNYPOT_IDENTITY_RUNTIME_DIR';
    public const DEFAULT_RUNTIME_ROOT = '/run/funnypot';

    public const MASTER_FILE = 'install.secret';
    public const LOCK_FILE = 'install.lock';
    public const TEMP_PREFIX = 'install.secret.tmp.';
    public const MANIFEST_FILE = 'manifest.json';

    public const HTTP_BUNDLE = 'http.json';
    public const SHELL_BUNDLE = 'shell.json';
    public const SIP_BUNDLE = 'sip.json';
    public const REDIS_BUNDLE = 'redis.json';
    public const POST_EXPLOIT_BUNDLE = 'post-exploit-state.json';

    private function __construct(private string $storageRoot, private string $runtimeRoot)
    {
    }

    /**
     * @param string      $storageDir  the persisted storage directory (dirname of the hit-store db)
     * @param string|null $runtimeRoot absolute runtime root; null = the default
     */
    public static function forStorage(string $storageDir, ?string $runtimeRoot = null): self
    {
        $storageDir = rtrim($storageDir, '/');
        if ($storageDir === '' || $storageDir[0] !== '/') {
            throw IdentityBootstrapException::withCode('storage-root-invalid', IdentityBootstrapException::REMEDY_CONFIG);
        }
        $runtime = $runtimeRoot ?? self::DEFAULT_RUNTIME_ROOT;
        $runtime = rtrim($runtime, '/');
        if ($runtime === '' || $runtime[0] !== '/' || in_array('..', explode('/', $runtime), true)) {
            throw IdentityBootstrapException::withCode('runtime-root-invalid', IdentityBootstrapException::REMEDY_CONFIG);
        }

        return new self($storageDir, $runtime);
    }

    /**
     * Resolve from the process environment the way AppConfig/ConfigStore derive the storage dir:
     * FUNNYPOT_DB's directory, else <demoDir>/storage. $env is getenv()-shaped (false when unset).
     *
     * @param callable(string):(string|false)|null $env
     */
    public static function fromEnvironment(string $demoDir, ?callable $env = null): self
    {
        $env ??= static fn (string $k) => getenv($k);
        $db = $env('FUNNYPOT_DB');
        if (!is_string($db) || $db === '' || $db === 'off') {
            $db = rtrim($demoDir, '/') . '/storage/funnypot.sqlite';
        }
        $runtime = $env(self::RUNTIME_ENV);

        return self::forStorage(dirname($db), is_string($runtime) && $runtime !== '' ? $runtime : null);
    }

    public function storageRoot(): string
    {
        return $this->storageRoot;
    }

    /** The private directory beneath the (legacy 0777) storage mount; 0700, owner-only. */
    public function privateRoot(): string
    {
        return $this->storageRoot . '/.funnypot';
    }

    public function persistentRoot(): string
    {
        return $this->privateRoot() . '/identity';
    }

    public function masterPath(): string
    {
        return $this->persistentRoot() . '/' . self::MASTER_FILE;
    }

    public function lockPath(): string
    {
        return $this->persistentRoot() . '/' . self::LOCK_FILE;
    }

    /** One attempt's temp: fixed prefix (so crash recovery can enumerate) + unpredictable suffix. */
    public function tempPath(string $suffix): string
    {
        return $this->persistentRoot() . '/' . self::TEMP_PREFIX . $suffix;
    }

    public function manifestPath(): string
    {
        return $this->persistentRoot() . '/' . self::MANIFEST_FILE;
    }

    public function tlsDir(): string
    {
        return $this->persistentRoot() . '/tls';
    }

    public function tlsCertPath(): string
    {
        return $this->tlsDir() . '/cert.pem';
    }

    public function tlsKeyPath(): string
    {
        return $this->tlsDir() . '/key.pem';
    }

    public function tlsProvenancePath(): string
    {
        return $this->tlsDir() . '/provenance.json';
    }

    public function runtimeRoot(): string
    {
        return $this->runtimeRoot;
    }

    public function privateRuntimeDir(): string
    {
        return $this->runtimeRoot . '/identity-private';
    }

    public function httpRuntimeDir(): string
    {
        return $this->runtimeRoot . '/identity-http';
    }

    public function httpBundlePath(): string
    {
        return $this->httpRuntimeDir() . '/' . self::HTTP_BUNDLE;
    }

    public function shellBundlePath(): string
    {
        return $this->privateRuntimeDir() . '/' . self::SHELL_BUNDLE;
    }

    public function sipBundlePath(): string
    {
        return $this->privateRuntimeDir() . '/' . self::SIP_BUNDLE;
    }

    public function redisBundlePath(): string
    {
        return $this->privateRuntimeDir() . '/' . self::REDIS_BUNDLE;
    }

    public function postExploitBundlePath(): string
    {
        return $this->privateRuntimeDir() . '/' . self::POST_EXPLOIT_BUNDLE;
    }

    public function runtimeTlsDir(): string
    {
        return $this->runtimeRoot . '/tls';
    }

    public function runtimeTlsCertPath(): string
    {
        return $this->runtimeTlsDir() . '/cert.pem';
    }

    public function runtimeTlsKeyPath(): string
    {
        return $this->runtimeTlsDir() . '/key.pem';
    }

    public function runtimeNginxDir(): string
    {
        return $this->runtimeRoot . '/nginx';
    }

    public function adminVhostPath(): string
    {
        return $this->runtimeNginxDir() . '/admin-ssl.conf';
    }
}

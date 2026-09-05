<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * Every fixed path of the service-profile subsystem, derived from a trusted storage root the same way
 * {@see \Funnypot\App\Identity\IdentityPaths} is — so a test (and FP-0319) redirects the whole tree
 * by choosing the storage dir, never by rewriting a hard-coded constant. The production literals stay
 * as class constants so a downstream ticket can record the exact production default and this class can
 * prove `forStorage('/app/demo/storage')->persistentManifest() === PERSISTENT_MANIFEST`.
 *
 * Two trees, different owners:
 *   Persistent, root-only (survives container recreate, beneath the storage volume):
 *     <storage>/.funnypot/services/                       0700 root:root
 *       runtime.sqlite                                    0600 root:root  (effective/LKG authority)
 *       exposure-manifest.json                            0600 root:root  (the ONLY binding source)
 *       nginx-http-listens.conf / nginx-https-listens.conf (fragment bytes bound to the plan hash)
 *   Persistent, www-data-writable (the PHP-writable desired store):
 *     <storage>/.funnypot/service-profile/                2770 root:www-data (setgid)
 *       service-profile.sqlite                            0660 root:www-data
 *   Runtime, per boot:
 *     /run/funnypot-service-status/effective.json         health heartbeat, never a binding source
 *     /run/funnypot/services-private/nginx-*-listens.conf installed fragments nginx includes
 *
 * The setgid desired dir makes the kernel assign the www-data group to the -wal/-shm sidecars at
 * creation, so a root open never leaves www-data locked out of a root:root -shm.
 */
final class ServicePaths
{
    /** The production storage mount (deploy mounts the data volume here). */
    public const PRODUCTION_STORAGE = '/app/demo/storage';

    /** The one downstream binding source, at the production default. FP-0319 records this literal. */
    public const PERSISTENT_MANIFEST = '/app/demo/storage/.funnypot/services/exposure-manifest.json';

    /** The health heartbeat, at the production default. Never a binding source. */
    public const STATUS_FILE = '/run/funnypot-service-status/effective.json';

    public const DEFAULT_RUNTIME_ROOT = '/run/funnypot';
    public const DEFAULT_STATUS_ROOT = '/run/funnypot-service-status';

    public const MANIFEST_FILE = 'exposure-manifest.json';
    public const RUNTIME_DB_FILE = 'runtime.sqlite';
    public const DESIRED_DB_FILE = 'service-profile.sqlite';
    public const STATUS_FILE_NAME = 'effective.json';
    public const NGINX_HTTP_FRAGMENT = 'nginx-http-listens.conf';
    public const NGINX_HTTPS_FRAGMENT = 'nginx-https-listens.conf';

    private function __construct(
        private string $storageRoot,
        private string $runtimeRoot,
        private string $statusRoot,
    ) {
    }

    /**
     * @param string      $storageDir  the persisted storage directory (dirname of the hit-store db)
     * @param string|null $runtimeRoot absolute runtime root for nginx fragments; null = the default
     * @param string|null $statusRoot  absolute status heartbeat root; null = the default
     */
    public static function forStorage(string $storageDir, ?string $runtimeRoot = null, ?string $statusRoot = null): self
    {
        $storageDir = self::validAbsolute($storageDir, 'storage-root');
        $runtime = self::validAbsolute($runtimeRoot ?? self::DEFAULT_RUNTIME_ROOT, 'runtime-root');
        $status = self::validAbsolute($statusRoot ?? self::DEFAULT_STATUS_ROOT, 'status-root');

        return new self($storageDir, $runtime, $status);
    }

    /**
     * Resolve from the environment exactly as {@see ConfigStore::defaultDbPath()} and IdentityPaths do:
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
        $runtime = $env('FUNNYPOT_IDENTITY_RUNTIME_DIR');
        $status = $env('FUNNYPOT_SERVICE_STATUS_DIR');

        return self::forStorage(
            dirname($db),
            is_string($runtime) && $runtime !== '' ? $runtime : null,
            is_string($status) && $status !== '' ? $status : null,
        );
    }

    private static function validAbsolute(string $path, string $what): string
    {
        $path = rtrim($path, '/');
        if ($path === '' || $path[0] !== '/' || in_array('..', explode('/', $path), true)) {
            throw new \InvalidArgumentException("service paths: {$what} must be an absolute path");
        }

        return $path;
    }

    public function storageRoot(): string
    {
        return $this->storageRoot;
    }

    public function privateRoot(): string
    {
        return $this->storageRoot . '/.funnypot';
    }

    /** The 0700 root:root persistent service dir: runtime.sqlite, exposure-manifest.json, fragments. */
    public function persistentDir(): string
    {
        return $this->privateRoot() . '/services';
    }

    public function persistentManifest(): string
    {
        return $this->persistentDir() . '/' . self::MANIFEST_FILE;
    }

    public function runtimeDbPath(): string
    {
        return $this->persistentDir() . '/' . self::RUNTIME_DB_FILE;
    }

    public function persistentNginxHttp(): string
    {
        return $this->persistentDir() . '/' . self::NGINX_HTTP_FRAGMENT;
    }

    public function persistentNginxHttps(): string
    {
        return $this->persistentDir() . '/' . self::NGINX_HTTPS_FRAGMENT;
    }

    /** The 2770 root:www-data setgid dir holding the PHP-writable desired store. */
    public function desiredStoreDir(): string
    {
        return $this->privateRoot() . '/service-profile';
    }

    public function desiredDbPath(): string
    {
        return $this->desiredStoreDir() . '/' . self::DESIRED_DB_FILE;
    }

    public function statusRoot(): string
    {
        return $this->statusRoot;
    }

    public function statusFile(): string
    {
        return $this->statusRoot . '/' . self::STATUS_FILE_NAME;
    }

    public function runtimeNginxDir(): string
    {
        return $this->runtimeRoot . '/services-private';
    }

    public function runtimeNginxHttp(): string
    {
        return $this->runtimeNginxDir() . '/' . self::NGINX_HTTP_FRAGMENT;
    }

    public function runtimeNginxHttps(): string
    {
        return $this->runtimeNginxDir() . '/' . self::NGINX_HTTPS_FRAGMENT;
    }
}

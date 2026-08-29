<?php

declare(strict_types=1);

namespace Funnypot\App\Docker;

use Funnypot\Core\RequestContext;

/**
 * Front-controller seam for the fake Docker Engine API. It recognises the Docker daemon's REST path
 * shape and hands matched requests to the responder. Docker clients prepend a `/v1.NN` API-version
 * prefix (`/v1.43/version`), so both the versioned and unversioned forms of each endpoint are matched;
 * everything unrecognised falls through to the honeypot catch-all unchanged.
 *
 * Path-based (not port-based) on purpose: a Docker client fingerprints the same daemon paths whichever
 * port it reached, and RequestContext carries no port. The distinctive paths (/_ping, /containers/*,
 * /v1.NN/*) are unmistakably Docker; the generic /version and /info are accepted as Docker paths too,
 * which is acceptable bait breadth for a honeypot.
 */
final class DockerApiRouter
{
    /** Optional Docker API-version prefix a client prepends, e.g. `/v1.43`. */
    private const VERSION_PREFIX = '#^/v1\.\d+(?:\.\d+)?#';

    public function __construct(private DockerApiResponder $responder)
    {
    }

    /** True for any request path the fake Docker daemon owns (recon GET or container-deploy POST). */
    public function matches(string $path): bool
    {
        return self::endpoint($path) !== null;
    }

    /** Static twin of matches() for the front controller, which strips X-Powered-By across this
     *  surface (a real Docker daemon sends none) before the router is even constructed. */
    public static function isDockerSurface(string $path): bool
    {
        return self::endpoint($path) !== null;
    }

    public function handle(RequestContext $ctx, string $clientIp): void
    {
        $this->responder->respond($ctx, $clientIp);
    }

    /**
     * Classify a request path into the Docker endpoint it hits, or null. The `/v1.NN` prefix is
     * stripped first so `/v1.43/version` and `/version` classify the same. Shared by matches() and the
     * responder so recognition lives in exactly one place.
     */
    public static function endpoint(string $path): ?string
    {
        $p = (string) preg_replace(self::VERSION_PREFIX, '', $path);
        if ($p === '') {
            $p = '/';
        }

        switch ($p) {
            case '/_ping':
                return 'ping';
            case '/version':
                return 'version';
            case '/info':
                return 'info';
            case '/containers/json':
                return 'containers';
            case '/containers/create':
                return 'create';
            case '/images/json':
                return 'images';
        }

        // POST /containers/{id}/start — {id} is a container name or hex id.
        if (preg_match('#^/containers/[^/]+/start$#', $p) === 1) {
            return 'start';
        }

        return null;
    }

    /** The container id/name in a `/containers/{id}/start` path (version prefix already tolerated). */
    public static function startTarget(string $path): string
    {
        $p = (string) preg_replace(self::VERSION_PREFIX, '', $path);
        if (preg_match('#^/containers/([^/]+)/start$#', $p, $m) === 1) {
            return $m[1];
        }

        return '';
    }
}

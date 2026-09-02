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
 * PORT SCOPING (FP-0264): the unmistakable Docker path shapes (/_ping, /v1.NN/*, /containers/*,
 * /images/*, /exec/*, /networks, /volumes, /events) are claimed on ANY port — a Docker client
 * fingerprints the same daemon paths whichever port it reached. The generic bare `/version` and
 * `/info`, which collide with ordinary web apps, are claimed ONLY on a Docker port (2375/2376/4243) or
 * when the port is unknown (0 — unit tests / `php -S`, kept permissive). On a Docker port the seam owns
 * the WHOLE port, so an unmatched path is answered as dockerd's own `404 {"message":"page not found"}`
 * with daemon headers instead of falling through to an nginx-style HTML 404 (itself a tell on 2375).
 */
final class DockerApiRouter
{
    /** Optional Docker API-version prefix a client prepends, e.g. `/v1.43`. */
    private const VERSION_PREFIX = '#^/v1\.\d+(?:\.\d+)?#';

    /** Ports a real unauthenticated dockerd listens on (2375 plaintext, 2376 TLS, 4243 legacy). */
    private const DOCKER_PORTS = [2375, 2376, 4243];

    public function __construct(private DockerApiResponder $responder, private int $port = 0)
    {
    }

    /** True for any request path the fake Docker daemon owns at this router's port. */
    public function matches(string $path): bool
    {
        if (self::isDockerPort($this->port)) {
            return true;   // on a Docker port the seam owns everything (unmatched => page-not-found)
        }

        return self::owns($path, $this->port);
    }

    /** Static twin of matches() for the front controller, which strips X-Powered-By across this
     *  surface (a real Docker daemon sends none) before the router is even constructed. */
    public static function isDockerSurface(string $path, int $port = 0): bool
    {
        return self::isDockerPort($port) || self::owns($path, $port);
    }

    public static function isDockerPort(int $port): bool
    {
        return in_array($port, self::DOCKER_PORTS, true);
    }

    public function handle(RequestContext $ctx, string $clientIp): void
    {
        $this->responder->respond($ctx, $clientIp);
    }

    /**
     * Whether the seam owns $path at $port, applying the port scoping. `port === 0` (unknown) and a
     * Docker port both allow the bare generic paths; other ports allow only the distinctive shapes.
     */
    private static function owns(string $path, int $port): bool
    {
        // A `/v1.NN` version prefix is itself an unmistakable Docker tell — owned on every port.
        $versioned = preg_match(self::VERSION_PREFIX, $path) === 1;
        $p = self::strip($path);
        if (!$versioned && ($p === '/version' || $p === '/info')) {
            return $port === 0 || self::isDockerPort($port);
        }
        if ($p === '/version' || $p === '/info') {
            return true;   // versioned form
        }

        return self::distinctive($p);
    }

    /** The unmistakable Docker path shapes, owned on every port. */
    private static function distinctive(string $p): bool
    {
        if (in_array($p, ['/_ping', '/containers/json', '/containers/create', '/images/json', '/images/create', '/events', '/networks', '/volumes'], true)) {
            return true;
        }

        return preg_match('#^/(?:containers|exec|images|networks|volumes)/#', $p) === 1;
    }

    /**
     * Classify a request path + method into the Docker endpoint kind it hits, or null. The `/v1.NN`
     * prefix is stripped first. Shared by the responder so recognition lives in one place. Method
     * matters only for `DELETE /containers/{id}` (remove) vs an otherwise-unclaimed bare id path.
     */
    public static function endpoint(string $path, string $method = 'GET'): ?string
    {
        $p = self::strip($path);

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
            case '/images/create':
                return 'pull';
            case '/networks':
            case '/volumes':
            case '/events':
                return 'noop-list';
        }

        // /containers/{id}/{verb}
        if (preg_match('#^/containers/[^/]+/(start|stop|kill|restart|json|logs|wait|attach|exec)$#', $p, $m) === 1) {
            return $m[1] === 'json' ? 'inspect' : ($m[1] === 'exec' ? 'exec-create' : $m[1]);
        }
        // /exec/{id}/{verb}
        if (preg_match('#^/exec/[^/]+/start$#', $p) === 1) {
            return 'exec-start';
        }
        if (preg_match('#^/exec/[^/]+/json$#', $p) === 1) {
            return 'exec-inspect';
        }
        // GET /images/{name}/json — the name may itself contain slashes (registry/repo).
        if (preg_match('#^/images/.+/json$#', $p) === 1) {
            return 'image-inspect';
        }
        // DELETE /containers/{id} — remove. Any other method on a bare id path is not a Docker verb.
        if (preg_match('#^/containers/[^/]+$#', $p) === 1) {
            return strtoupper($method) === 'DELETE' ? 'remove' : null;
        }

        return null;
    }

    /** The container id/name in a `/containers/{id}/…` or bare `/containers/{id}` path. */
    public static function target(string $path): string
    {
        $p = self::strip($path);
        if (preg_match('#^/containers/([^/]+)(?:/[^/]+)?$#', $p, $m) === 1) {
            return $m[1];
        }
        if (preg_match('#^/exec/([^/]+)/[^/]+$#', $p, $m) === 1) {
            return $m[1];
        }
        if (preg_match('#^/images/(.+)/json$#', $p, $m) === 1) {
            return $m[1];
        }

        return '';
    }

    /** Backwards-compatible alias kept for callers that only need the start target. */
    public static function startTarget(string $path): string
    {
        $p = self::strip($path);

        return preg_match('#^/containers/([^/]+)/start$#', $p, $m) === 1 ? $m[1] : '';
    }

    private static function strip(string $path): string
    {
        $p = (string) preg_replace(self::VERSION_PREFIX, '', $path);

        return $p === '' ? '/' : $p;
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use Funnypot\App\Docker\DockerApiResponder;
use Funnypot\App\Docker\DockerApiRouter;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The Docker front-controller seam: which paths it owns (the daemon's REST endpoints, versioned or
 * not), which paths it must NOT claim (notably the AI `/v1/…` slash paths, distinct from Docker's
 * `/v1.NN` dotted prefix), that handle() delegates to the responder, and the FP-0264 port scoping
 * (bare /version + /info only on a Docker port or when the port is unknown).
 */
final class DockerApiRouterTest extends TestCase
{
    /** @return array<string,array{0:string,1:string}> path => expected endpoint kind */
    public static function ownedPaths(): array
    {
        return [
            'unversioned ping' => ['/_ping', 'ping'],
            'unversioned version' => ['/version', 'version'],
            'unversioned info' => ['/info', 'info'],
            'unversioned containers' => ['/containers/json', 'containers'],
            'unversioned create' => ['/containers/create', 'create'],
            'unversioned images' => ['/images/json', 'images'],
            'images create (pull)' => ['/images/create', 'pull'],
            'start by hex id' => ['/containers/c8a1e94fc07b/start', 'start'],
            'start by name' => ['/containers/xmrig/start', 'start'],
            'inspect' => ['/containers/abc/json', 'inspect'],
            'logs' => ['/containers/abc/logs', 'logs'],
            'wait' => ['/containers/abc/wait', 'wait'],
            'stop' => ['/containers/abc/stop', 'stop'],
            'kill' => ['/containers/abc/kill', 'kill'],
            'restart' => ['/containers/abc/restart', 'restart'],
            'attach' => ['/containers/abc/attach', 'attach'],
            'exec create' => ['/containers/abc/exec', 'exec-create'],
            'exec start' => ['/exec/deadbeef/start', 'exec-start'],
            'exec inspect' => ['/exec/deadbeef/json', 'exec-inspect'],
            'image inspect' => ['/images/alpine/json', 'image-inspect'],
            'image inspect nested' => ['/images/library/alpine/json', 'image-inspect'],
            'versioned ping' => ['/v1.43/_ping', 'ping'],
            'versioned version' => ['/v1.24/version', 'version'],
            'versioned info' => ['/v1.41/info', 'info'],
            'versioned containers' => ['/v1.24/containers/json', 'containers'],
            'versioned create' => ['/v1.24/containers/create', 'create'],
            'versioned start' => ['/v1.43/containers/deadbeef/start', 'start'],
        ];
    }

    /** @dataProvider ownedPaths */
    public function test_matches_and_classifies_every_docker_endpoint(string $path, string $kind): void
    {
        $router = new DockerApiRouter($this->spyResponder());

        self::assertTrue($router->matches($path), "$path should be a Docker path");
        self::assertTrue(DockerApiRouter::isDockerSurface($path), "$path should be a Docker surface");
        self::assertSame($kind, DockerApiRouter::endpoint($path), "$path should classify as $kind");
    }

    public function test_delete_container_is_remove_only_for_the_delete_method(): void
    {
        self::assertSame('remove', DockerApiRouter::endpoint('/containers/abc', 'DELETE'));
        self::assertNull(DockerApiRouter::endpoint('/containers/abc', 'GET'));
    }

    /** @return array<string,array{0:string}> paths the Docker seam must leave to other handlers. */
    public static function foreignPaths(): array
    {
        return [
            'ai models (slash v1, not dotted)' => ['/v1/models'],
            'ai chat completions' => ['/v1/chat/completions'],
            'ai messages' => ['/v1/messages'],
            'root' => ['/'],
            'wp-login' => ['/wp-login.php'],
            'partial version word' => ['/versionx'],
            'random path' => ['/some/random/path'],
        ];
    }

    /** @dataProvider foreignPaths */
    public function test_does_not_claim_foreign_paths(string $path): void
    {
        $router = new DockerApiRouter($this->spyResponder());   // port 0 (unknown)

        self::assertFalse($router->matches($path), "$path must not be claimed by the Docker seam");
        self::assertFalse(DockerApiRouter::isDockerSurface($path));
    }

    public function test_bare_version_and_info_are_port_scoped(): void
    {
        // Owned on a Docker port or when the port is unknown (0), NOT on a web port.
        foreach ([0, 2375, 2376, 4243] as $port) {
            self::assertTrue((new DockerApiRouter($this->spyResponder(), $port))->matches('/version'), "version owned at port $port");
            self::assertTrue((new DockerApiRouter($this->spyResponder(), $port))->matches('/info'), "info owned at port $port");
        }
        foreach ([80, 443, 8080] as $port) {
            self::assertFalse((new DockerApiRouter($this->spyResponder(), $port))->matches('/version'), "version NOT owned at port $port");
            self::assertFalse((new DockerApiRouter($this->spyResponder(), $port))->matches('/info'), "info NOT owned at port $port");
        }
    }

    public function test_distinctive_shapes_are_owned_on_every_port(): void
    {
        foreach ([80, 443, 2375] as $port) {
            $r = new DockerApiRouter($this->spyResponder(), $port);
            self::assertTrue($r->matches('/v1.43/version'), 'versioned /version is distinctive');
            self::assertTrue($r->matches('/_ping'));
            self::assertTrue($r->matches('/containers/json'));
            self::assertTrue($r->matches('/containers/abc/start'));
        }
    }

    public function test_docker_port_owns_the_whole_port_for_fallthrough(): void
    {
        $r = new DockerApiRouter($this->spyResponder(), 2375);
        self::assertTrue($r->matches('/wp-login.php'), 'a Docker port answers even unmatched paths (page-not-found)');
        // The endpoint classifier itself returns null; the responder turns that into page-not-found.
        self::assertNull(DockerApiRouter::endpoint('/wp-login.php'));

        $web = new DockerApiRouter($this->spyResponder(), 80);
        self::assertFalse($web->matches('/wp-login.php'), 'a web port leaves unmatched paths to the honeypot');
    }

    public function test_target_extracts_the_container_id(): void
    {
        self::assertSame('c8a1e94fc07b', DockerApiRouter::target('/containers/c8a1e94fc07b/start'));
        self::assertSame('xmrig', DockerApiRouter::target('/v1.43/containers/xmrig/json'));
        self::assertSame('abc', DockerApiRouter::target('/containers/abc'));
        self::assertSame('deadbeef', DockerApiRouter::target('/exec/deadbeef/start'));
        self::assertSame('library/alpine', DockerApiRouter::target('/images/library/alpine/json'));
        self::assertSame('c8a1e94fc07b', DockerApiRouter::startTarget('/containers/c8a1e94fc07b/start'));
        self::assertSame('', DockerApiRouter::target('/version'));
    }

    public function test_handle_delegates_to_the_responder(): void
    {
        $calls = 0;
        $responder = $this->getMockBuilder(DockerApiResponder::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['respond'])
            ->getMock();
        $responder->method('respond')->willReturnCallback(static function () use (&$calls): void {
            $calls++;
        });

        (new DockerApiRouter($responder))->handle(new RequestContext('GET', '/version'), '9.9.9.9');

        self::assertSame(1, $calls);
    }

    /** @return DockerApiResponder&\PHPUnit\Framework\MockObject\MockObject */
    private function spyResponder(): DockerApiResponder
    {
        return $this->getMockBuilder(DockerApiResponder::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['respond'])
            ->getMock();
    }
}

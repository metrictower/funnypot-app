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
 * `/v1.NN` dotted prefix), and that handle() delegates to the responder.
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
            'start by hex id' => ['/containers/c8a1e94fc07b/start', 'start'],
            'start by name' => ['/containers/xmrig/start', 'start'],
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

    /** @return array<string,array{0:string}> paths the Docker seam must leave to other handlers. */
    public static function foreignPaths(): array
    {
        return [
            'ai models (slash v1, not dotted)' => ['/v1/models'],
            'ai chat completions' => ['/v1/chat/completions'],
            'ai messages' => ['/v1/messages'],
            'root' => ['/'],
            'wp-login' => ['/wp-login.php'],
            'containers stop (unhandled verb)' => ['/containers/abc/stop'],
            'container inspect (unhandled)' => ['/containers/abc/json'],
            'images create (unhandled pull)' => ['/images/create'],
            'partial version word' => ['/versionx'],
        ];
    }

    /** @dataProvider foreignPaths */
    public function test_does_not_claim_foreign_paths(string $path): void
    {
        $router = new DockerApiRouter($this->spyResponder());

        self::assertFalse($router->matches($path), "$path must not be claimed by the Docker seam");
        self::assertFalse(DockerApiRouter::isDockerSurface($path));
        self::assertNull(DockerApiRouter::endpoint($path));
    }

    public function test_start_target_extracts_the_container_id(): void
    {
        self::assertSame('c8a1e94fc07b', DockerApiRouter::startTarget('/containers/c8a1e94fc07b/start'));
        self::assertSame('xmrig', DockerApiRouter::startTarget('/v1.43/containers/xmrig/start'));
        self::assertSame('', DockerApiRouter::startTarget('/version'));
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

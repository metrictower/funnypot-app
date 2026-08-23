<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\AiApiRouter;
use Funnypot\App\AiApi\AiChatHandler;
use Funnypot\App\AiApi\Dialect\AnthropicDialect;
use Funnypot\App\AiApi\Dialect\OllamaDialect;
use Funnypot\App\AiApi\Dialect\OpenAiDialect;
use Funnypot\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The AI-API front-controller seam: which paths it owns (POST chat only), which paths count as the AI
 * footprint (chat + GET recon), and that handle() delegates to the handler with the right dialect.
 */
final class AiApiRouterTest extends TestCase
{
    public function test_matches_only_the_post_chat_paths(): void
    {
        $router = new AiApiRouter($this->spyHandler());

        self::assertTrue($router->matches('/api/chat'));
        self::assertTrue($router->matches('/api/generate'));
        self::assertTrue($router->matches('/v1/chat/completions'));
        self::assertTrue($router->matches('/v1/messages'));

        self::assertFalse($router->matches('/api/tags'));   // GET recon is core's job
        self::assertFalse($router->matches('/v1/models'));
        self::assertFalse($router->matches('/x'));
    }

    public function test_is_ai_surface_covers_chat_and_recon(): void
    {
        self::assertTrue(AiApiRouter::isAiSurface('/api/chat'));
        self::assertTrue(AiApiRouter::isAiSurface('/api/tags'));
        self::assertTrue(AiApiRouter::isAiSurface('/v1/models'));
        self::assertTrue(AiApiRouter::isAiSurface('/api/show'));

        self::assertFalse(AiApiRouter::isAiSurface('/wp-login.php'));
        self::assertFalse(AiApiRouter::isAiSurface('/'));
    }

    public function test_handle_delegates_once_with_the_ollama_dialect(): void
    {
        $this->assertDelegatesWith('/api/chat', OllamaDialect::class);
        $this->assertDelegatesWith('/api/generate', OllamaDialect::class);
        $this->assertDelegatesWith('/v1/chat/completions', OpenAiDialect::class);
        $this->assertDelegatesWith('/v1/messages', AnthropicDialect::class);
    }

    private function assertDelegatesWith(string $path, string $dialectClass): void
    {
        $captured = null;
        $calls = 0;
        $handler = $this->spyHandler();
        $handler->method('serve')->willReturnCallback(
            function ($dialect, $ctx, $ip) use (&$captured, &$calls): void {
                $captured = $dialect;
                $calls++;
            }
        );

        (new AiApiRouter($handler))->handle(new RequestContext('POST', $path), '9.9.9.9');

        self::assertSame(1, $calls, "$path should delegate exactly once");
        self::assertInstanceOf($dialectClass, $captured, "$path should map to $dialectClass");
    }

    /** @return AiChatHandler&\PHPUnit\Framework\MockObject\MockObject */
    private function spyHandler(): AiChatHandler
    {
        return $this->getMockBuilder(AiChatHandler::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['serve'])
            ->getMock();
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Dialect\AnthropicDialect;
use Funnypot\App\AiApi\Dialect\OllamaDialect;
use Funnypot\App\AiApi\Dialect\OpenAiDialect;
use Funnypot\Core\RequestContext;

/**
 * Front-controller seam for the fake inference API. It owns the POST chat surface only: it maps one of
 * the four chat paths to the provider dialect that frames it and hands the turn to the handler. The
 * GET recon surface (/api/tags, /v1/models, ...) is funnypot-core's job — isAiSurface() lists both
 * so the front controller can strip X-Powered-By across the whole AI footprint, not just the chat POSTs.
 */
final class AiApiRouter
{
    /** The POST chat endpoints this router serves (exact-match). */
    public const CHAT_PATHS = ['/api/chat', '/api/generate', '/v1/chat/completions', '/v1/messages'];

    /** The GET recon endpoints core serves; not handled here, but part of the AI footprint. */
    private const RECON_PATHS = ['/api/tags', '/api/version', '/api/ps', '/api/show', '/v1/models'];

    /** @var array<string,ChatDialect> path => the dialect that frames it */
    private array $dialects;

    public function __construct(private AiChatHandler $handler)
    {
        // One Ollama dialect serves both its paths (it tells /api/chat from /api/generate by the path).
        $ollama = new OllamaDialect();
        $this->dialects = [
            '/api/chat' => $ollama,
            '/api/generate' => $ollama,
            '/v1/chat/completions' => new OpenAiDialect(),
            '/v1/messages' => new AnthropicDialect(),
        ];
    }

    /** True for a POST chat path this router should handle (GET recon is core's job → false). */
    public function matches(string $path): bool
    {
        return in_array($path, self::CHAT_PATHS, true);
    }

    /** True for any AI-API path (chat or recon) — the front controller uses this to strip X-Powered-By. */
    public static function isAiSurface(string $path): bool
    {
        return in_array($path, self::CHAT_PATHS, true) || in_array($path, self::RECON_PATHS, true);
    }

    /** Pick the dialect for this path and delegate to the handler. */
    public function handle(RequestContext $ctx, string $clientIp): void
    {
        $dialect = $this->dialects[$ctx->path] ?? null;
        if ($dialect === null) {
            return; // not a chat path; callers guard with matches() first
        }

        $this->handler->serve($dialect, $ctx, $clientIp);
    }
}

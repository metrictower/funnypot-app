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
    /** The POST chat endpoints this router serves (canonical; one trailing slash also accepted). */
    public const CHAT_PATHS = AiSurfacePath::CHAT;

    /** @var array<string,ChatDialect> canonical path => the dialect that frames it */
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

    /** True for a POST chat path this router should handle (canonical or one trailing slash). */
    public function matches(string $path): bool
    {
        return AiSurfacePath::chat($path) !== null;
    }

    /** True for any AI-API path (chat or recon) — the front controller uses this to strip X-Powered-By
     *  AND to exclude the AI surface from the general raw-capture store. Trailing-slash tolerant. */
    public static function isAiSurface(string $path): bool
    {
        return AiSurfacePath::isAiSurface($path);
    }

    /** Pick the dialect for the canonical chat path and delegate to the handler. */
    public function handle(RequestContext $ctx, string $clientIp): void
    {
        $canonical = AiSurfacePath::chat($ctx->path);
        $dialect = $canonical !== null ? ($this->dialects[$canonical] ?? null) : null;
        if ($dialect === null) {
            return; // not a chat path; callers guard with matches() first
        }

        $this->handler->serve($dialect, $ctx, $clientIp);
    }
}

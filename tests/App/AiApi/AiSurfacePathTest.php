<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\AiSurfacePath;
use PHPUnit\Framework\TestCase;

/**
 * The one canonical AI-route classifier. It accepts an exact route or that route with ONE trailing
 * slash and returns the canonical no-slash form; it never percent-decodes, case-folds or admits
 * doubled slashes — closing the slash-variant hole that could let a served AI path skip raw-capture
 * exclusion.
 */
final class AiSurfacePathTest extends TestCase
{
    public function test_canonical_exact_routes(): void
    {
        self::assertSame('/v1/messages', AiSurfacePath::canonical('/v1/messages'));
        self::assertSame('/api/chat', AiSurfacePath::canonical('/api/chat'));
        self::assertSame('/api/show', AiSurfacePath::canonical('/api/show'));
    }

    public function test_one_trailing_slash_is_canonicalised(): void
    {
        self::assertSame('/v1/messages', AiSurfacePath::canonical('/v1/messages/'));
        self::assertSame('/api/chat', AiSurfacePath::canonical('/api/chat/'));
    }

    public function test_rejects_doubled_slash_case_and_encoding(): void
    {
        self::assertNull(AiSurfacePath::canonical('/api/chat//'));
        self::assertNull(AiSurfacePath::canonical('/v1//messages'));
        self::assertNull(AiSurfacePath::canonical('/API/chat'));
        self::assertNull(AiSurfacePath::canonical('/api/chat%2f'));
        self::assertNull(AiSurfacePath::canonical('/not/a/route'));
    }

    public function test_chat_only_matches_chat_routes(): void
    {
        self::assertSame('/api/chat', AiSurfacePath::chat('/api/chat/'));
        self::assertNull(AiSurfacePath::chat('/api/show'));     // recon, not chat
        self::assertNull(AiSurfacePath::chat('/v1/models'));
    }

    public function test_is_ai_surface_covers_chat_and_recon_trailing_slash_tolerant(): void
    {
        self::assertTrue(AiSurfacePath::isAiSurface('/v1/models'));
        self::assertTrue(AiSurfacePath::isAiSurface('/api/tags/'));
        self::assertTrue(AiSurfacePath::isAiSurface('/v1/chat/completions'));
        self::assertFalse(AiSurfacePath::isAiSurface('/wp-login.php'));
    }
}

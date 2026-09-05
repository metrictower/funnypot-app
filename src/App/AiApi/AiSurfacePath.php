<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

/**
 * One canonical classifier for the closed AI-API route list, driving routing, X-Powered-By suppression
 * and general-raw-capture exclusion from a single decision. It accepts only an exact known route or that
 * route with ONE trailing slash, and returns the canonical no-slash form. It never percent-decodes,
 * case-folds, collapses dot segments or admits multiple slashes, so `/v1/messages/` routes like
 * `/v1/messages` while `/API/chat`, `/v1//messages`, `/api/chat//` and `/api/chat%2f` do not — closing
 * the slash-variant hole where a served AI path could otherwise slip past the raw-capture exclusion.
 */
final class AiSurfacePath
{
    /** POST chat endpoints served by the app when the feature is on. */
    public const CHAT = ['/api/chat', '/api/generate', '/v1/chat/completions', '/v1/messages'];

    /** GET recon endpoints (core's job); part of the AI footprint for header/capture policy. */
    public const RECON = ['/api/tags', '/api/version', '/api/ps', '/api/show', '/v1/models'];

    /** The canonical no-slash route for $path, or null when $path is not a known AI route. */
    public static function canonical(string $path): ?string
    {
        $all = array_merge(self::CHAT, self::RECON);
        if (in_array($path, $all, true)) {
            return $path;
        }
        // Exactly one trailing slash is allowed; a doubled slash is not.
        if ($path !== '' && substr($path, -1) === '/' && substr($path, -2) !== '//') {
            $trimmed = substr($path, 0, -1);
            if (in_array($trimmed, $all, true)) {
                return $trimmed;
            }
        }

        return null;
    }

    /** The canonical chat route for $path (canonical or one trailing slash), or null. */
    public static function chat(string $path): ?string
    {
        $canonical = self::canonical($path);

        return ($canonical !== null && in_array($canonical, self::CHAT, true)) ? $canonical : null;
    }

    /** True for any AI-API path (chat or recon), trailing-slash tolerant. */
    public static function isAiSurface(string $path): bool
    {
        return self::canonical($path) !== null;
    }
}

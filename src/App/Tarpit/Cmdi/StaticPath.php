<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * A path that names a static asset. Serving a shell page there would answer a `.js` or `.png`
 * request with HTML, which is a tell, so both console rewriters leave such answers alone.
 */
final class StaticPath
{
    private const EXTENSIONS = ['js', 'css', 'json', 'xml', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'map'];

    public static function is(string $path): bool
    {
        $base = strtolower(basename($path));
        $dot = strrpos($base, '.');

        return $dot !== false && in_array(substr($base, $dot + 1), self::EXTENSIONS, true);
    }
}

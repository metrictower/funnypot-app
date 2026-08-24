<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/** Total, pure path canonicalizer. The single source of truth for both listing and validation. */
final class PathCanon
{
    public static function canonical(string $path): string
    {
        $out = [];
        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($out); // can't escape root
                continue;
            }
            $out[] = $seg;
        }

        return '/' . implode('/', $out);
    }

    /** @return string[] */
    public static function segments(string $path): array
    {
        $c = self::canonical($path);

        return $c === '/' ? [] : explode('/', substr($c, 1));
    }

    public static function parent(string $path): string
    {
        $segs = self::segments($path);
        array_pop($segs);

        return $segs === [] ? '/' : '/' . implode('/', $segs);
    }

    public static function basename(string $path): string
    {
        $segs = self::segments($path);

        return $segs === [] ? '/' : (string) end($segs);
    }
}

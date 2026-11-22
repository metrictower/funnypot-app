<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

/**
 * A stream wrapper that records every open and every url_stat of a URL scheme and refuses it, so a test
 * sees even the quiet calls (file_exists on a URL) that raise nothing. install() replaces the http,
 * https, ftp and ftps wrappers PHP has; restore() puts them back.
 */
final class RecordingWrapper
{
    /** @var list<string> */
    public static array $log = [];

    /** @var list<string> */
    private static array $replaced = [];

    /** @var resource|null */
    public $context;

    public static function install(): void
    {
        self::$log = [];
        self::$replaced = [];
        foreach (['http', 'https', 'ftp', 'ftps'] as $scheme) {
            if (in_array($scheme, stream_get_wrappers(), true)) {
                stream_wrapper_unregister($scheme);
                self::$replaced[] = $scheme;
            }
            stream_wrapper_register($scheme, self::class);
        }
    }

    public static function restore(): void
    {
        foreach (['http', 'https', 'ftp', 'ftps'] as $scheme) {
            @stream_wrapper_unregister($scheme);
            if (in_array($scheme, self::$replaced, true)) {
                stream_wrapper_restore($scheme);
            }
        }
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
    {
        self::$log[] = 'open ' . $path;

        return false;
    }

    public function url_stat(string $path, int $flags): array|false
    {
        self::$log[] = 'stat ' . $path;

        return false;
    }

    public function dir_opendir(string $path, int $options): bool
    {
        self::$log[] = 'opendir ' . $path;

        return false;
    }
}

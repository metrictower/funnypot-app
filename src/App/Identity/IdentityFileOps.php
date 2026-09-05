<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * The narrow filesystem/process seam every identity component goes through. Production is this class
 * unchanged (native PHP calls); tests extend it to force a short write, a failed flush/fsync/link/
 * unlink, changed metadata, a fake euid or a crash at a chosen boundary. Nothing here interprets
 * results — the callers own every validation.
 *
 * @internal
 */
class IdentityFileOps
{
    public function euid(): int
    {
        return posix_geteuid();
    }

    /** @return array<string,mixed>|null */
    public function passwdByName(string $name): ?array
    {
        $r = posix_getpwnam($name);

        return is_array($r) ? $r : null;
    }

    /** @return array<string,mixed>|null */
    public function passwdByUid(int $uid): ?array
    {
        $r = posix_getpwuid($uid);

        return is_array($r) ? $r : null;
    }

    /** @return array<string,mixed>|null */
    public function groupByName(string $name): ?array
    {
        $r = posix_getgrnam($name);

        return is_array($r) ? $r : null;
    }

    /** @return array<string,mixed>|null */
    public function groupByGid(int $gid): ?array
    {
        $r = posix_getgrgid($gid);

        return is_array($r) ? $r : null;
    }

    public function supportsFsync(): bool
    {
        return function_exists('fsync');
    }

    /** @return array<string,int>|false */
    public function lstat(string $path)
    {
        clearstatcache(true, $path);

        return @lstat($path);
    }

    /**
     * @param resource $h
     * @return array<string,int>|false
     */
    public function fstat($h)
    {
        return @fstat($h);
    }

    /**
     * O_CREAT|O_EXCL — fails if the name exists, never follows a symlink. Created 0600 regardless
     * of the process umask.
     *
     * @return resource|false
     */
    public function openExclusive(string $path)
    {
        $old = umask(0077);
        try {
            return @fopen($path, 'xb');
        } finally {
            umask($old);
        }
    }

    /** @return resource|false */
    public function openRead(string $path)
    {
        return @fopen($path, 'rb');
    }

    /** A directory handle, for directory fsync after a link/unlink. @return resource|false */
    public function openDir(string $path)
    {
        return @fopen($path, 'r');
    }

    /** @param resource $h @return int|false */
    public function write($h, string $bytes)
    {
        return @fwrite($h, $bytes);
    }

    /** @param resource $h */
    public function flush($h): bool
    {
        return @fflush($h);
    }

    /** @param resource $h */
    public function fsync($h): bool
    {
        return @fsync($h);
    }

    /** @param resource $h @return string|false up to $max bytes (callers detect oversize by asking for max+1) */
    public function readAll($h, int $max)
    {
        $out = '';
        while (strlen($out) < $max) {
            $chunk = @fread($h, min(8192, $max - strlen($out)));
            if ($chunk === false) {
                return false;
            }
            if ($chunk === '') {
                break;
            }
            $out .= $chunk;
        }

        return $out;
    }

    /** @param resource $h */
    public function flock($h, int $op): bool
    {
        return @flock($h, $op);
    }

    /** @param resource $h */
    public function close($h): void
    {
        if (is_resource($h)) {
            @fclose($h);
        }
    }

    public function link(string $target, string $link): bool
    {
        return @link($target, $link);
    }

    public function unlink(string $path): bool
    {
        return @unlink($path);
    }

    public function rename(string $from, string $to): bool
    {
        return @rename($from, $to);
    }

    public function symlink(string $target, string $link): bool
    {
        return @symlink($target, $link);
    }

    /** @return string|false */
    public function readlink(string $path)
    {
        return @readlink($path);
    }

    /** @return string|false */
    public function realpath(string $path)
    {
        return @realpath($path);
    }

    public function mkdir(string $path, int $mode): bool
    {
        $old = umask(0);
        try {
            return @mkdir($path, $mode);
        } finally {
            umask($old);
        }
    }

    public function chmod(string $path, int $mode): bool
    {
        return @chmod($path, $mode);
    }

    public function chgrp(string $path, int $gid): bool
    {
        return @chgrp($path, $gid);
    }

    /** @return list<string>|false */
    public function scandir(string $path)
    {
        return @scandir($path);
    }

    public function randomHex(int $bytes): string
    {
        return bin2hex(random_bytes($bytes));
    }

    public function randomBytes(int $n): string
    {
        return random_bytes($n);
    }

    public function sleepMs(int $ms): void
    {
        usleep($ms * 1000);
    }

    public function time(): int
    {
        return time();
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/** A generated filesystem node. PHP 8.0 has no readonly props — public typed props set once at build. */
final class Node
{
    public function __construct(
        public string $name,
        public string $type,     // 'dir' | 'file' | 'link'
        public int $uid,
        public int $gid,
        public int $size,
        public int $mode,
        public int $mtime,
        public ?string $target = null
    ) {
    }

    public function isDir(): bool
    {
        return $this->type === 'dir';
    }

    public function isFile(): bool
    {
        return $this->type === 'file';
    }

    public function isLink(): bool
    {
        return $this->type === 'link';
    }
}

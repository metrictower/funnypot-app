<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * The account the fake webshell runs as. One object feeds the panel header, the landing transcript
 * and every command answer, so `id`, `whoami`, `env`, passwd and the landing can never disagree.
 *
 * The pool is deliberately tiny: www-data (the php-fpm worker) or root inside the same locked-down
 * container. Both match the passwd/group files core already serves on its LFI answers, so every
 * surface tells the same story. Root stays a dead end: no capabilities, read-only rootfs, no egress.
 */
final class FootholdIdentity
{
    public const WWW_DATA = 'www-data';
    public const ROOT = 'root';

    /** Roughly one source in four lands on root: a first byte below 64 out of 256. */
    private const ROOT_THRESHOLD = 64;

    private function __construct(
        public readonly string $name,
        public readonly int $uid,
        public readonly string $home,
        public readonly string $shell,
    ) {
    }

    public static function www(): self
    {
        return new self(self::WWW_DATA, 33, '/var/www', '/usr/sbin/nologin');
    }

    public static function root(): self
    {
        return new self(self::ROOT, 0, '/root', '/bin/bash');
    }

    /**
     * The identity for an apparent source: a keyed hash of the IP, so it is stable for that source
     * across requests and restarts but cannot be predicted without the private key.
     */
    public static function forSource(string $identityKey, string $clientIp): self
    {
        $mac = hash_hmac('sha256', 'identity|' . $clientIp, $identityKey, true);

        return ord($mac[0]) < self::ROOT_THRESHOLD ? self::root() : self::www();
    }

    /** Honours an operator pin (`www-data` / `root`); anything else falls back to the per-source draw. */
    public static function resolve(string $pin, string $identityKey, string $clientIp): self
    {
        return match ($pin) {
            self::WWW_DATA => self::www(),
            self::ROOT => self::root(),
            default => self::forSource($identityKey, $clientIp),
        };
    }

    public function isRoot(): bool
    {
        return $this->uid === 0;
    }

    /** What busybox `id` prints. The group file lists no members, so there are no extra groups. */
    public function idLine(): string
    {
        return "uid={$this->uid}({$this->name}) gid={$this->uid}({$this->name}) groups={$this->uid}({$this->name})";
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * Proof of HOW a source file was opened, handed downstream with its still-open handle so a consumer
 * never reopens a path. PHP has no O_NOFOLLOW, so `direct-nofollow/v1` is defined in PHP-feasible
 * terms: every component beneath a trusted anchor is `lstat`ed (a directory, not a symlink, no
 * group/other write, an accepted owner), the final name is `lstat`ed (a regular file, not a symlink,
 * link count one), then `fopen('rb')` + `fstat`, and the two stats must agree on dev/ino/mode/uid/
 * gid/nlink; the bytes are read and `fstat` must agree again. A swapped-in symlink to another inode
 * is caught by the equality; one resolving to the SAME inode is the same file. A consumer proves the
 * chain by `fstat`ing the handle it received and calling {@see matches()} — an attestation that is
 * only recorded, never compared, is decorative.
 *
 * `letsencrypt-managed-chain/v1` is the single exception: the certbot live pair is two symlinks whose
 * targets must be exactly `../../archive/<same domain>/<name><same revision>.pem`; the archive finals
 * are then opened by the direct rule above.
 */
final class SourceOpenAttestation
{
    public const DIRECT_NOFOLLOW = 'direct-nofollow/v1';
    public const LETSENCRYPT_MANAGED_CHAIN = 'letsencrypt-managed-chain/v1';

    public function __construct(
        public readonly string $id,
        public readonly int $dev,
        public readonly int $ino,
        public readonly int $mode,
        public readonly int $uid,
        public readonly int $gid,
        public readonly int $nlink,
        public readonly int $size,
    ) {
        if ($id !== self::DIRECT_NOFOLLOW && $id !== self::LETSENCRYPT_MANAGED_CHAIN) {
            throw new \InvalidArgumentException('unknown attestation id');
        }
    }

    /** @param array<string,int> $st an lstat()/fstat() array */
    public static function fromStat(string $id, array $st): self
    {
        return new self($id, (int) $st['dev'], (int) $st['ino'], (int) $st['mode'], (int) $st['uid'], (int) $st['gid'], (int) $st['nlink'], (int) $st['size']);
    }

    /** The identity facts a later fstat must reproduce. @param array<string,int> $st */
    public function matches(array $st): bool
    {
        return (int) $st['dev'] === $this->dev
            && (int) $st['ino'] === $this->ino
            && (int) $st['mode'] === $this->mode
            && (int) $st['uid'] === $this->uid
            && (int) $st['gid'] === $this->gid
            && (int) $st['nlink'] === $this->nlink;
    }

    public function isRegularFile(): bool
    {
        return ($this->mode & 0170000) === 0100000;
    }

    /** @return array{id:string,dev:int,ino:int,mode:int,uid:int,gid:int,nlink:int,size:int} */
    public function facts(): array
    {
        return [
            'id' => $this->id,
            'dev' => $this->dev,
            'ino' => $this->ino,
            'mode' => $this->mode,
            'uid' => $this->uid,
            'gid' => $this->gid,
            'nlink' => $this->nlink,
            'size' => $this->size,
        ];
    }
}

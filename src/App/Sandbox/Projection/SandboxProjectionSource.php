<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

final class SandboxProjectionSource
{
    /** @param array<string,string> $envelope */
    public function __construct(
        public readonly string $sourceClass,
        public readonly string $attestationId,
        public readonly int $dev,
        public readonly int $ino,
        public readonly int $mode,
        public readonly int $uid,
        public readonly int $gid,
        public readonly int $nlink,
        public readonly int $byteLength,
        public readonly string $contentSha256,
        public readonly array $envelope,
    ) {
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'source_class' => $this->sourceClass,
            'attestation_id' => $this->attestationId,
            'device' => $this->dev,
            'inode' => $this->ino,
            'mode' => $this->mode,
            'uid' => $this->uid,
            'gid' => $this->gid,
            'link_count' => $this->nlink,
            'byte_length' => $this->byteLength,
            'content_sha256' => $this->contentSha256,
            'envelope' => $this->envelope,
        ];
    }
}

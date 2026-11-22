<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * What a fake fetch got back: an HTTP answer (status, content type, a body excerpt of at most 2 KB), or
 * a protocol failure (an SSH banner where HTTP was expected, an empty reply, a reset), each with the
 * error text a fetch worker would log. It is shown to the visitor as escaped text, never sent as a
 * real response.
 */
final class Reply
{
    public const MAX_EXCERPT = 2048;
    public const PROTOCOLS = ['http', 'banner', 'empty', 'conn_reset'];

    private function __construct(
        public readonly string $protocol,
        public readonly ?int $status,
        public readonly string $contentType,
        public readonly string $body,
        public readonly ?string $error,
    ) {
    }

    public static function http(int $status, string $contentType, string $body): self
    {
        return new self('http', $status, $contentType, substr($body, 0, self::MAX_EXCERPT), null);
    }

    public static function failure(string $protocol, string $error, string $excerpt = ''): self
    {
        if (!in_array($protocol, self::PROTOCOLS, true) || $protocol === 'http') {
            throw new \LogicException('failure protocol outside the closed set');
        }

        return new self($protocol, null, '', substr($excerpt, 0, self::MAX_EXCERPT), $error);
    }

    public function ok(): bool
    {
        return $this->protocol === 'http';
    }
}

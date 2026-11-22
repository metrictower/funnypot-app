<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * Where one fetch went, decided before any byte could leave: the egress class and the outcome kind,
 * plus the node and port it reached when it reached one.
 */
final class Resolution
{
    public const OUTCOMES = ['open', 'refused', 'timeout', 'nxdomain', 'dns_transient', 'proxy_denied', 'code_host', 'unroutable', 'no_route', 'loopback', 'metadata', 'validation'];

    public function __construct(
        public readonly string $egress,
        public readonly string $outcome,
        public readonly ?NetNode $node,
        public readonly int $port,
    ) {
        if (!in_array($outcome, self::OUTCOMES, true)) {
            throw new \LogicException('outcome outside the closed set');
        }
    }

    public function nodeKind(): string
    {
        return $this->node?->kind ?? '';
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The read-only persona view app-owned listener factories consume: the stable base family and the
 * non-secret variant token, plus the effective service ids. It is deployment-global and identical for
 * every client and request, so it never carries a client IP, date or scan-order input. A failed or
 * pending desired profile never produces one — only a committed effective set does.
 */
final class EffectiveServiceProfile
{
    /** @param list<string> $serviceIds */
    public function __construct(
        public readonly string $baseFamily,
        public readonly string $variantId,
        public readonly array $serviceIds,
    ) {
    }

    public function baseFamily(): string
    {
        return $this->baseFamily;
    }

    public function variantId(): string
    {
        return $this->variantId;
    }

    public function hasService(string $id): bool
    {
        return in_array($id, $this->serviceIds, true);
    }
}

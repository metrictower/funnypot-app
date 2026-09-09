<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/** A rendered MANIFEST.sha256 body and its length (FP-0272 §6.4). */
final class RenderedAttritionManifest
{
    public function __construct(
        public readonly string $body,
        public readonly int $length,
    ) {
    }
}

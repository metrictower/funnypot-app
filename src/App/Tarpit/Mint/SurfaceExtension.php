<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * What a sibling surface adds to the account: extra token scopes with their labels, extra forms and
 * where they post, extra pages a redirect may name, nav items and API reference rows. The account
 * surface reads it but never depends on the sibling's classes. none() adds nothing, and with it every
 * page and answer is exactly what the account surface serves on its own.
 */
final class SurfaceExtension
{
    /**
     * @param array<string,string> $scopes scope => label
     * @param array<string,string> $forms form id => action path (`{id}` is the object)
     * @param list<string> $locations patterns of extra redirect targets
     * @param list<array{0:string,1:string}> $nav [href, label] shown to a signed-in visitor
     * @param list<array{0:string,1:string,2:string,3:string}> $ops [method, path, description, scope] API reference rows
     */
    public function __construct(
        public readonly array $scopes = [],
        public readonly array $forms = [],
        public readonly array $locations = [],
        public readonly array $nav = [],
        public readonly array $ops = [],
    ) {
    }

    public static function none(): self
    {
        return new self();
    }

    public function isEmpty(): bool
    {
        return $this->scopes === [] && $this->forms === [] && $this->locations === [] && $this->nav === [] && $this->ops === [];
    }
}

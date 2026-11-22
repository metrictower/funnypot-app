<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\Core\Support\PersonaIdentity;

/**
 * The deploy persona as the account surface shows it: the company, its organisation slug (the one
 * `{org}` the surface answers for), the token prefix, and the persona's existing members (the admin
 * plus the published WordPress authors), who sign in through the company's SSO.
 */
final class MintPersona
{
    /** @param array<string,string> $members login => display name */
    private function __construct(
        public readonly string $company,
        public readonly string $slug,
        public readonly string $domain,
        public readonly string $prefix,
        public readonly array $members,
    ) {
    }

    public static function fromSeed(int $seed): self
    {
        $p = PersonaIdentity::fromSeed($seed);
        $slug = (string) $p->field('company.slug');
        $members = [(string) $p->field('user.admin.username') => ''];
        for ($i = 1; $i <= 5; $i++) {
            $login = (string) $p->field("wordpress.user.{$i}.slug");
            if ($login !== '' && !isset($members[$login])) {
                $members[$login] = (string) $p->field("wordpress.user.{$i}.name");
            }
        }

        return new self(
            (string) $p->field('company.name'),
            $slug,
            (string) $p->field('company.domain'),
            TokenCodec::prefixFor($slug),
            $members,
        );
    }

    public function isMember(string $login): bool
    {
        foreach (array_keys($this->members) as $m) {
            if (strcasecmp((string) $m, $login) === 0) {
                return true;
            }
        }

        return false;
    }

    /** The member's canonical login when $login names one (case-insensitively), else null. */
    public function member(string $login): ?string
    {
        foreach (array_keys($this->members) as $m) {
            if (strcasecmp((string) $m, $login) === 0) {
                return (string) $m;
            }
        }

        return null;
    }
}

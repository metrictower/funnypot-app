<?php
declare(strict_types=1);
namespace Funnypot\App\Render;

use Funnypot\Support\Fake\FakePeople;
use Funnypot\Support\PersonaIdentity;

/**
 * The visual half of a host's fake identity — the part PersonaIdentity (credential-shaped, no visual
 * fields) does not carry. Every value is a pure function of the seed, so a host renders one stable
 * look and coherent company across all its pages. The class-name prefix, palette and pick() carry
 * real per-seed entropy so a public, fixed skin does not collapse the whole fleet to one CSS hash —
 * pick() specifically lets a skin vary its class-name vocabulary and DOM structure, not just leaf
 * colors/prefixes, so the entropy survives a scanner that normalizes those away.
 */
final class VisualPersona
{
    private function __construct(
        private string $classPrefix,
        /** @var array{bg:string,fg:string,accent:string,muted:string,border:string} */
        private array $palette,
        private PersonaIdentity $identity,
        private int $seed,
    ) {
    }

    public static function fromSeed(int $seed): self
    {
        $h = static fn (string $f): string => hash('sha256', $seed . '|visual|' . $f);
        $hue = static fn (string $f): string => '#' . substr($h($f), 0, 6);
        // Accent is vivid; bg/border are near-neutral (high bytes) so text stays legible. These are
        // seed-derived, not fixed, which is the anti-fleet-fingerprint property.
        $palette = [
            'bg' => '#' . self::light($h('bg')),
            'fg' => '#1b1e21',
            'accent' => $hue('accent'),
            'muted' => '#6b7280',
            'border' => '#' . self::light($h('border')),
        ];
        return new self('fp-' . substr($h('prefix'), 0, 4), $palette, PersonaIdentity::fromSeed($seed), $seed);
    }

    /** Map a hash to a light hex (each channel biased high) so backgrounds/borders read as chrome. */
    private static function light(string $hex): string
    {
        $out = '';
        for ($i = 0; $i < 3; $i++) {
            $b = hexdec(substr($hex, $i * 2, 2)) % 64 + 190; // 190-253
            $out .= str_pad(dechex($b), 2, '0', STR_PAD_LEFT);
        }
        return $out;
    }

    /** The persona seed — so a skin can build a coherent ServerProfile (same host identity) from it. */
    public function seed(): int { return $this->seed; }

    public function classPrefix(): string { return $this->classPrefix; }
    /** @return array{bg:string,fg:string,accent:string,muted:string,border:string} */
    public function palette(): array { return $this->palette; }
    public function company(): string { return $this->identity->field('company.name') ?? 'Internal'; }
    public function domain(): string { return $this->identity->field('company.domain') ?? 'example.internal'; }
    public function adminEmail(): string { return $this->identity->field('user.admin.email') ?? 'admin@example.internal'; }

    public function dbHost(): string { return $this->identity->field('db.host') ?? 'localhost'; }
    public function dbName(): string { return $this->identity->field('db.name') ?? 'appdb'; }
    public function dbUser(): string { return $this->identity->field('db.user') ?? 'appuser'; }
    public function dbPassword(): string { return $this->identity->field('db.password') ?? 'changeme'; }

    public function fakeToken(string $salt): string
    {
        return 'tok_' . substr(hash('sha256', $this->seed . '|token|' . $salt), 0, 12);
    }

    /**
     * Deterministically choose one of $options, keyed by $salt so unrelated structural choices (e.g.
     * a header class word vs a nav markup shape) don't move in lockstep with each other or with
     * palette()/classPrefix(). Same seed+salt always picks the same option — invariant 3: byte-
     * identical per deployment, varying only across deployments. This is the structural analog of
     * palette()/classPrefix(): a skin uses it to vary its class-name vocabulary and DOM shape per
     * seed, not just its leaf colors/prefix, so a value-normalizing scanner can't collapse the whole
     * fleet to one skeleton.
     *
     * @param non-empty-list<string> $options
     */
    public function pick(string $salt, array $options): string
    {
        $idx = hexdec(substr(hash('sha256', $this->seed . '|pick|' . $salt), 0, 8)) % count($options);
        return $options[$idx];
    }

    public function awsKey(): string
    {
        $key = $this->identity->field('cloud.aws.accessKeyId');
        if ($key !== null) {
            return $key;
        }
        return 'AKIA' . strtoupper(substr(hash('sha256', $this->seed . '|awskey|'), 0, 16));
    }

    /**
     * A deterministic fake person for $key (e.g. a table row id), scoped to this persona's seed.
     *
     * @return array{first:string,last:string,full:string,userName:string}
     */
    public function person(string $key): array
    {
        return FakePeople::person($this->seed, $key);
    }

    /** person($key)'s email at THIS persona's company domain, so a fake user table never
     *  contradicts the company/domain shown elsewhere on the same host. */
    public function personEmail(string $key): string
    {
        return FakePeople::email($this->person($key), $this->domain());
    }

    public function personJobTitle(string $key): string
    {
        return FakePeople::jobTitle($this->seed, $key);
    }

    public function personCity(string $key): string
    {
        return FakePeople::city($this->seed, $key);
    }
}

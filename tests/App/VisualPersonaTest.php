<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

final class VisualPersonaTest extends TestCase
{
    public function test_deterministic_per_seed(): void
    {
        $a = VisualPersona::fromSeed(123);
        $b = VisualPersona::fromSeed(123);
        self::assertSame($a->classPrefix(), $b->classPrefix());
        self::assertSame($a->palette(), $b->palette());
        self::assertSame($a->fakeToken('cell00'), $b->fakeToken('cell00'));
    }

    public function test_different_seeds_diverge(): void
    {
        self::assertNotSame(VisualPersona::fromSeed(1)->classPrefix(), VisualPersona::fromSeed(2)->classPrefix());
        self::assertNotSame(VisualPersona::fromSeed(1)->palette()['accent'], VisualPersona::fromSeed(2)->palette()['accent']);
    }

    public function test_palette_is_hex_and_token_shape(): void
    {
        $p = VisualPersona::fromSeed(7);
        foreach ($p->palette() as $c) {
            self::assertMatchesRegularExpression('/^#[0-9a-f]{6}$/', $c);
        }
        self::assertMatchesRegularExpression('/^tok_[0-9a-f]{12}$/', $p->fakeToken('x'));
        self::assertMatchesRegularExpression('/^fp-[0-9a-f]{4}$/', $p->classPrefix());
    }

    /** The db.* accessors delegate to the wrapped PersonaIdentity — non-empty and, since the
     *  identity is a pure function of the seed, byte-identical across two instances of the same seed. */
    public function test_db_accessors_are_nonempty_and_deterministic_per_seed(): void
    {
        $a = VisualPersona::fromSeed(123);
        $b = VisualPersona::fromSeed(123);

        self::assertNotSame('', $a->dbHost());
        self::assertNotSame('', $a->dbName());
        self::assertNotSame('', $a->dbUser());
        self::assertNotSame('', $a->dbPassword());

        self::assertSame($a->dbHost(), $b->dbHost());
        self::assertSame($a->dbName(), $b->dbName());
        self::assertSame($a->dbUser(), $b->dbUser());
        self::assertSame($a->dbPassword(), $b->dbPassword());
    }

    public function test_db_accessors_diverge_across_seeds(): void
    {
        $x = VisualPersona::fromSeed(1);
        $y = VisualPersona::fromSeed(2);

        // Not every field is guaranteed to diverge for any two seeds (small dictionaries), but the
        // high-entropy password must, and it's enough to prove the accessor isn't a fixed constant.
        self::assertNotSame($x->dbPassword(), $y->dbPassword());
    }

    public function test_person_is_deterministic_per_seed_and_key(): void
    {
        $a = VisualPersona::fromSeed(123);
        $b = VisualPersona::fromSeed(123);
        self::assertSame($a->person('row-0'), $b->person('row-0'));
    }

    public function test_person_diverges_by_key(): void
    {
        $p = VisualPersona::fromSeed(123);
        self::assertNotSame($p->person('row-0'), $p->person('row-1'));
    }

    /** Coherence: personEmail must use THIS persona's company domain, not a fixed placeholder
     *  like example.com — a fake user table must never contradict the company shown elsewhere. */
    public function test_person_email_uses_persona_domain_not_example_com(): void
    {
        $p = VisualPersona::fromSeed(123);
        $domain = $p->domain();

        self::assertNotSame('example.com', $domain);
        self::assertStringEndsWith('@' . $domain, $p->personEmail('row-0'));
        self::assertSame($p->person('row-0')['userName'] . '@' . $domain, $p->personEmail('row-0'));
    }

    public function test_person_email_is_deterministic(): void
    {
        $a = VisualPersona::fromSeed(456);
        $b = VisualPersona::fromSeed(456);
        self::assertSame($a->personEmail('row-2'), $b->personEmail('row-2'));
    }

    public function test_person_job_title_and_city_are_deterministic_and_nonempty(): void
    {
        $a = VisualPersona::fromSeed(9);
        $b = VisualPersona::fromSeed(9);
        self::assertSame($a->personJobTitle('row-0'), $b->personJobTitle('row-0'));
        self::assertSame($a->personCity('row-0'), $b->personCity('row-0'));
        self::assertNotSame('', $a->personJobTitle('row-0'));
        self::assertNotSame('', $a->personCity('row-0'));
    }
}

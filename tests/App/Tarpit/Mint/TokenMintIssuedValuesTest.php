<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\CsrfCodec;
use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Mint\MintContext;
use Funnypot\App\Tarpit\Mint\MintKeys;
use Funnypot\App\Tarpit\Mint\MintPersona;
use Funnypot\App\Tarpit\Mint\MintState;
use Funnypot\App\Tarpit\Mint\TokenCodec;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * Every random value the surface issues, sampled under fixed keys through the real issuing code and sent
 * back the way its pages and API docs say, leaves the engine quiet: no match and no attack class. Form
 * tokens, refresh tokens, codes, client ids and secrets, recovery codes and request ids go as form fields
 * (followed by another field, and last); access tokens and JWTs as `?access_token`, a Bearer header and
 * X-Api-Key; client and request ids also as query parameters; public ids as path segments; the session
 * cookie as the Cookie header. Values travel in small batches, and a flagged batch is halved down to the
 * single value that trips the engine.
 */
final class TokenMintIssuedValuesTest extends TestCase
{
    private const NOW = 1763800000;

    private Honeypot $hp;

    protected function setUp(): void
    {
        $this->hp = MintCorpus::engine();
    }

    private static function context(int $seed): MintContext
    {
        return new MintContext(
            new MintKeys(hash('sha256', 'issued-values|' . $seed, true)),
            MintPersona::fromSeed($seed),
            new TokenMintStore(sys_get_temp_dir() . '/unused-' . $seed . '.sqlite'),
            static fn (): int => self::NOW,
        );
    }

    /** @return array{0:MintState,1:int,2:string} a state holding one account, its position and kref */
    private static function account(int $seed): array
    {
        $s = MintState::fresh(self::NOW, substr(hash('sha256', 'epoch|' . $seed), 0, 16));
        $pos = $s->addAccount('artex' . $seed, 'artex' . $seed . '@example.com', 'pw', self::NOW);

        return [$s, $pos, substr(hash('sha256', 'kref|' . $seed, true), 0, 16)];
    }

    /**
     * @return array<string,list<string>> value kind => issued values
     */
    private static function sample(): array
    {
        $out = ['recovery code' => []];
        for ($seed = 1; $seed <= 6; $seed++) {
            $c = self::context($seed);
            [$s, $pos, $kref] = self::account($seed);
            for ($i = 0; $i < 500; $i++) {
                $out['csrf'][] = $c->csrfToken(hash('sha256', 'sid|' . $seed . '|' . $i, true), 'token_create', $i % 7, self::NOW - 37 * $i);
                $out['client id'][] = $c->clientId($kref, $s, $seed, $i);
                $out['client secret'][] = $c->clientSecret($kref, $s, $seed, $i, $i % 3);
                $out['code'][] = $c->oauthCode($kref, $s, $seed, $i);
                $out['request id'][] = $c->requestId($kref, $s, $i);
                $out['public id'][] = $c->appPublicId($kref, $s, $seed, $i);
                $out['refresh token'][] = $c->refreshToken($kref, $s, $pos, $i);
            }
            for ($i = 0; $i < 500; $i++) {
                if ($i % MintState::MAX_TOKENS === 0) {
                    $s->d['a'][$pos]['k'] = [];
                }
                [$tpos, $pat] = $c->addToken($s, $pos, $kref, $i % 2 === 0 ? 'pat' : 'oat', '', ['read:user'], 0, null, self::NOW);
                $out['access token'][] = $pat;
                $out['public id'][] = (string) $s->d['a'][$pos]['k'][$tpos]['id'];
                $out['jwt'][] = $c->loginJwt(bin2hex(substr($kref, 0, 8)), $s, $pos, $i, self::NOW + $i);
                $out['session cookie'][] = $c->startSession($s, $pos, $kref, self::NOW);
                if ($i % 10 === 0) {
                    array_push($out['recovery code'], ...$c->recoveryCodes($kref, $s, $seed, $i));
                }
            }
        }

        return $out;
    }

    private static function fields(array $values, string $name, bool $last): string
    {
        $pairs = array_map(static fn (string $v): string => $name . '=' . $v, $values);

        return implode('&', $pairs) . ($last ? '' : '&note=x');
    }

    /** @return array<string,list<callable(list<string>):RequestContext>> value kind => the ways it travels */
    private static function travels(): array
    {
        $form = static fn (string $name): array => [
            static fn (array $vs): RequestContext => new RequestContext('POST', '/login/oauth/access_token', '', MintCorpus::F, self::fields($vs, $name, false)),
            static fn (array $vs): RequestContext => new RequestContext('POST', '/login/oauth/access_token', '', MintCorpus::F, 'grant_type=x&' . self::fields($vs, $name, true)),
        ];
        $bearer = [
            static fn (array $vs): RequestContext => new RequestContext('GET', '/api/v2/user', self::fields($vs, 'access_token', true), []),
            static fn (array $vs): RequestContext => new RequestContext('GET', '/api/v2/user', '', ['Authorization' => 'Bearer ' . implode(' ', $vs)]),
            static fn (array $vs): RequestContext => new RequestContext('GET', '/api/v2/user', '', ['X-Api-Key' => implode(' ', $vs)]),
        ];
        $query = static fn (string $name): callable => static fn (array $vs): RequestContext => new RequestContext('GET', '/login/oauth/authorize', self::fields($vs, $name, false), []);

        return [
            'csrf' => $form('csrf_token'),
            'refresh token' => $form('refresh_token'),
            'code' => $form('code'),
            'client secret' => $form('client_secret'),
            'recovery code' => $form('recovery_code'),
            'client id' => [...$form('client_id'), $query('client_id')],
            'request id' => [...$form('authorization_request'), $query('authorization_request')],
            'access token' => $bearer,
            'jwt' => $bearer,
            'public id' => [
                static fn (array $vs): RequestContext => new RequestContext('POST', '/settings/tokens/' . implode('/', $vs) . '/delete', '', MintCorpus::F, 'csrf_token=x'),
                static fn (array $vs): RequestContext => new RequestContext('GET', '/settings/applications/' . implode('/', $vs), '', []),
            ],
            'session cookie' => [
                static fn (array $vs): RequestContext => new RequestContext('GET', '/settings/tokens', '', ['Cookie' => implode('; ', array_map(static fn (string $v): string => 'session=' . $v, $vs))]),
            ],
        ];
    }

    private function trips(RequestContext $ctx): bool
    {
        $d = $this->hp->detect($ctx);

        return $d->matched || in_array('attack', $d->tags(), true);
    }

    /**
     * @param callable(list<string>):RequestContext $travel
     * @param list<string> $values
     * @return list<string> the single values that trip the engine
     */
    private function tripping(callable $travel, array $values): array
    {
        if ($values === [] || !$this->trips($travel($values))) {
            return [];
        }
        if (count($values) === 1) {
            return $values;
        }
        $half = intdiv(count($values), 2);

        return [...$this->tripping($travel, array_slice($values, 0, $half)), ...$this->tripping($travel, array_slice($values, $half))];
    }

    public function test_no_issued_value_trips_the_engine_where_it_travels(): void
    {
        $sample = self::sample();
        $travels = self::travels();
        self::assertSame(array_keys($travels), array_values(array_intersect(array_keys($travels), array_keys($sample))), 'every kind is sampled');
        $tripped = [];
        foreach ($travels as $kind => $ways) {
            self::assertGreaterThanOrEqual(3000, count($sample[$kind]), "sanity: {$kind} sample");
            foreach ($ways as $w => $travel) {
                self::assertFalse($this->trips($travel(['7Q7Q7Q'])), "sanity: {$kind} way {$w} is quiet alone");
                foreach (array_chunk($sample[$kind], 20) as $chunk) {
                    foreach ($this->tripping($travel, $chunk) as $v) {
                        $tripped[] = "{$kind} way {$w}: {$v}";
                    }
                }
            }
            foreach ($sample[$kind] as $v) {
                self::assertTrue($kind === 'session cookie' || IssuedValue::quiet($v), "{$kind} {$v} was issued unfit");
            }
        }
        self::assertSame([], $tripped);
    }

    public function test_a_first_pick_core_flags_is_re_rolled_and_running_out_is_a_fault(): void
    {
        // Find a form token whose first pick core flags as a form field, then issue it for real.
        $c = self::context(3);
        $hit = null;
        for ($i = 0; $i < 200000 && $hit === null; $i++) {
            $raw = $c->csrf->issue('sid' . $i, 'token_create', 0, self::NOW);
            if (!IssuedValue::quiet($raw) && $this->trips(new RequestContext('POST', '/settings/tokens', '', MintCorpus::F, 'csrf_token=' . $raw . '&note=x'))) {
                $hit = ['sid' . $i, $raw];
            }
        }
        self::assertNotNull($hit, 'a flagged first pick exists in the search range');
        [$sid, $raw] = $hit;
        $issued = $c->csrfToken($sid, 'token_create', 0, self::NOW);
        self::assertNotSame($raw, $issued);
        self::assertTrue(IssuedValue::quiet($issued));
        self::assertFalse($this->trips(new RequestContext('POST', '/settings/tokens', '', MintCorpus::F, 'csrf_token=' . $issued . '&note=x')));
        $at = $c->csrf->verify($issued, $sid, 'token_create', 0, self::NOW);
        self::assertNotNull($at, 'the re-rolled token still verifies');
        self::assertGreaterThanOrEqual(self::NOW - 7, $at, 'and was nudged back by seconds only');
        self::assertSame($issued, $c->csrfToken($sid, 'token_create', 0, self::NOW), 'the choice is deterministic');

        self::assertSame('ok7Q', IssuedValue::first(4, static fn (int $v): ?string => [null, 'x7Q7Qenv', 'ok7Q', 'never'][$v]));
        $this->expectException(\LogicException::class);
        IssuedValue::first(3, static fn (int $v): string => 'x7Q7Qeval');
    }

    public function test_the_re_roll_is_rare_and_every_persona_prefix_can_issue(): void
    {
        // A first pick is refused about once in twenty thousand, so the re-roll leaves no visible gap.
        $refused = 0;
        for ($i = 0; $i < 20000; $i++) {
            $first = (new CsrfCodec(hash('sha256', 'raw|' . $i, true)))->issue(hash('sha256', 's' . $i, true), 'f', 0, self::NOW);
            $refused += IssuedValue::quiet($first) ? 0 : 1;
        }
        self::assertLessThan(10, $refused, "{$refused} of 20000 first picks refused");

        // The fixed head of a token (persona prefix and kind) is never refused, so every persona can mint.
        $companies = (new \ReflectionClass(PersonaIdentity::class))->getConstant('COMPANIES');
        foreach ((array) $companies as $company) {
            foreach (TokenCodec::KINDS as $kind) {
                $head = TokenCodec::prefixFor(strtolower((string) $company)) . '_' . $kind . '_';
                self::assertTrue(IssuedValue::quiet($head . '7Q7Q7Q'), $head);
            }
        }
    }
}

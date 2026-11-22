<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\IssuedValue;
use Funnypot\App\Tarpit\Mint\MintContext;
use Funnypot\App\Tarpit\Mint\MintKeys;
use Funnypot\App\Tarpit\Mint\MintPersona;
use Funnypot\App\Tarpit\Mint\MintState;
use Funnypot\App\Tarpit\Mint\TokenCodec;
use Funnypot\App\Tarpit\Mint\Totp;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * The engine check every issued value goes through (IssuedValue). Values are sampled under fixed keys
 * through the real issuing code and sent back the way the surface's pages and API docs say: every form
 * token to its own form's action, as a form field (followed by another field, and last) and as JSON;
 * codes, secrets and refresh tokens to the token endpoint; client and request ids to the authorize
 * query and as form fields; recovery codes to the reauth form; access tokens and JWTs as `?access_token`,
 * a Bearer header and X-Api-Key on several API paths; public ids as path segments; the session cookie as
 * the Cookie header. None trips the engine or the app's classifier. Values travel in small batches, and
 * a flagged batch is halved down to the single value that trips. Further tests pin real flagged first
 * picks being re-rolled, the clock never fixing a form token's head, and the cost.
 */
final class TokenMintIssuedValuesTest extends TestCase
{
    private const NOW = 1763800000;

    private static ?Honeypot $engine = null;

    private static function engine(): Honeypot
    {
        return self::$engine ??= MintCorpus::engine();
    }

    private static function check(): IssuedValue
    {
        return IssuedValue::forEngine(self::engine(), new AttackClassifier());
    }

    private static function context(int $seed, ?string $root = null): MintContext
    {
        $c = new MintContext(
            new MintKeys($root ?? hash('sha256', 'issued-values|' . $seed, true)),
            MintPersona::fromSeed($seed),
            new TokenMintStore(sys_get_temp_dir() . '/unused-' . $seed . '.sqlite'),
            static fn (): int => self::NOW,
        );
        $c->issuingWith(self::check());

        return $c;
    }

    /** @return array{0:MintState,1:int,2:string} a state holding one account, its position and kref */
    private static function account(int $seed, ?string $epoch = null, ?string $kref = null): array
    {
        $s = MintState::fresh(self::NOW, $epoch ?? substr(hash('sha256', 'epoch|' . $seed), 0, 16));
        $pos = $s->addAccount('artex' . $seed, 'artex' . $seed . '@example.com', 'pw', self::NOW);

        return [$s, $pos, $kref ?? substr(hash('sha256', 'kref|' . $seed, true), 0, 16)];
    }

    /**
     * @return array<string,list<string>> value kind => issued values
     */
    private static function sample(): array
    {
        $out = ['recovery code' => []];
        for ($seed = 1; $seed <= 4; $seed++) {
            $c = self::context($seed);
            [$s, $pos, $kref] = self::account($seed);
            for ($i = 0; $i < 100; $i++) {
                if ($i % MintState::MAX_TOKENS === 0) {
                    $s->d['a'][$pos]['k'] = [];
                }
                $out['client id'][] = $c->clientId($kref, $s, $seed, $i);
                $out['client secret'][] = $c->clientSecret($kref, $s, $seed, $i, $i % 3);
                $out['code'][] = $c->oauthCode($kref, $s, $seed, $i);
                $out['request id'][] = $c->requestId($kref, $s, $i);
                $out['public id'][] = $c->appPublicId($kref, $s, $seed, $i);
                $out['refresh token'][] = $c->refreshToken($kref, $s, $pos, $i);
                $out['session cookie'][] = $c->startSession($s, $pos, $kref, self::NOW);
                // An access token or JWT is probed on each of the API paths, so half as many keep the cost bounded.
                if ($i % 2 === 0) {
                    [$tpos, $pat] = $c->addToken($s, $pos, $kref, $i % 4 === 0 ? 'pat' : 'oat', '', ['read:user'], 0, null, self::NOW);
                    $out['access token'][] = $pat;
                    $out['public id'][] = (string) $s->d['a'][$pos]['k'][$tpos]['id'];
                    $out['jwt'][] = $c->loginJwt(bin2hex(substr($kref, 0, 8)), $s, $pos, $i, self::NOW + $i);
                }
                if ($i % 5 === 0) {
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
        $form = static fn (string $name, string $path = '/login/oauth/access_token'): array => [
            static fn (array $vs): RequestContext => new RequestContext('POST', $path, '', MintCorpus::F, self::fields($vs, $name, false)),
            static fn (array $vs): RequestContext => new RequestContext('POST', $path, '', MintCorpus::F, 'grant_type=x&' . self::fields($vs, $name, true)),
            static fn (array $vs): RequestContext => new RequestContext('POST', $path, '', MintCorpus::J, (string) json_encode([$name => $vs[0], 'more' => $vs, 'password' => 'x'])),
        ];
        $bearer = [
            static fn (array $vs): RequestContext => new RequestContext('GET', '/api/v2/user', self::fields($vs, 'access_token', true), []),
            static fn (array $vs): RequestContext => new RequestContext('GET', '/v2/users', self::fields($vs, 'access_token', true), []),
            static fn (array $vs): RequestContext => new RequestContext('POST', '/api/v2/orders/exports', self::fields($vs, 'access_token', true), MintCorpus::J, '{"format":"csv"}'),
            static fn (array $vs): RequestContext => new RequestContext('GET', '/api/v2/user', '', ['Authorization' => 'Bearer ' . implode(' ', $vs)]),
            static fn (array $vs): RequestContext => new RequestContext('GET', '/api/v2/user', '', ['X-Api-Key' => implode(' ', $vs)]),
        ];
        $query = static fn (string $name): callable => static fn (array $vs): RequestContext => new RequestContext('GET', '/login/oauth/authorize', self::fields($vs, $name, false), []);

        return [
            'refresh token' => $form('refresh_token'),
            'code' => $form('code'),
            'client secret' => $form('client_secret'),
            'recovery code' => $form('recovery_code', '/settings/reauth'),
            'client id' => [...$form('client_id'), $query('client_id')],
            'request id' => [...$form('authorization_request', '/login/oauth/authorize'), $query('authorization_request')],
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
        $d = self::engine()->detect($ctx);

        return $d->matched || in_array('attack', $d->tags(), true) || (new AttackClassifier())->classify($ctx) !== null;
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
            self::assertGreaterThanOrEqual(200, count($sample[$kind]), "sanity: {$kind} sample");
            foreach ($ways as $w => $travel) {
                self::assertFalse($this->trips($travel(['7Q7Q7Q'])), "sanity: {$kind} way {$w} is quiet alone");
                foreach (array_chunk($sample[$kind], 20) as $chunk) {
                    foreach ($this->tripping($travel, $chunk) as $v) {
                        $tripped[] = "{$kind} way {$w}: {$v}";
                    }
                }
            }
        }
        self::assertSame([], $tripped);
    }

    public function test_every_form_token_is_quiet_on_its_own_form(): void
    {
        $tripped = [];
        $sent = 0;
        for ($seed = 1; $seed <= 4; $seed++) {
            $c = self::context($seed);
            [$s, $pos, $kref] = self::account($seed);
            [$tpos] = $c->addToken($s, $pos, $kref, 'pat', '', ['read:user'], 0, null, self::NOW);
            $ids = ['token_delete' => (string) $s->d['a'][$pos]['k'][$tpos]['id'], 'app_secret' => $c->appPublicId($kref, $s, $seed, 1)];
            $ids['app_delete'] = $ids['app_secret'];
            foreach (MintContext::FORM_ACTIONS as $form => $action) {
                $id = $ids[$form] ?? '';
                $path = strtr($action, ['{id}' => $id, '{org}' => $c->persona->slug]);
                $tokens = [];
                for ($i = 0; $i < 40; $i++) {
                    $tokens[] = $c->csrfToken(hash('sha256', 'sid|' . $seed . '|' . $i, true), $form, $i % 5, self::NOW - 41 * $i, $id);
                }
                $ways = [
                    static fn (array $vs): RequestContext => new RequestContext('POST', $path, '', MintCorpus::F, self::fields($vs, 'csrf_token', false)),
                    static fn (array $vs): RequestContext => new RequestContext('POST', $path, '', MintCorpus::F, 'password=Passw0rd%21x&' . self::fields($vs, 'csrf_token', true)),
                    static fn (array $vs): RequestContext => new RequestContext('POST', $path, '', MintCorpus::J, (string) json_encode(['csrf_token' => $vs[0], 'more' => $vs])),
                ];
                foreach ($ways as $w => $way) {
                    self::assertFalse($this->trips($way(['7Q7Q7Q'])), "sanity: {$path} way {$w} is quiet alone");
                    foreach (array_chunk($tokens, 20) as $chunk) {
                        $sent += count($chunk);
                        foreach ($this->tripping($way, $chunk) as $v) {
                            $tripped[] = "{$form} on {$path} way {$w}: {$v}";
                        }
                    }
                }
            }
        }
        self::assertSame(4 * 40 * 3 * count(MintContext::FORM_ACTIONS), $sent);
        self::assertSame([], $tripped);
    }

    public function test_a_first_pick_core_flags_is_re_rolled(): void
    {
        // A real join-form token that core flags on its own form: the path ends in a command-like word
        // and the token in `time`. A probe on any other path missed it.
        $j = self::context(7, str_repeat("\x42", 32));
        $source = substr(hash('sha256', 'source|864100', true), 0, 16);
        $first = $j->csrf->issue($source, 'join', 0, 1795300000);
        self::assertSame('iDZlU-0ivGARhiaDxza4zwmNRb3BNSGxTimE', $first, 'sanity: the first pick');
        $join = static fn (string $t): RequestContext => new RequestContext('POST', '/join', '', MintCorpus::F, 'csrf_token=' . $t . '&username=artex1&email=artex1%40example.com&password=Passw0rd%21x&password_confirmation=Passw0rd%21x');
        self::assertTrue($this->trips($join($first)), 'sanity: core flags it on the sign-up form');
        $issued = $j->csrfToken($source, 'join', 0, 1795300000);
        self::assertNotSame($first, $issued);
        self::assertFalse($this->trips($join($issued)));
        self::assertNotNull($j->csrf->verify($issued, $source, 'join', 0, 1795300000));


        // A real recovery code that core flagged before the engine check: `qezso-xmlns` as code 0.
        $c = self::context(7, str_repeat("\x42", 32));
        [$s] = self::account(7, 'abcdef0123456789');
        $kref = str_repeat("\x07", 16);
        $raw = strtolower(Totp::base32(substr(hash_hmac('sha256', 'recovery|' . bin2hex($kref) . '|abcdef0123456789|1|20753297|0|0', $c->keys->key('totp'), true), 0, 7)));
        self::assertSame('qezso-xmlns', substr($raw, 0, 5) . '-' . substr($raw, 5, 5), 'sanity: the first pick');
        $confirm = static fn (string $code): array => [
            new RequestContext('POST', '/settings/reauth', '', MintCorpus::F, 'csrf_token=' . str_repeat('A', 36) . '&password=x&recovery_code=' . $code),
            new RequestContext('POST', '/settings/reauth', '', MintCorpus::J, (string) json_encode(['recovery_code' => $code, 'password' => 'x'])),
        ];
        self::assertTrue($this->trips($confirm('qezso-xmlns')[0]), 'sanity: core flags the first pick');
        $code = $c->recoveryCodes($kref, $s, 1, 20753297)[0];
        self::assertNotSame('qezso-xmlns', $code);
        foreach ($confirm($code) as $ctx) {
            self::assertFalse($this->trips($ctx), "{$code} is re-rolled to a quiet code");
        }
        self::assertSame($code, $c->recoveryCodes($kref, $s, 1, 20753297)[0], 'the choice is deterministic');

        // A form token whose first pick core flags as a form field (found by a cheap pre-filter, then the engine).
        $hit = null;
        for ($i = 0; $i < 400000 && $hit === null; $i++) {
            $first = $c->csrf->issue('sid' . $i, 'token_create', 0, self::NOW);
            if (preg_match('~(?:env|eval)\z~i', $first) === 1 && $this->trips(new RequestContext('POST', '/settings/tokens', '', MintCorpus::F, 'csrf_token=' . $first . '&note=x'))) {
                $hit = ['sid' . $i, $first];
            }
        }
        self::assertNotNull($hit, 'a flagged first pick exists in the search range');
        [$sid, $first] = $hit;
        $issued = $c->csrfToken($sid, 'token_create', 0, self::NOW);
        self::assertNotSame($first, $issued);
        self::assertFalse($this->trips(new RequestContext('POST', '/settings/tokens', '', MintCorpus::F, 'csrf_token=' . $issued . '&note=x')));
        $at = $c->csrf->verify($issued, $sid, 'token_create', 0, self::NOW);
        self::assertNotNull($at, 'the re-rolled token still verifies');
        self::assertGreaterThanOrEqual(self::NOW - 7, $at, 'and was nudged back by seconds only');
        self::assertTrue($c->csrf->issuedByUs($issued), 'and is still recognisably ours');
        self::assertSame($issued, $c->csrfToken($sid, 'token_create', 0, self::NOW), 'the choice is deterministic');
    }

    public function test_the_catch_all_still_catches_a_value_only_a_command_word_path_flags(): void
    {
        // Core reads a path ending in a command-like word with a value ending in `time`: the sign-up form
        // token above, and an access token ending the same way. Neither reads as an attack on its other
        // paths, so only the catch-all refuses them; a catch-all that stopped pairing would fail here.
        $check = self::check();
        $form = 'iDZlU-0ivGARhiaDxza4zwmNRb3BNSGxTimE';
        $pat = 'pal_pat_Lp1GAF51csSpDavjUKULfng72HBTiME';
        self::assertTrue($this->trips(IssuedValue::probe($form, IssuedValue::CATCH_ALL)));
        self::assertFalse($this->trips(IssuedValue::probe($form, '/settings/tokens')));
        self::assertFalse($check->fit($form, ['/settings/tokens']), 'refused by the catch-all alone');
        self::assertTrue($this->trips(IssuedValue::bearerProbe($pat, IssuedValue::CATCH_ALL)));
        self::assertFalse($this->trips(IssuedValue::bearerProbe($pat, '/api/v2/user')));
        self::assertFalse($check->fit($pat, ['/api/v2/user'], [], true), 'refused by the catch-all alone');
    }

    public function test_the_check_steps_skips_and_fails_safe(): void
    {
        $check = new IssuedValue(static fn (RequestContext $r): bool => str_contains($r->query, 'bad'));
        self::assertSame('ok7Q', $check->first(4, static fn (int $v): ?string => [null, 'bad7Q', 'ok7Q', 'never'][$v]));
        self::assertFalse($check->fit('7Qbad7Q'));
        self::assertTrue($check->fit('7Qok7Q'));
        $paths = new IssuedValue(static fn (RequestContext $r): bool => str_contains($r->path, '/bad'));
        self::assertTrue($paths->fit('bad1'), 'a value that never travels in a path skips the path probe');
        self::assertFalse($paths->fit('bad1', [], ['POST /settings/tokens/{v}/delete']));
        $seen = [];
        (new IssuedValue(static function (RequestContext $r) use (&$seen): bool {
            $seen[] = $r->method . ' ' . $r->path;

            return false;
        }))->fit('v7Q', ['/settings/profile'], ['GET /settings/applications/{v}']);
        self::assertSame(['POST /settings/profile', 'POST ' . IssuedValue::CATCH_ALL, 'GET /settings/applications/v7Q'], $seen, 'its own path, the catch-all, then each route');
        self::assertTrue(self::check()->fit('7Q7Q7Q'), 'sanity: the probe alone is quiet');

        $c = self::context(5);
        $c->issuingWith(null);
        try {
            $c->csrfToken('sid', 'profile', 0, self::NOW);
            self::fail('issuing without the engine check must fail');
        } catch (\LogicException) {
        }
        $this->expectException(\LogicException::class);
        $check->first(3, static fn (int $v): string => 'bad' . $v);
    }

    public function test_the_clock_never_fixes_a_form_tokens_head_and_the_cost_is_bounded(): void
    {
        // The MAC leads, so tokens of one second, or of a minute, never share a head.
        $c = self::context(11);
        $heads = [];
        for ($i = 0; $i < 60; $i++) {
            $heads[] = substr($c->csrfToken('sid' . $i, 'profile', 0, self::NOW + intdiv($i, 2)), 0, 3);
        }
        self::assertGreaterThan(50, count(array_unique($heads)), 'heads vary within a minute');

        // The fixed head of an access token (persona prefix and kind) is never refused, so every persona can mint.
        $check = self::check();
        $companies = (new \ReflectionClass(PersonaIdentity::class))->getConstant('COMPANIES');
        foreach ((array) $companies as $company) {
            foreach (TokenCodec::KINDS as $kind) {
                $head = TokenCodec::prefixFor(strtolower((string) $company)) . '_' . $kind . '_';
                self::assertTrue($check->fit($head . '7Q7Q7Q7Q7Q7Q7Q7Q'), $head);
            }
        }

        // The check is one engine pass per candidate, a second only for a public id.
        $t = hrtime(true);
        for ($i = 0; $i < 200; $i++) {
            $c->csrfToken('sid' . $i, 'token_create', 0, self::NOW);
        }
        $perValueMs = (hrtime(true) - $t) / 1e6 / 200;
        self::assertLessThan(20.0, $perValueMs, 'a form token costs one bounded engine pass');
    }
}

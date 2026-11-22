<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Closure;
use Funnypot\App\Storage\TokenMintOutcome;
use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Storage\TokenMintTx;
use Funnypot\App\Tarpit\InertSecret;

/**
 * The account surface's shared machinery: keys and codecs, the deterministic derivations of every
 * credential from its serials (so no raw secret is ever stored and a replayed run is byte-identical),
 * session and CSRF handling, and the per-source work-unit ledger.
 *
 * The ledger counts requests, not time: GET 1, form POST 3, API call 1, token endpoint 2, sign-in 3,
 * at most UNITS_PER_HOUR per source per clock hour. The same request sequence is shed at the same
 * request whatever the host's load; nothing here reads a wall clock except the injected one.
 */
final class MintContext
{
    public const UNITS_PER_HOUR = 1500;
    public const COST_GET = 1;
    public const COST_POST = 3;
    public const COST_API = 1;
    public const COST_TOKEN = 2;
    public const COST_SIGNIN = 3;

    public readonly TokenCodec $tokens;
    public readonly SessionCodec $sessions;
    public readonly CsrfCodec $csrf;
    public readonly FrictionPicker $friction;
    public readonly AccountPages $pages;
    private ?IssuedValue $issued = null;

    /** @param Closure():int $clock */
    public function __construct(
        public readonly MintKeys $keys,
        public readonly MintPersona $persona,
        public readonly TokenMintStore $store,
        private Closure $clock,
        bool $friction = true,
    ) {
        $this->tokens = new TokenCodec($keys->key('token'), $persona->prefix);
        $this->sessions = new SessionCodec($keys->key('session'));
        $this->csrf = new CsrfCodec($keys->key('csrf'));
        $this->friction = new FrictionPicker($keys->key('pick'), $friction);
        $this->pages = new AccountPages($persona);
    }

    /**
     * The engine check for the request being answered (null between requests). Every random value the
     * surface issues and expects back goes through it; issuing without one is a fault, never an
     * unchecked value.
     */
    public function issuingWith(?IssuedValue $check): void
    {
        $this->issued = $check;
    }

    /** @param callable(int):?string $gen */
    private function issue(int $tries, callable $gen, bool $inPath = false): string
    {
        if ($this->issued === null) {
            throw new \LogicException('issuing needs the engine check');
        }

        return $this->issued->first($tries, $gen, $inPath);
    }

    public function now(): int
    {
        return ($this->clock)();
    }

    /** @return array{0:string,1:string} [row key hex, k8 hex] for a source reference */
    public static function rowKeys(string $kref): array
    {
        return [bin2hex($kref), bin2hex(substr($kref, 0, 8))];
    }

    public function newState(string $kref, int $now): MintState
    {
        return MintState::fresh($now, $this->keys->hexId('row|' . bin2hex($kref) . '|' . $now, 16));
    }

    // --- units -----------------------------------------------------------------------------------

    /** The 429 a source over its hourly units gets, or null. */
    public function overUnits(TokenMintTx $tx, int $cost, bool $json, bool $signedIn = false): ?MintPlan
    {
        if ($tx->unitsUsed + $cost <= self::UNITS_PER_HOUR) {
            return null;
        }
        $retry = 3600 - ($tx->now % 3600);

        return $this->throttledPlan($retry, $json, $signedIn);
    }

    /** The throttle answer; an HTML one shows the nav for the visitor's real session state. */
    public function throttledPlan(int $retry, bool $json, bool $signedIn): MintPlan
    {
        $text = MintVocabulary::text('throttled', ['wait' => MintVocabulary::wait($retry)]);
        $plan = $json
            ? MintPlan::json(429, ['message' => $text, 'documentation_url' => '/docs/api'])
            : MintPlan::html(429, $this->pages->error('Too many requests', $text, '/', 'Go home', $signedIn));

        return $plan->with('Retry-After', (string) $retry)->attribute(['outcome' => 'throttled']);
    }

    /** The units a request costs: zero once a source is already over its hour, so the shed costs no write. */
    public static function charge(TokenMintTx $tx, int $cost): int
    {
        return $tx->unitsUsed > self::UNITS_PER_HOUR ? 0 : $cost;
    }

    // --- sessions --------------------------------------------------------------------------------

    /**
     * Whether the request carries a session that is live in committed state. A read only, for pages
     * that show the nav without touching the account; any fault reads as signed out.
     */
    public function signedIn(MintRequest $r): bool
    {
        try {
            $now = $this->now();
            $sess = $this->session($r, $now);
            if ($sess === null) {
                return false;
            }

            return $this->liveAccount($this->store->load(bin2hex($sess['kref'])), $sess, $now) !== null;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** @return array{kref:string,acct:int,sid:string,issuedAt:int}|null */
    public function session(MintRequest $r, int $now): ?array
    {
        $c = $r->cookie(SessionCodec::COOKIE);

        return $c === null ? null : $this->sessions->parse($c, $now);
    }

    /**
     * The account position a live session names in this state, or null.
     *
     * @param array{kref:string,acct:int,sid:string,issuedAt:int} $sess
     */
    public function liveAccount(?MintState $s, array $sess, int $now): ?int
    {
        if ($s === null) {
            return null;
        }
        $pos = $s->accountPos($sess['acct']);
        if ($pos === null) {
            return null;
        }
        $sp = $s->sidPos($pos, bin2hex($sess['sid']));
        if ($sp === null || !MintState::sidLive($s->d['a'][$pos]['s'][$sp], $now)) {
            return null;
        }

        return $pos;
    }

    /** @param array{kref:string,acct:int,sid:string,issuedAt:int} $sess */
    public function touchSession(MintState $s, int $pos, array $sess, int $now): void
    {
        $sp = $s->sidPos($pos, bin2hex($sess['sid']));
        if ($sp !== null) {
            $s->d['a'][$pos]['s'][$sp]['l'] = $now;
        }
        $s->d['a'][$pos]['t'] = $now;
    }

    /**
     * Start a session for an account; returns the cookie value. Keeps the newest four sids. The cookie
     * rides only in the Cookie header, which core's attack rules never scan, so it needs only the
     * fingerprint check; its first characters are fixed per source and could never be re-rolled anyway.
     */
    public function startSession(MintState $s, int $pos, string $kref, int $now): string
    {
        $a = &$s->d['a'][$pos];
        $cookie = '';
        $sid = '';
        for ($try = 0; $try < 16; $try++) {
            $n = (int) $a['sn'];
            $a['sn'] = $n + 1;
            $sid = substr(hash_hmac('sha256', 'sid|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $a['i'] . '|' . $n, $this->keys->key('session'), true), 0, 8);
            $cookie = $this->sessions->issue($kref, ((int) $a['i']) % 256, $sid, $now);
            if (InertSecret::isClean('"' . $cookie . '"')) {
                break;
            }
            if ($try === 15) {
                throw new \LogicException('no clean session cookie within the tries');
            }
        }
        $a['s'][] = ['id' => bin2hex($sid), 'c' => $now, 'l' => $now];
        $a['s'] = array_slice($a['s'], -MintState::MAX_SIDS);
        $a['t'] = $now;
        unset($a);

        return $cookie;
    }

    public function cookieHeader(string $value, bool $https): string
    {
        return SessionCodec::COOKIE . '=' . $value . '; Path=/; HttpOnly; SameSite=Lax' . ($https ? '; Secure' : '');
    }

    public function clearCookieHeader(bool $https): string
    {
        return SessionCodec::COOKIE . '=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax' . ($https ? '; Secure' : '');
    }

    // --- CSRF ------------------------------------------------------------------------------------

    /** A fresh form token, nudged back a second at a time until it is fit to issue. */
    public function csrfToken(string $sid, string $formId, int $epoch, int $now): string
    {
        return $this->issue(8, fn (int $i): string => $this->csrf->issue($sid, $formId, $epoch, $now - $i));
    }

    /** The sid a form is bound to: the session's, or the source reference for signed-out forms. */
    public static function formSid(?array $sess, string $kref): string
    {
        return $sess !== null ? $sess['sid'] : $kref;
    }

    // --- derivations -----------------------------------------------------------------------------

    public function pwHash(string $kref, string $password): string
    {
        return base64_encode(hash_hmac('sha256', bin2hex($kref) . "\0" . $password, $this->keys->key('password'), true));
    }

    private function tokenBind(MintState $s, array $a, array $t): string
    {
        return $s->epoch() . '|' . $a['i'] . '|' . $t['n'] . '|' . $t['v'];
    }

    /** Re-derive a stored token entry's string. */
    public function tokenString(MintState $s, int $pos, int $tpos, string $kref): string
    {
        $a = $s->d['a'][$pos];
        $t = $a['k'][$tpos];

        return $this->tokens->encode((string) $t['k'], substr($kref, 0, 8), ((int) $a['i']) % 256, ((int) $t['n']) % 256, $this->tokenBind($s, $a, $t));
    }

    /**
     * Add a token entry (pat or oat) and return [position, string]. The variant is the first whose
     * string is fit to issue, and is stored so the string re-derives exactly.
     *
     * @param list<string> $scopes
     * @return array{0:int,1:string}
     */
    public function addToken(MintState $s, int $pos, string $kref, string $kind, string $note, array $scopes, int $expires, ?int $app, int $now): array
    {
        $n = $s->nextTokenSerial($pos);
        $entry = [
            'n' => $n, 'v' => 0, 'k' => $kind,
            'id' => $this->publicId('tok|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $s->d['a'][$pos]['i'] . '|' . $n),
            'nt' => $note, 'sc' => $scopes, 'c' => $now, 'x' => $expires, 'lu' => 0, 'ap' => $app, 'rl' => [0, 0],
        ];
        $s->d['a'][$pos]['k'][] = $entry;
        $tpos = count($s->d['a'][$pos]['k']) - 1;
        $token = $this->issue(64, function (int $v) use ($s, $pos, $tpos, $kref): string {
            $s->d['a'][$pos]['k'][$tpos]['v'] = $v;

            return $this->tokenString($s, $pos, $tpos, $kref);
        });

        return [$tpos, $token];
    }

    /** A 12-hex public id that always holds a digit, so it is always an `{id}` the routes own. */
    public function publicId(string $label): string
    {
        return $this->issue(64, function (int $v) use ($label): ?string {
            $id = $this->keys->hexId($label . self::step($v), 12);

            return preg_match('/[0-9]/', $id) === 1 ? $id : null;
        }, true);
    }

    /** The derivation suffix for re-roll step $v; step 0 adds nothing, so a first pick keeps its value. */
    private static function step(int $v): string
    {
        return $v === 0 ? '' : '|v' . $v;
    }

    /** A hex value fit to issue, re-rolled over the label's steps. */
    private function hexValue(string $label, int $chars): string
    {
        return $this->issue(64, fn (int $v): string => $this->keys->hexId($label . self::step($v), $chars));
    }

    public function clientId(string $kref, MintState $s, int $acctSerial, int $appSerial): string
    {
        return $this->hexValue('client|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $appSerial, 20);
    }

    public function appPublicId(string $kref, MintState $s, int $acctSerial, int $appSerial): string
    {
        return $this->publicId('app|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $appSerial);
    }

    public function clientSecret(string $kref, MintState $s, int $acctSerial, int $appSerial, int $secretN): string
    {
        $label = 'clientsecret|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $appSerial . '|' . $secretN;

        return $this->issue(64, fn (int $v): string => substr(hash_hmac('sha256', $label . self::step($v), $this->keys->key('token')), 0, 40));
    }

    public function oauthCode(string $kref, MintState $s, int $acctSerial, int $n): string
    {
        $label = 'code|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $n;

        return $this->issue(64, fn (int $v): string => substr(hash_hmac('sha256', $label . self::step($v), $this->keys->key('token')), 0, 20));
    }

    /** A refresh token fit to issue, re-rolled by stepping the variant in its binding. */
    public function refreshToken(string $kref, MintState $s, int $pos, int $rn): string
    {
        $a = $s->d['a'][$pos];

        return $this->issue(64, fn (int $v): string => $this->tokens->encode('ort', substr($kref, 0, 8), ((int) $a['i']) % 256, $rn % 256, $s->epoch() . '|' . $a['i'] . '|r' . $rn . '|' . $v));
    }

    /** A sign-in JWT fit to issue; only its `jti` steps. */
    public function loginJwt(string $k8, MintState $s, int $pos, int $jn, int $now): string
    {
        $a = $s->d['a'][$pos];
        $serial = (int) $a['i'];

        return $this->issue(16, fn (int $v): string => JwtCodec::encode([
            'sub' => (string) $a['u'],
            'sid' => DecoyPrincipalResolver::sessionClaim($k8, $s->epoch(), $serial),
            'scope' => 'read:user',
            'iat' => $now,
            'exp' => $now + JwtCodec::LIFETIME_S,
            'jti' => $this->keys->hexId('jwt|' . $k8 . '|' . $serial . '|' . $jn . '|' . $v, 16),
        ], $this->keys->key('jwt')));
    }

    public function totpSecret(string $kref, MintState $s, int $acctSerial, int $enrol): string
    {
        return substr(hash_hmac('sha256', 'totp|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $enrol, $this->keys->key('totp'), true), 0, 20);
    }

    /** @return list<string> ten single-use recovery codes, each fit to issue */
    public function recoveryCodes(string $kref, MintState $s, int $acctSerial, int $enrol): array
    {
        $out = [];
        for ($i = 0; $i < MintState::RECOVERY_CODES; $i++) {
            $out[] = $this->issue(16, function (int $v) use ($kref, $s, $acctSerial, $enrol, $i): string {
                $raw = hash_hmac('sha256', 'recovery|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $enrol . '|' . $i . '|' . $v, $this->keys->key('totp'), true);
                $b32 = strtolower(Totp::base32(substr($raw, 0, 7)));

                return substr($b32, 0, 5) . '-' . substr($b32, 5, 5);
            });
        }

        return $out;
    }

    public function requestId(string $kref, MintState $s, int $n): string
    {
        return $this->hexValue('req|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $n, 12);
    }

    /** Numeric account id, in a range that never reads as a rule number. */
    public function accountNumber(string $kref, MintState $s, int $acctSerial): int
    {
        return 4000000 + (hexdec($this->keys->hexId('uid|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial, 6)) % 900000);
    }

    /** Wrap a decision (usually a plan) and its state change for the store. */
    public static function out(?MintState $state, bool $stateChange, int $units, mixed $value): TokenMintOutcome
    {
        return new TokenMintOutcome($state, $stateChange, $units, $value);
    }
}

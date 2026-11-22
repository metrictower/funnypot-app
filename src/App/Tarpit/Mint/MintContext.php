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

    /** Start a session for an account; returns the cookie value. Keeps the newest four sids. */
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

    /** A fresh form token, nudged by a second until it is fingerprint-clean. */
    public function csrfToken(string $sid, string $formId, int $epoch, int $now): string
    {
        $t = $this->csrf->issue($sid, $formId, $epoch, $now);
        for ($i = 1; $i < 8 && !InertSecret::isClean("'" . $t . "'"); $i++) {
            $t = $this->csrf->issue($sid, $formId, $epoch, $now - $i);
        }

        return $t;
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
     * Add a token entry (pat or oat) and return [position, string]. The variant is the first that
     * renders fingerprint-clean, and is stored so the string re-derives exactly.
     *
     * @param list<string> $scopes
     * @return array{0:int,1:string}
     */
    public function addToken(MintState $s, int $pos, string $kref, string $kind, string $note, array $scopes, int $expires, ?int $app, int $now): array
    {
        $n = $s->nextTokenSerial($pos);
        $entry = [
            'n' => $n, 'v' => 0, 'k' => $kind,
            'id' => $this->keys->hexId('tok|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $s->d['a'][$pos]['i'] . '|' . $n, 12),
            'nt' => $note, 'sc' => $scopes, 'c' => $now, 'x' => $expires, 'lu' => 0, 'ap' => $app, 'rl' => [0, 0],
        ];
        $s->d['a'][$pos]['k'][] = $entry;
        $tpos = count($s->d['a'][$pos]['k']) - 1;
        $token = '';
        for ($v = 0; $v < 64; $v++) {
            $s->d['a'][$pos]['k'][$tpos]['v'] = $v;
            $token = $this->tokenString($s, $pos, $tpos, $kref);
            if (InertSecret::isClean('"' . $token . '"')) {
                break;
            }
        }

        return [$tpos, $token];
    }

    public function clientId(string $kref, MintState $s, int $acctSerial, int $appSerial): string
    {
        return $this->keys->hexId('client|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $appSerial, 20);
    }

    public function appPublicId(string $kref, MintState $s, int $acctSerial, int $appSerial): string
    {
        return $this->keys->hexId('app|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $appSerial, 12);
    }

    public function clientSecret(string $kref, MintState $s, int $acctSerial, int $appSerial, int $secretN): string
    {
        return substr(hash_hmac('sha256', 'clientsecret|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $appSerial . '|' . $secretN, $this->keys->key('token')), 0, 40);
    }

    public function oauthCode(string $kref, MintState $s, int $acctSerial, int $n): string
    {
        return substr(hash_hmac('sha256', 'code|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $n, $this->keys->key('token')), 0, 20);
    }

    public function totpSecret(string $kref, MintState $s, int $acctSerial, int $enrol): string
    {
        return substr(hash_hmac('sha256', 'totp|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $enrol, $this->keys->key('totp'), true), 0, 20);
    }

    /** @return list<string> ten single-use recovery codes, each fingerprint-clean */
    public function recoveryCodes(string $kref, MintState $s, int $acctSerial, int $enrol): array
    {
        $out = [];
        for ($i = 0; $i < MintState::RECOVERY_CODES; $i++) {
            $code = '';
            for ($v = 0; $v < 16; $v++) {
                $raw = hash_hmac('sha256', 'recovery|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $acctSerial . '|' . $enrol . '|' . $i . '|' . $v, $this->keys->key('totp'), true);
                $b32 = strtolower(Totp::base32(substr($raw, 0, 7)));
                $code = substr($b32, 0, 5) . '-' . substr($b32, 5, 5);
                if (InertSecret::isClean('"' . $code . '"')) {
                    break;
                }
            }
            $out[] = $code;
        }

        return $out;
    }

    public function requestId(string $kref, MintState $s, int $n): string
    {
        return $this->keys->hexId('req|' . bin2hex($kref) . '|' . $s->epoch() . '|' . $n, 12);
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

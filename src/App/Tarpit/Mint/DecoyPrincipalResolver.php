<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * Resolves who a request acts as on the account surface: a live session cookie, or a bearer value
 * (a personal or OAuth access token, or a login JWT) checked against committed state. A sibling
 * surface that wants to honour the same accounts (outbound webhooks, for one) asks this, and gets
 * the same answer the API would.
 */
final class DecoyPrincipalResolver
{
    public function __construct(private MintContext $c)
    {
    }

    /**
     * The presented API credential, verified. Null when none was sent; kind 'bad' when one was sent
     * and does not verify. Header first, then X-API-Key, then the deprecated query parameter.
     *
     * @return array{0:array<string,mixed>|null,1:bool} [credential, came from the query]
     */
    public function bearer(MintRequest $r, int $now): array
    {
        $value = null;
        $deprecated = false;
        $auth = $r->header('Authorization');
        if ($auth !== null && preg_match('/\A(?:bearer|token)\s+(\S+)\s*\z/i', substr($auth, 0, 4200), $m) === 1) {
            $value = $m[1];
        } elseif ($auth !== null && trim($auth) !== '') {
            return [['kind' => 'bad'], false];
        } elseif (($key = $r->header('X-Api-Key')) !== null && trim($key) !== '') {
            $value = trim($key);
        } elseif (($q = $r->queryStr('access_token')) !== null && $q !== '') {
            $value = $q;
            $deprecated = true;
        }
        if ($value === null) {
            return [null, false];
        }
        if (strlen($value) > JwtCodec::MAX_BYTES) {
            return [['kind' => 'bad'], $deprecated];
        }

        return [$this->verify($value, $now) ?? ['kind' => 'bad'], $deprecated];
    }

    /** @return array<string,mixed>|null */
    private function verify(string $value, int $now): ?array
    {
        if (JwtCodec::looksLikeJwt($value)) {
            $claims = JwtCodec::decode($value, $this->c->keys->key('jwt'), $now);
            if ($claims === null || !is_string($claims['k8'] ?? null) || !is_string($claims['e'] ?? null) || !is_int($claims['a'] ?? null)
                || preg_match('/\A[a-f0-9]{16}\z/', $claims['k8']) !== 1) {
                return null;
            }
            foreach ($this->c->store->rowsByK8($claims['k8']) as $k => $s) {
                if (hash_equals($s->epoch(), $claims['e']) && $s->accountPosBySerial($claims['a']) !== null) {
                    return ['kind' => 'jwt', 'k' => $k, 'k8' => $claims['k8'], 'kref' => (string) hex2bin($k), 'acct' => $claims['a'], 'scopes' => ['read:user']];
                }
            }

            return null;
        }
        $d = $this->c->tokens->decode($value);
        if ($d === null || $d['kind'] === 'ort') {
            return null;
        }
        $k8 = bin2hex($d['k8']);
        foreach ($this->c->store->rowsByK8($k8) as $k => $s) {
            $pos = $s->accountPos($d['acct']);
            $tpos = $pos !== null ? $s->tokenPos($pos, $d['serial'], $d['kind']) : null;
            if ($pos === null || $tpos === null) {
                continue;
            }
            $t = $s->d['a'][$pos]['k'][$tpos];
            $bind = $s->epoch() . '|' . $s->d['a'][$pos]['i'] . '|' . $t['n'] . '|' . $t['v'];
            if ($this->c->tokens->verify($d, $bind) && ((int) $t['x'] === 0 || (int) $t['x'] > $now)) {
                return ['kind' => $d['kind'], 'k' => $k, 'k8' => $k8, 'kref' => (string) hex2bin($k), 'acct' => (int) $s->d['a'][$pos]['i'], 'tn' => (int) $t['n'], 'scopes' => (array) $t['sc']];
            }
        }

        return null;
    }

    /**
     * The account a request acts as, by session or bearer, or null.
     *
     * @return array{login:string,kind:string,scopes:list<string>}|null
     */
    public function resolve(MintRequest $r): ?array
    {
        $now = $this->c->now();
        $sess = $this->c->session($r, $now);
        if ($sess !== null) {
            $s = $this->c->store->load(bin2hex($sess['kref']));
            $pos = $this->c->liveAccount($s, $sess, $now);
            if ($s !== null && $pos !== null) {
                return ['login' => (string) $s->d['a'][$pos]['u'], 'kind' => 'session', 'scopes' => []];
            }
        }
        [$cred] = $this->bearer($r, $now);
        if ($cred === null || $cred['kind'] === 'bad') {
            return null;
        }
        $s = $this->c->store->load((string) $cred['k']);
        $pos = $s?->accountPosBySerial((int) $cred['acct']);
        if ($s === null || $pos === null) {
            return null;
        }

        return ['login' => (string) $s->d['a'][$pos]['u'], 'kind' => (string) $cred['kind'], 'scopes' => (array) $cred['scopes']];
    }
}

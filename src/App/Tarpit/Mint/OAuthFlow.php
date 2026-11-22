<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\App\Storage\TokenMintTx;

/**
 * The OAuth authorization-code flow, the organisation SSO page and the identity provider.
 *
 * Nothing here navigates off-site: consent, the issued code, a denial and every error render on the
 * surface's own pages, and a registered callback is only ever shown as text. The `state` a client
 * sends is held server-side under a generated request id and appears only in the body of the consent
 * POST's answer, escaped; never in a GET answer and never in a header.
 *
 * Codes and refresh tokens are single-use: the token endpoint consumes them with a row count inside
 * the same transaction that issues the new tokens, so a replay or a race has exactly one winner.
 * The identity provider never signs anyone in.
 */
final class OAuthFlow
{
    public const CODE_TTL_S = 600;
    public const ACCESS_TTL_S = 28800;
    public const REFRESH_TTL_S = 2592000;
    private const STATE = '/\A[A-Za-z0-9._~-]{1,128}\z/';

    public function __construct(private MintContext $c, private MintFlow $flow)
    {
    }

    public function handle(MintRequest $r): MintPlan
    {
        $get = $r->readMethod() === 'GET';

        return match ($r->route) {
            'authorize' => $get ? $this->authorizePage($r) : $this->authorizePost($r),
            'access_token' => $this->tokenEndpoint($r),
            'sso' => $get ? $this->ssoPage($r) : $this->ssoPost($r),
            'idp' => $get ? $this->idpPage($r) : $this->idpPost($r),
            default => throw new \LogicException('unrouted'),
        };
    }

    // --- authorization ---------------------------------------------------------------------------

    private function authorizePage(MintRequest $r): MintPlan
    {
        $clientId = (string) $r->queryStr('client_id');
        $redirect = $r->queryStr('redirect_uri');
        $scopes = array_values(array_diff(ScopeSet::parseParam((string) $r->queryStr('scope')), ['admin:org']));
        $stateParam = $r->queryStr('state');
        $state = $stateParam !== null && preg_match(self::STATE, $stateParam) === 1 ? $stateParam : null;

        return $this->flow->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($clientId, $redirect, $scopes, $state) {
            $ap = preg_match('/\A[a-f0-9]{20}\z/', $clientId) === 1 ? $s->appPosByClientId($pos, $clientId) : null;
            if ($ap === null) {
                return MintPlan::html(404, $this->c->pages->notFound(true, 'app_not_found'))->attribute(['outcome' => 'unknown_client']);
            }
            $app = $s->d['a'][$pos]['ap'][$ap];
            if ($redirect !== null && $redirect !== '' && !hash_equals((string) $app['cb'], $redirect)) {
                return MintPlan::html(400, $this->c->pages->error('Redirect URI mismatch', MintVocabulary::text('redirect_mismatch'), '/settings/applications', 'Back to applications'))->attribute(['outcome' => 'redirect_mismatch']);
            }
            $n = (int) $s->d['rn'];
            $s->d['rn'] = $n + 1;
            $id = $this->c->requestId($sess['kref'], $s, $n);
            $s->addRequest(['id' => $id, 'k' => 'authz', 'a' => (int) $s->d['a'][$pos]['i'], 'ap' => (int) $app['n'], 'sc' => $scopes, 'st' => $state, 'c' => $now]);
            $page = $this->c->pages->consent((string) $app['nm'], $scopes, $this->flow->csrf($sess, 'authorize', $s, $pos, $now), $id);

            return [MintPlan::html(200, $page)->with('Cache-Control', 'no-store')->attribute(['outcome' => 'consent']), false];
        }, true, '/settings/applications', MintContext::COST_GET);
    }

    private function authorizePost(MintRequest $r): MintPlan
    {
        return $this->flow->withSession($r, function (MintState $s, int $pos, array $sess, int $now, ?TokenMintTx $tx) use ($r) {
            $a = $s->d['a'][$pos];
            $serial = (int) $a['i'];
            $s->pushMintPost($serial, $now);
            $issued = $this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'authorize', (int) $a['ce'], $now);
            if ($issued === null) {
                return [$this->flow->csrfFailure('/settings/applications'), false];
            }
            $reqId = (string) $r->str('authorization_request');
            $rp = preg_match('/\A[a-f0-9]{12}\z/', $reqId) === 1 ? $s->requestPos($reqId, $serial) : null;
            $req = $rp !== null ? $s->d['r'][$rp] : null;
            $ap = $req !== null && $req['k'] === 'authz' ? $s->appPosBySerial($pos, (int) $req['ap']) : null;
            if ($req === null || $ap === null) {
                return [MintPlan::html(404, $this->c->pages->notFound(true, 'app_not_found'))->attribute(['outcome' => 'unknown_request']), false];
            }
            $app = $a['ap'][$ap];
            if ($r->str('deny') !== null) {
                array_splice($s->d['r'], (int) $rp, 1);

                return [MintPlan::html(200, $this->c->pages->denied((string) $app['nm']))->attribute(['outcome' => 'denied']), true];
            }
            $scopes = ScopeSet::normalise((array) $req['sc']);
            $sensitive = ScopeSet::anySensitive($scopes);
            if ($sensitive && $a['tf'] === null) {
                return [MintPlan::html(422, $this->c->pages->error('Two-factor authentication required', MintVocabulary::text('scope_2fa'), '/settings/security', 'Set up two-factor authentication')), false];
            }
            if ($sensitive && (int) $a['cu'] <= $now) {
                $s->d['a'][$pos]['rt'] = '/settings/applications';

                return [MintPlan::redirect('/settings/confirm', $this->c->persona)->attribute(['outcome' => 'needs_confirm']), true];
            }
            if ((int) $a['ru'] > $now) {
                return [$this->c->throttledPlan((int) $a['ru'] - $now, false), false];
            }
            $shape = 'authorize|' . implode(',', $scopes);
            $kind = $this->flow->pick($s, $pos, $sess, $now, $issued, $sensitive, $shape);
            $phantom = $this->flow->applyPhantom($s, $pos, $sess, $now, $kind, $shape, '/settings/applications', '/settings/applications');
            if ($phantom !== null) {
                return [$phantom->attribute(['friction' => $kind, 'scopes' => implode(' ', $scopes), 'kind' => 'code']), true];
            }
            if ($tx === null) {
                throw new \LogicException('a code is issued only inside a transaction');
            }
            $cn = (int) ($a['cn'] ?? 0);
            $s->d['a'][$pos]['cn'] = $cn + 1;
            $code = $this->c->oauthCode($sess['kref'], $s, $serial, $cn);
            $tx->insertCode($this->c->keys->secretHash($code), $serial, (int) $app['n'], $scopes, $reqId, $now + self::CODE_TTL_S);
            $state = is_string($req['st']) ? $req['st'] : null;
            array_splice($s->d['r'], (int) $rp, 1);
            $s->d['a'][$pos]['ch'] = $now;
            $s->pushOutcome($serial, FrictionPicker::SUCCESS, $now);

            return [MintPlan::html(200, $this->c->pages->code((string) $app['nm'], $code, $state))->with('Cache-Control', 'no-store')
                ->attribute(['outcome' => 'code', 'friction' => 'success', 'scopes' => implode(' ', $scopes), 'kind' => 'code']), true];
        }, true, '/settings/applications');
    }

    // --- token endpoint --------------------------------------------------------------------------

    private static function oauthError(string $error, int $status = 400): MintPlan
    {
        return MintPlan::json($status, ['error' => $error, 'error_description' => MintVocabulary::text('oauth_' . $error)])
            ->attribute(['outcome' => $error]);
    }

    private function tokenEndpoint(MintRequest $r): MintPlan
    {
        if ($r->badJson) {
            return self::oauthError('invalid_request');
        }
        [$clientId, $clientSecret] = $this->clientAuth($r);
        $grant = $r->str('grant_type');
        if ($grant === null || $grant === '') {
            return self::oauthError('invalid_request');
        }
        if ($grant === 'client_credentials') {
            return self::oauthError('unauthorized_client');
        }
        if ($grant === 'authorization_code') {
            $code = (string) $r->str('code');
            if (preg_match('/\A[a-f0-9]{20}\z/', $code) !== 1) {
                return $code === '' ? self::oauthError('invalid_request') : self::oauthError('invalid_grant');
            }
            $h = $this->c->keys->secretHash($code);
            $row = $this->c->store->codeRow($h);

            return $row === null ? self::oauthError('invalid_grant') : $this->exchange($r, (string) $row['k'], $h, $clientId, $clientSecret, false);
        }
        if ($grant === 'refresh_token') {
            $rt = (string) $r->str('refresh_token');
            if ($rt === '' || $this->c->tokens->decode($rt) === null) {
                return $rt === '' ? self::oauthError('invalid_request') : self::oauthError('invalid_grant');
            }
            $h = $this->c->keys->secretHash($rt);
            $row = $this->c->store->refreshRow($h);

            return $row === null ? self::oauthError('invalid_grant') : $this->exchange($r, (string) $row['k'], $h, $clientId, $clientSecret, true);
        }

        return self::oauthError('unsupported_grant_type');
    }

    /** @return array{0:string,1:string} client id and secret from the body or HTTP Basic */
    private function clientAuth(MintRequest $r): array
    {
        $id = (string) $r->str('client_id');
        $secret = (string) $r->str('client_secret');
        $basic = $r->header('Authorization');
        if ($basic !== null && strlen($basic) <= 512 && stripos($basic, 'basic ') === 0) {
            $raw = base64_decode(substr($basic, 6), true);
            if (is_string($raw) && str_contains($raw, ':')) {
                [$id, $secret] = explode(':', $raw, 2);
            }
        }

        return [$id, $secret];
    }

    private function exchange(MintRequest $r, string $k, string $h, string $clientId, string $clientSecret, bool $refresh): MintPlan
    {
        $now = $this->c->now();
        if (preg_match('/\A[a-f0-9]{32}\z/', $k) !== 1) {
            return self::oauthError('invalid_grant');
        }
        $kref = (string) hex2bin($k);
        [, $k8] = MintContext::rowKeys($kref);
        $wanted = $r->str('scope');
        $redirect = $r->str('redirect_uri');
        $res = $this->c->store->transact($k, $k8, $now, function (?MintState $s, TokenMintTx $tx) use ($kref, $h, $clientId, $clientSecret, $refresh, $wanted, $redirect, $now) {
            $units = MintContext::charge($tx, MintContext::COST_TOKEN);
            if (($over = $this->c->overUnits($tx, MintContext::COST_TOKEN, true)) !== null) {
                return MintContext::out(null, false, $units, $over);
            }
            $side = $refresh ? $this->c->store->refreshRow($h) : $this->c->store->codeRow($h);
            $pos = $s !== null && $side !== null ? $s->accountPosBySerial((int) $side['acct']) : null;
            $ap = $pos !== null ? $s->appPosBySerial($pos, (int) $side['app']) : null;
            if ($pos === null || $ap === null) {
                return MintContext::out(null, false, $units, self::oauthError('invalid_grant'));
            }
            $app = $s->d['a'][$pos]['ap'][$ap];
            // A grant issued to another client reads exactly like one that does not exist.
            if (!hash_equals((string) $app['ci'], $clientId)) {
                return MintContext::out(null, false, $units, self::oauthError('invalid_grant'));
            }
            $secretOk = false;
            foreach ($app['sx'] as $sx) {
                if (hash_equals((string) $sx[1], $this->c->keys->secretHash($clientSecret))) {
                    $secretOk = true;
                }
            }
            if (!$secretOk) {
                return MintContext::out(null, false, $units, self::oauthError('invalid_client', 401));
            }
            if (!$refresh && $redirect !== null && $redirect !== '' && !hash_equals((string) $app['cb'], $redirect)) {
                return MintContext::out(null, false, $units, self::oauthError('invalid_grant'));
            }
            $granted = array_values(array_filter(explode(' ', (string) $side['scopes']), static fn (string $x): bool => $x !== ''));
            $scopes = $granted;
            if ($refresh && $wanted !== null && $wanted !== '') {
                $asked = ScopeSet::parseParam($wanted);
                if (array_diff($asked, $granted) !== [] || $asked === []) {
                    return MintContext::out(null, false, $units, self::oauthError('invalid_scope'));
                }
                $scopes = $asked;
            }
            $consumed = $refresh ? $tx->consumeRefresh($h) : $tx->consumeCode($h);
            if ($consumed === null) {
                return MintContext::out(null, false, $units, self::oauthError('invalid_grant'));
            }
            // OAuth access tokens are capped per account; the oldest gives way.
            $oats = array_keys(array_filter($s->d['a'][$pos]['k'], static fn (array $t): bool => $t['k'] === 'oat'));
            if (count($oats) >= MintState::MAX_OAUTH_TOKENS) {
                array_splice($s->d['a'][$pos]['k'], (int) $oats[0], 1);
            }
            [, $access] = $this->c->addToken($s, $pos, $kref, 'oat', '', $scopes, $now + self::ACCESS_TTL_S, (int) $app['n'], $now);
            $rn = (int) ($s->d['a'][$pos]['rn'] ?? 0);
            $s->d['a'][$pos]['rn'] = $rn + 1;
            $refreshToken = $this->refreshToken($kref, $s, $pos, $rn);
            $tx->insertRefresh($this->c->keys->secretHash($refreshToken), (int) $s->d['a'][$pos]['i'], (int) $app['n'], $scopes, $now + self::REFRESH_TTL_S);
            $plan = MintPlan::json(200, [
                'access_token' => $access,
                'token_type' => 'bearer',
                'scope' => implode(' ', $scopes),
                'expires_in' => self::ACCESS_TTL_S,
                'refresh_token' => $refreshToken,
            ])->attribute(['outcome' => $refresh ? 'refreshed' : 'exchanged', 'scopes' => implode(' ', $scopes), 'kind' => 'oat']);

            return MintContext::out($s, true, $units, $plan);
        });
        if ($res['ok']) {
            return $res['value'];
        }

        return MintPlan::json(429, ['message' => MintVocabulary::text('api_retry')])->with('Retry-After', '5')->attribute(['outcome' => 'store_failure']);
    }

    private function refreshToken(string $kref, MintState $s, int $pos, int $rn): string
    {
        $a = $s->d['a'][$pos];
        $t = '';
        for ($v = 0; $v < 64; $v++) {
            $t = $this->c->tokens->encode('ort', substr($kref, 0, 8), ((int) $a['i']) % 256, $rn % 256, $s->epoch() . '|' . $a['i'] . '|r' . $rn . '|' . $v);
            if (\Funnypot\App\Tarpit\InertSecret::isClean('"' . $t . '"')) {
                break;
            }
        }

        return $t;
    }

    // --- organisation SSO ------------------------------------------------------------------------

    private function ssoPage(MintRequest $r): MintPlan
    {
        $reqId = (string) $r->queryStr('authorization_request');

        return $this->flow->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($reqId): MintPlan {
            $serial = (int) $s->d['a'][$pos]['i'];
            $rp = preg_match('/\A[a-f0-9]{12}\z/', $reqId) === 1 ? $s->requestPos($reqId, $serial) : null;
            $req = $rp !== null && in_array($s->d['r'][$rp]['k'], ['sso', 'approval'], true) ? $s->d['r'][$rp] : null;
            $approval = $req !== null && $req['k'] === 'approval';
            $appName = null;
            if ($approval) {
                $ap = $s->appPosBySerial($pos, (int) $req['ap']);
                $appName = $ap !== null ? (string) $s->d['a'][$pos]['ap'][$ap]['nm'] : null;
                $approval = $appName !== null;
            }

            return MintPlan::html(200, $this->c->pages->sso($this->flow->csrf($sess, 'sso', $s, $pos, $now), $req !== null ? (string) $req['id'] : '', $approval, $appName));
        }, false, '/');
    }

    private function ssoPost(MintRequest $r): MintPlan
    {
        return $this->flow->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            $serial = (int) $s->d['a'][$pos]['i'];
            if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'sso', (int) $s->d['a'][$pos]['ce'], $now) === null) {
                return $this->flow->csrfFailure('/orgs/' . $this->c->persona->slug . '/sso');
            }
            $reqId = (string) $r->str('authorization_request');
            $rp = preg_match('/\A[a-f0-9]{12}\z/', $reqId) === 1 ? $s->requestPos($reqId, $serial) : null;
            if ($rp !== null && $s->d['r'][$rp]['k'] === 'approval' && $s->appPosBySerial($pos, (int) $s->d['r'][$rp]['ap']) !== null) {
                $s->d['r'][$rp]['st'] = 'requested';

                return [MintPlan::html(200, $this->c->pages->approvalRequested())->attribute(['outcome' => 'approval_requested']), true];
            }

            return MintPlan::redirect('/idp/' . $this->c->persona->slug . '/signin', $this->c->persona)->attribute(['outcome' => 'to_idp']);
        }, true, '/');
    }

    // --- identity provider -----------------------------------------------------------------------

    private function idpPage(MintRequest $r): MintPlan
    {
        $kref = $this->c->keys->kref($r->ip);

        return MintPlan::html(200, $this->c->pages->idp($this->c->csrfToken($kref, 'idp', 0, $this->c->now()), null, []));
    }

    private function idpPost(MintRequest $r): MintPlan
    {
        $now = $this->c->now();
        $kref = $this->c->keys->kref($r->ip);
        $user = (string) $r->str('username');
        $values = strlen($user) <= 160 && (preg_match(MintForms::EMAIL, $user) === 1 || preg_match(MintForms::USERNAME, $user) === 1) ? ['username' => $user] : [];
        $page = fn (string $err, int $status = 200): MintPlan => MintPlan::html($status, $this->c->pages->idp($this->c->csrfToken($kref, 'idp', 0, $now), $err, $values))->attribute(['outcome' => $err]);
        if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $kref, 'idp', 0, $now) === null) {
            return $page('csrf', 422);
        }
        [$k, $k8] = MintContext::rowKeys($kref);
        $res = $this->c->store->transact($k, $k8, $now, function (?MintState $s, TokenMintTx $tx) use ($kref, $user, $now, $page) {
            $units = MintContext::charge($tx, MintContext::COST_SIGNIN);
            if (($over = $this->c->overUnits($tx, MintContext::COST_SIGNIN, false)) !== null) {
                return MintContext::out(null, false, $units, $over);
            }
            $state = $s ?? $this->c->newState($kref, $now);
            if ($state->idpFails($now, 900) >= MintState::MAX_IDP_FAILS) {
                return MintContext::out($s, false, $units, $page('idp_locked'));
            }
            $state->pushIdpFail($now);
            $own = $user !== '' && $state->accountPosByLogin($user) !== null;

            return MintContext::out($state, true, $units, $page($own ? 'idp_unassigned' : 'idp_invalid'));
        });

        return $res['ok'] ? $res['value'] : $page('signin_failed');
    }
}

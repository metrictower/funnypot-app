<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\App\Storage\TokenMintTx;

/**
 * The member API under both `/api/v2/` and `/v2/` (one table, byte-identical bodies), plus its
 * password login.
 *
 * A credential is a bearer or `X-API-Key` value (a personal or OAuth access token, or a login JWT),
 * or the deprecated `access_token` query parameter. It authenticates for real; what it can reach is
 * {@see AuthzPolicy}'s member view, so the one call that matters always ends at a scope, single
 * sign-on or owner-approval 403. Authentication comes before every existence check, and an answer
 * that reveals no stored object is logged as not served, like the miss it replaces.
 *
 * The login answers a persona member's username with the SSO 403 without looking at the password, so
 * a leaked password is neither confirmed nor refuted.
 */
final class MintApi
{
    public const RATE_LIMIT = 5000;
    public const SECONDARY_PER_60S = 30;

    /** Endpoints whose path carries an object name. */
    private const PATTERN_ENDPOINTS = ['users_login', 'orgs_org', 'orgs_members', 'orders_id'];

    public function __construct(private MintContext $c, private DecoyPrincipalResolver $principals)
    {
    }

    public function handle(MintRequest $r): MintPlan
    {
        if ($r->route === 'auth_login') {
            return $this->login($r);
        }
        if ($r->badJson) {
            return MintPlan::json(400, ['message' => MintVocabulary::text('api_invalid_body'), 'documentation_url' => '/docs/api'])->attribute(['outcome' => 'bad_body']);
        }
        $now = $this->c->now();
        [$cred, $deprecated] = $this->principals->bearer($r, $now);
        $method = $r->readMethod();
        $decision = AuthzPolicy::decide($r->route, $method, $cred === null ? null : ['kind' => $cred['kind'], 'scopes' => $cred['scopes'] ?? []]);
        if ($cred === null || $cred['kind'] === 'bad') {
            return $this->unauthorized($decision['decision'], $deprecated);
        }

        $res = $this->c->store->transact($cred['k'], $cred['k8'], $now, function (?MintState $s, TokenMintTx $tx) use ($r, $cred, $method, $now, $deprecated) {
            $units = MintContext::charge($tx, MintContext::COST_API);
            if (($over = $this->c->overUnits($tx, MintContext::COST_API, true)) !== null) {
                return MintContext::out(null, false, $units, $over);
            }
            [$plan, $change] = $this->answer($r, $s, $cred, $method, $now, $deprecated, true);

            return MintContext::out($s, $change, $units, $plan);
        });
        if ($res['ok']) {
            return $res['value'];
        }
        if ($method !== 'GET') {
            return MintPlan::json(429, ['message' => MintVocabulary::text('api_retry')])->with('Retry-After', '5')->attribute(['outcome' => 'store_failure']);
        }
        // A read whose counter update failed still answers, from the last committed state.
        [$plan] = $this->answer($r, $this->c->store->load($cred['k']), $cred, $method, $now, $deprecated, false);

        return $plan;
    }

    private function unauthorized(string $decision, bool $deprecated): MintPlan
    {
        $key = $decision === 'bad_credentials' ? 'api_bad_credentials' : 'api_auth';
        $plan = MintPlan::json(401, ['message' => MintVocabulary::text($key), 'documentation_url' => '/docs/api'], false)
            ->with('WWW-Authenticate', 'Bearer realm="' . $this->c->persona->company . ' API"')
            ->attribute(['outcome' => $key]);

        return $deprecated ? $plan->with('Deprecation', 'true') : $plan;
    }

    /**
     * @param array<string,mixed> $cred
     * @return array{0:MintPlan,1:bool}
     */
    private function answer(MintRequest $r, ?MintState $s, array $cred, string $method, int $now, bool $deprecated, bool $live): array
    {
        $pos = $s !== null ? $s->accountPosBySerial((int) $cred['acct']) : null;
        $tpos = null;
        if ($pos !== null && $cred['kind'] !== 'jwt') {
            foreach ($s->d['a'][$pos]['k'] as $i => $t) {
                if ((int) $t['n'] === (int) $cred['tn'] && $t['k'] === $cred['kind'] && ((int) $t['x'] === 0 || (int) $t['x'] > $now)) {
                    $tpos = $i;
                }
            }
        }
        if ($s === null || $pos === null || ($cred['kind'] !== 'jwt' && $tpos === null)) {
            return [$this->unauthorized('bad_credentials', $deprecated), false];
        }
        $a = $s->d['a'][$pos];
        $serial = (int) $a['i'];
        $scopes = $tpos !== null ? (array) $a['k'][$tpos]['sc'] : ['read:user'];

        $pattern = in_array($r->route, self::PATTERN_ENDPOINTS, true);
        if ($s->apiCalls($serial, $now, 60) >= self::SECONDARY_PER_60S) {
            $plan = MintPlan::json(429, ['message' => MintVocabulary::text('api_secondary'), 'documentation_url' => '/docs/api'], !$pattern)->with('Retry-After', '60')->attribute(['outcome' => 'secondary_limit']);

            return [$this->withRate($plan, $s, $pos, $tpos, $now, $deprecated, false), false];
        }
        $s->pushApi($serial, $now);
        if ($tpos !== null) {
            $s->d['a'][$pos]['k'][$tpos]['lu'] = $now;
        }
        $decision = AuthzPolicy::decide($r->route, $method, ['kind' => $cred['kind'], 'scopes' => $scopes]);
        $change = false;
        switch ($decision['decision']) {
            case 'scope':
                $need = $decision['required'][0];
                $plan = MintPlan::json(403, [
                    'message' => MintVocabulary::text('api_scope', ['scope' => $need]),
                    'required_scopes' => $decision['required'],
                    'documentation_url' => '/docs/api',
                ], !$pattern)->with('X-Required-Scopes', implode(', ', $decision['required']))->attribute(['outcome' => 'scope_403']);
                break;
            case 'sso':
                $id = $this->wallRequest($s, $pos, $cred, 'sso', null, $now, $live);
                $url = '/orgs/' . $this->c->persona->slug . '/sso?authorization_request=' . $id;
                $plan = MintPlan::json(403, [
                    'message' => MintVocabulary::text('api_sso', ['company' => $this->c->persona->company]),
                    'sso_url' => $url,
                    'documentation_url' => '/docs/api',
                ], !$pattern)->with('X-SSO', 'required; url=' . $url)->attribute(['outcome' => 'sso_403']);
                break;
            case 'approval':
                $appSerial = (int) $a['k'][(int) $tpos]['ap'];
                $ap = $s->appPosBySerial($pos, $appSerial);
                $appName = $ap !== null ? (string) $a['ap'][$ap]['nm'] : 'this application';
                $id = $this->wallRequest($s, $pos, $cred, 'approval', $appSerial, $now, $live);
                $plan = MintPlan::json(403, [
                    'message' => MintVocabulary::text('api_approval', ['app' => $appName, 'company' => $this->c->persona->company]),
                    'approval_url' => '/orgs/' . $this->c->persona->slug . '/sso?authorization_request=' . $id,
                    'documentation_url' => '/docs/api',
                ], !$pattern)->attribute(['outcome' => 'approval_403']);
                break;
            case 'method':
                $plan = MintPlan::json(405, ['message' => MintVocabulary::text('method')])->with('Allow', implode(', ', AuthzPolicy::methods($r->route)));
                break;
            default:
                [$plan, $change] = $this->ok($r, $s, $pos, $method, $now, $cred);
        }

        return [$this->withRate($plan, $s, $pos, $tpos, $now, $deprecated, $live), $change];
    }

    /**
     * @param array<string,mixed> $cred
     * @return array{0:MintPlan,1:bool}
     */
    private function ok(MintRequest $r, MintState $s, int $pos, string $method, int $now, array $cred): array
    {
        $a = $s->d['a'][$pos];
        switch ($r->route) {
            case 'user':
                if ($method === 'PATCH') {
                    // A field that is absent, or not a string, keeps its stored value.
                    $name = $r->str('name') ?? (string) $a['nm'];
                    $bio = $r->str('bio') ?? (string) $a['bi'];
                    $errors = MintForms::profile($name, $bio);
                    if ($errors !== []) {
                        return [MintPlan::json(422, ['message' => MintVocabulary::text('fields_invalid'), 'fields' => array_keys($errors), 'documentation_url' => '/docs/api'])->attribute(['outcome' => 'invalid']), false];
                    }
                    // Only name and bio are writable; role, admin flags and the rest are ignored.
                    $s->d['a'][$pos]['nm'] = (string) $name;
                    $s->d['a'][$pos]['bi'] = (string) $bio;
                    $s->d['a'][$pos]['ch'] = $now;

                    return [MintPlan::json(200, $this->profile($cred, $s, $pos))->attribute(['outcome' => 'profile_updated']), true];
                }

                return [MintPlan::json(200, $this->profile($cred, $s, $pos))->attribute(['outcome' => 'profile']), false];
            case 'user_orgs':
                return [MintPlan::json(200, [['login' => $this->c->persona->slug, 'name' => $this->c->persona->company, 'role' => 'member', 'sso_enforced' => true]])->attribute(['outcome' => 'orgs']), false];
            case 'user_orders':
                return [MintPlan::json(200, [])->attribute(['outcome' => 'own_orders']), false];
            case 'orgs_org':
                return [MintPlan::json(200, ['login' => $this->c->persona->slug, 'name' => $this->c->persona->company, 'type' => 'Organization', 'sso_enforced' => true])->attribute(['outcome' => 'org']), false];
            case 'users_login':
                $login = $r->id();
                $member = $this->c->persona->member($login);
                if ($member !== null) {
                    $name = $this->c->persona->members[$member];

                    return [MintPlan::json(200, ['login' => $member, 'name' => $name !== '' ? $name : null, 'type' => 'User'])->attribute(['outcome' => 'member']), false];
                }
                if (strcasecmp((string) $a['u'], $login) === 0) {
                    return [MintPlan::json(200, ['login' => (string) $a['u'], 'name' => (string) $a['nm'] !== '' ? (string) $a['nm'] : null, 'type' => 'User'])->attribute(['outcome' => 'self']), false];
                }

                return [MintPlan::json(404, ['message' => MintVocabulary::text('not_found'), 'documentation_url' => '/docs/api'], false)->attribute(['outcome' => 'not_found']), false];
            default:
                // Walled endpoints never get here; AuthzPolicy has answered them already.
                return [MintPlan::json(404, ['message' => MintVocabulary::text('not_found'), 'documentation_url' => '/docs/api'], false), false];
        }
    }

    /** @param array<string,mixed> $cred @return array<string,mixed> */
    private function profile(array $cred, MintState $s, int $pos): array
    {
        $a = $s->d['a'][$pos];

        return [
            'login' => (string) $a['u'],
            'id' => $this->c->accountNumber((string) $cred['kref'], $s, (int) $a['i']),
            'name' => (string) $a['nm'] !== '' ? (string) $a['nm'] : null,
            'bio' => (string) $a['bi'] !== '' ? (string) $a['bi'] : null,
            'email' => (string) $a['em'],
            'role' => 'member',
            'two_factor_enabled' => $a['tf'] !== null,
            'created_at' => gmdate('Y-m-d\TH:i:s\Z', (int) $a['c']),
        ];
    }

    /** Reuse or open the account's pending SSO or approval request; its id is server-made. */
    private function wallRequest(MintState $s, int $pos, array $cred, string $kind, ?int $app, int $now, bool $live): string
    {
        $serial = (int) $s->d['a'][$pos]['i'];
        foreach ($s->d['r'] as $req) {
            if ((int) $req['a'] === $serial && $req['k'] === $kind && ($app === null || (int) $req['ap'] === $app)) {
                return (string) $req['id'];
            }
        }
        $n = (int) $s->d['rn'];
        $id = $this->c->requestId((string) $cred['kref'], $s, $n);
        if ($live) {
            $s->d['rn'] = $n + 1;
            $s->addRequest(['id' => $id, 'k' => $kind, 'a' => $serial, 'ap' => $app, 'sc' => [], 'st' => null, 'c' => $now]);
        }

        return $id;
    }

    private function withRate(MintPlan $plan, MintState $s, int $pos, ?int $tpos, int $now, bool $deprecated, bool $count): MintPlan
    {
        $hour = intdiv($now, 3600);
        $rl = $tpos !== null ? $s->d['a'][$pos]['k'][$tpos]['rl'] : $s->d['a'][$pos]['rl'];
        $used = (int) $rl[0] === $hour ? (int) $rl[1] : 0;
        if ($count) {
            $used++;
            if ($tpos !== null) {
                $s->d['a'][$pos]['k'][$tpos]['rl'] = [$hour, $used];
            } else {
                $s->d['a'][$pos]['rl'] = [$hour, $used];
            }
        }
        $plan->with('X-RateLimit-Limit', (string) self::RATE_LIMIT)
            ->with('X-RateLimit-Remaining', (string) max(0, self::RATE_LIMIT - $used))
            ->with('X-RateLimit-Reset', (string) (($hour + 1) * 3600));
        if ($tpos !== null) {
            $plan->with('X-Token-Scopes', implode(', ', (array) $s->d['a'][$pos]['k'][$tpos]['sc']));
        }

        return $deprecated ? $plan->with('Deprecation', 'true') : $plan;
    }

    // --- password login --------------------------------------------------------------------------

    private function login(MintRequest $r): MintPlan
    {
        if ($r->badJson) {
            return MintPlan::json(400, ['message' => MintVocabulary::text('api_invalid_body'), 'documentation_url' => '/docs/api'])->attribute(['outcome' => 'bad_body']);
        }
        $user = $r->str('username') ?? $r->str('email');
        $pass = $r->str('password');
        // A member's username alone decides this answer: the password is never looked at.
        if ($user !== null && $this->c->persona->isMember($user)) {
            return MintPlan::json(403, ['message' => MintVocabulary::text('api_member_sso', ['company' => $this->c->persona->company]), 'documentation_url' => '/docs/api'])->attribute(['outcome' => 'member_sso']);
        }
        if ($user === null || $user === '' || $pass === null || $pass === '') {
            return MintPlan::json(400, ['message' => MintVocabulary::text('api_login_fields'), 'documentation_url' => '/docs/api'])->attribute(['outcome' => 'login_fields']);
        }
        $bad = MintPlan::json(401, ['message' => MintVocabulary::text('api_bad_credentials'), 'documentation_url' => '/docs/api'], false)->attribute(['outcome' => 'login_bad']);
        $now = $this->c->now();
        $kref = $this->c->keys->kref($r->ip);
        [$k, $k8] = MintContext::rowKeys($kref);
        $loaded = $this->c->store->load($k);
        if ($loaded === null || $loaded->accountPosByLogin($user) === null) {
            return $bad;
        }
        $res = $this->c->store->transact($k, $k8, $now, function (?MintState $s, TokenMintTx $tx) use ($user, $pass, $kref, $k8, $now, $bad) {
            $units = MintContext::charge($tx, MintContext::COST_SIGNIN);
            if (($over = $this->c->overUnits($tx, MintContext::COST_SIGNIN, true)) !== null) {
                return MintContext::out(null, false, $units, $over);
            }
            $pos = $s?->accountPosByLogin($user);
            if ($s === null || $pos === null || !hash_equals((string) $s->d['a'][$pos]['pw'], $this->c->pwHash($kref, $pass))) {
                return MintContext::out(null, false, $units, $bad);
            }
            $serial = (int) $s->d['a'][$pos]['i'];
            $jn = (int) ($s->d['a'][$pos]['jn'] ?? 0);
            $jwt = '';
            for ($v = 0; $v < 16; $v++) {
                $jwt = JwtCodec::encode([
                    'sub' => (string) $s->d['a'][$pos]['u'],
                    'a' => $serial,
                    'k8' => $k8,
                    'e' => $s->epoch(),
                    'scope' => 'read:user',
                    'iat' => $now,
                    'exp' => $now + JwtCodec::LIFETIME_S,
                    'jti' => $this->c->keys->hexId('jwt|' . $k8 . '|' . $serial . '|' . $jn . '|' . $v, 16),
                ], $this->c->keys->key('jwt'));
                if (\Funnypot\App\Tarpit\InertSecret::isClean('"' . $jwt . '"')) {
                    break;
                }
            }
            $s->d['a'][$pos]['jn'] = $jn + 1;
            $s->d['a'][$pos]['t'] = $now;

            return MintContext::out($s, false, $units, MintPlan::json(200, ['access_token' => $jwt, 'token_type' => 'bearer', 'expires_in' => JwtCodec::LIFETIME_S])->attribute(['outcome' => 'login_jwt', 'kind' => 'jwt']));
        });

        return $res['ok'] ? $res['value'] : MintPlan::json(429, ['message' => MintVocabulary::text('api_retry')])->with('Retry-After', '5')->attribute(['outcome' => 'store_failure']);
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Storage\TokenMintTx;

/**
 * The account pages: sign-up, sign-out, profile, two-factor enrolment, confirm-access, personal access
 * tokens and OAuth applications.
 *
 * Every page that reads an account runs in one transaction on the session's row, and every form that
 * changes one decides and writes before its answer exists, so the answer never shows a token, secret,
 * cookie or enrolment the store does not hold. A store failure on a form answers the coherent
 * "couldn't save" page (or the throttle page when a write cap was the cause); a read answers from the
 * last committed state without writing.
 *
 * The mint forms check everything true first, in stages (session, form token, fields, scopes,
 * throttle), and only then ask {@see FrictionPicker} whether this submission meets an obstacle. Each
 * obstacle is applied as a real state change.
 */
final class MintFlow
{
    public const MINT_ROUTES = ['token_create', 'app_create', 'app_secret', 'authorize'];

    public function __construct(private MintContext $c)
    {
    }

    public function handle(MintRequest $r): MintPlan
    {
        $get = $r->readMethod() === 'GET';

        return match ($r->route) {
            'join' => $get ? $this->joinPage($r) : $this->joinPost($r),
            'signout' => $get ? $this->page($r, fn (MintState $s, int $pos, array $sess, int $now): MintPlan => MintPlan::html(200, $this->c->pages->signout($this->csrf($sess, 'signout', $s, $pos, $now)))) : $this->signoutPost($r),
            'profile' => $get ? $this->page($r, fn (MintState $s, int $pos, array $sess, int $now): MintPlan => MintPlan::html(200, $this->c->pages->profile($s->d['a'][$pos], $this->csrf($sess, 'profile', $s, $pos, $now), [], [], null))) : $this->profilePost($r),
            'security' => $get ? $this->securityPage($r) : $this->securityPost($r),
            'confirm' => $get ? $this->page($r, fn (MintState $s, int $pos, array $sess, int $now): MintPlan => MintPlan::html(200, $this->c->pages->confirm($this->csrf($sess, 'confirm', $s, $pos, $now), $s->d['a'][$pos]['tf'] !== null, []))) : $this->confirmPost($r),
            'tokens' => $get ? $this->tokensPage($r) : $this->tokenCreate($r),
            'token_new' => $this->tokenNewPage($r),
            'token_delete' => $this->tokenDelete($r),
            'apps' => $get ? $this->appsPage($r) : $this->appCreate($r),
            'app_new' => $this->page($r, fn (MintState $s, int $pos, array $sess, int $now): MintPlan => MintPlan::html(200, $this->c->pages->appNew($this->csrf($sess, 'app_create', $s, $pos, $now), [], []))),
            'app_show' => $this->appShow($r),
            'app_secret' => $this->appSecret($r),
            'app_delete' => $this->appDelete($r),
            default => throw new \LogicException('unrouted'),
        };
    }

    // --- shared ----------------------------------------------------------------------------------

    /** @param array{kref:string,acct:int,sid:string,issuedAt:int} $sess */
    public function csrf(array $sess, string $formId, MintState $s, int $pos, int $now): string
    {
        return $this->c->csrfToken($sess['sid'], $formId, (int) $s->d['a'][$pos]['ce'], $now);
    }

    /** The answer to an account page without a live session: back to sign-in. */
    public function noSession(MintRequest $r): MintPlan
    {
        // On an id-bearing page this reveals nothing about the id, so it counts like a miss.
        return MintPlan::redirect('/', $this->c->persona, !$r->pattern)->attribute(['outcome' => 'no_session']);
    }

    /**
     * Run an account page or form in one transaction on the session's row.
     *
     * @param callable(MintState,int,array,int,?TokenMintTx):(MintPlan|array{0:MintPlan,1:bool}) $body
     *        returns the plan, or [plan, stateChange] for a form that changed the account
     */
    public function withSession(MintRequest $r, callable $body, bool $form, string $back, ?int $cost = null): MintPlan
    {
        $now = $this->c->now();
        $sess = $this->c->session($r, $now);
        if ($sess === null) {
            return $this->noSession($r);
        }
        [$k, $k8] = MintContext::rowKeys($sess['kref']);
        $cost ??= $form ? MintContext::COST_POST : MintContext::COST_GET;
        $res = $this->c->store->transact($k, $k8, $now, function (?MintState $s, TokenMintTx $tx) use ($r, $sess, $now, $cost, $body) {
            $units = MintContext::charge($tx, $cost);
            $pos = $this->c->liveAccount($s, $sess, $now);
            if (($over = $this->c->overUnits($tx, $cost, false, $pos !== null)) !== null) {
                return MintContext::out(null, false, $units, $over);
            }
            if ($s === null || $pos === null) {
                return MintContext::out(null, false, $units, $this->noSession($r));
            }
            $this->c->touchSession($s, $pos, $sess, $now);
            $out = $body($s, $pos, $sess, $now, $tx);
            [$plan, $change] = is_array($out) ? $out : [$out, false];

            return MintContext::out($s, $change, $units, $plan);
        });
        if ($res['ok']) {
            return $res['value'];
        }
        if (!$form) {
            $s = $this->c->store->load($k);
            $pos = $this->c->liveAccount($s, $sess, $now);
            if ($s === null || $pos === null) {
                return $this->noSession($r);
            }
            $out = $body($s, $pos, $sess, $now, null);

            return is_array($out) ? $out[0] : $out;
        }

        return $this->formFailure((string) $res['failure'], $back, true);
    }

    /** @param callable(MintState,int,array,int,?TokenMintTx):(MintPlan|array{0:MintPlan,1:bool}) $body */
    private function page(MintRequest $r, callable $body): MintPlan
    {
        return $this->withSession($r, $body, false, '/');
    }

    /** The coherent answer to a form whose save failed: nothing changed, try again. */
    public function formFailure(string $why, string $back, bool $signedIn): MintPlan
    {
        if ($why === TokenMintStore::FAIL_CAP) {
            return $this->c->throttledPlan(300, false, $signedIn)->attribute(['outcome' => 'store_cap']);
        }

        return MintPlan::html(422, $this->c->pages->error('Something went wrong', MintVocabulary::text('transient'), $back, 'Back', $signedIn))
            ->attribute(['outcome' => 'store_failure']);
    }

    public function csrfFailure(string $back, bool $signedIn = true): MintPlan
    {
        return MintPlan::html(422, $this->c->pages->error('Form expired', MintVocabulary::text('csrf'), $back, 'Reload the form', $signedIn))
            ->attribute(['outcome' => 'csrf']);
    }

    private function sessionAge(array $sess, int $now): int
    {
        return $now - (int) $sess['issuedAt'];
    }

    // --- sign-up and sign-out --------------------------------------------------------------------

    private function joinPage(MintRequest $r): MintPlan
    {
        $now = $this->c->now();
        $sess = $this->c->session($r, $now);
        if ($sess !== null) {
            [$k] = MintContext::rowKeys($sess['kref']);
            if ($this->c->liveAccount($this->c->store->load($k), $sess, $now) !== null) {
                return MintPlan::redirect('/', $this->c->persona);
            }
        }
        $kref = $this->c->keys->kref($r->ip);

        return MintPlan::html(200, $this->c->pages->join($this->c->csrfToken($kref, 'join', 0, $now), [], []));
    }

    private function joinPost(MintRequest $r): MintPlan
    {
        $now = $this->c->now();
        $kref = $this->c->keys->kref($r->ip);
        if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $kref, 'join', 0, $now) === null) {
            return $this->csrfFailure('/join', false);
        }
        $signedIn = $this->c->signedIn($r);
        [$k, $k8] = MintContext::rowKeys($kref);
        $res = $this->c->store->transact($k, $k8, $now, function (?MintState $s, TokenMintTx $tx) use ($r, $kref, $now, $signedIn) {
            $units = MintContext::charge($tx, MintContext::COST_POST);
            if (($over = $this->c->overUnits($tx, MintContext::COST_POST, false, $signedIn)) !== null) {
                return MintContext::out(null, false, $units, $over);
            }
            $state = $s ?? $this->c->newState($kref, $now);
            $username = $r->str('username');
            $email = $r->str('email');
            $errors = MintForms::join(
                $username,
                $email,
                $r->str('password'),
                $r->str('password_confirmation'),
                fn (string $u): bool => $state->accountPosByUsername($u) !== null || $this->c->persona->isMember($u),
                fn (string $e): bool => $state->emailTaken($e),
            );
            if ($errors !== []) {
                $values = [];
                foreach (['username' => MintForms::USERNAME, 'email' => MintForms::EMAIL] as $f => $re) {
                    $v = $r->str($f);
                    if ($v !== null && !isset($errors[$f]) && preg_match($re, $v) === 1) {
                        $values[$f] = $v;
                    }
                }
                $csrf = $this->c->csrfToken($kref, 'join', 0, $now);

                return MintContext::out(null, false, $units, MintPlan::html(422, $this->c->pages->join($csrf, $values, $errors))->attribute(['outcome' => 'invalid']));
            }
            $pos = $state->addAccount((string) $username, (string) $email, $this->c->pwHash($kref, (string) $r->str('password')), $now);
            $cookie = $this->c->startSession($state, $pos, $kref, $now);
            $plan = MintPlan::redirect('/', $this->c->persona)->with('Set-Cookie', $this->c->cookieHeader($cookie, $r->https))->attribute(['outcome' => 'joined']);

            return MintContext::out($state, true, $units, $plan);
        });

        return $res['ok'] ? $res['value'] : $this->formFailure((string) $res['failure'], '/join', $signedIn);
    }

    private function signoutPost(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'signout', (int) $s->d['a'][$pos]['ce'], $now) === null) {
                return $this->csrfFailure('/signout');
            }
            $sp = $s->sidPos($pos, bin2hex($sess['sid']));
            if ($sp !== null) {
                array_splice($s->d['a'][$pos]['s'], $sp, 1);
            }

            return [MintPlan::redirect('/', $this->c->persona)->with('Set-Cookie', $this->c->clearCookieHeader($r->https))->attribute(['outcome' => 'signed_out']), true];
        }, true, '/signout');
    }

    // --- profile, security, confirm --------------------------------------------------------------

    private function profilePost(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'profile', (int) $s->d['a'][$pos]['ce'], $now) === null) {
                return $this->csrfFailure('/settings/profile');
            }
            $name = $r->str('name');
            $bio = $r->str('bio');
            $errors = MintForms::profile($name, $bio);
            if ($errors !== []) {
                $values = [];
                foreach (['name' => $name, 'bio' => $bio] as $f => $v) {
                    if ($v !== null && !isset($errors[$f])) {
                        $values[$f] = $v;
                    }
                }

                return MintPlan::html(422, $this->c->pages->profile($s->d['a'][$pos], $this->csrf($sess, 'profile', $s, $pos, $now), $values, $errors, null))->attribute(['outcome' => 'invalid']);
            }
            $s->d['a'][$pos]['nm'] = (string) $name;
            $s->d['a'][$pos]['bi'] = (string) $bio;
            $s->d['a'][$pos]['ch'] = $now;

            return [MintPlan::html(200, $this->c->pages->profile($s->d['a'][$pos], $this->csrf($sess, 'profile', $s, $pos, $now), [], [], MintVocabulary::text('profile_saved')))->attribute(['outcome' => 'saved']), true];
        }, true, '/settings/profile');
    }

    private function securityPage(MintRequest $r): MintPlan
    {
        return $this->page($r, function (MintState $s, int $pos, array $sess, int $now): MintPlan {
            $a = $s->d['a'][$pos];
            $secret = $a['tf'] === null ? Totp::base32($this->c->totpSecret($this->sessKref($sess), $s, (int) $a['i'], (int) $a['te'])) : null;

            return MintPlan::html(200, $this->c->pages->security($a, $this->csrf($sess, 'security', $s, $pos, $now), $secret, [], null, null))->with('Cache-Control', 'no-store');
        });
    }

    private function securityPost(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            $a = $s->d['a'][$pos];
            if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'security', (int) $a['ce'], $now) === null) {
                return $this->csrfFailure('/settings/security');
            }
            if ($a['tf'] !== null) {
                return MintPlan::redirect('/settings/security', $this->c->persona);
            }
            $kref = $this->sessKref($sess);
            $enrol = (int) $a['te'];
            $secret = $this->c->totpSecret($kref, $s, (int) $a['i'], $enrol);
            $step = Totp::verify($secret, (string) $r->str('otp'), $now, 0);
            if ($step === null) {
                return MintPlan::html(422, $this->c->pages->security($a, $this->csrf($sess, 'security', $s, $pos, $now), Totp::base32($secret), ['otp' => 'otp_invalid'], null, null))
                    ->with('Cache-Control', 'no-store')->attribute(['outcome' => 'invalid']);
            }
            $codes = $this->c->recoveryCodes($kref, $s, (int) $a['i'], $enrol);
            $s->d['a'][$pos]['tf'] = ['e' => $enrol, 's' => $step, 'rc' => array_map(fn (string $c): string => substr($this->c->keys->secretHash($c), 0, 16), $codes)];
            $s->d['a'][$pos]['te'] = $enrol + 1;
            $s->d['a'][$pos]['ch'] = $now;
            $page = $this->c->pages->security($s->d['a'][$pos], $this->csrf($sess, 'security', $s, $pos, $now), null, [], $codes, MintVocabulary::text('twofa_enabled'));

            return [MintPlan::html(200, $page)->with('Cache-Control', 'no-store')->attribute(['outcome' => 'twofa_on']), true];
        }, true, '/settings/security');
    }

    private function confirmPost(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            $a = $s->d['a'][$pos];
            if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'confirm', (int) $a['ce'], $now) === null) {
                return $this->csrfFailure('/settings/confirm');
            }
            $kref = $this->sessKref($sess);
            $retry = fn (string $err): MintPlan => MintPlan::html(422, $this->c->pages->confirm($this->csrf($sess, 'confirm', $s, $pos, $now), $a['tf'] !== null, [$err === 'confirm_password' ? 'password' : 'otp' => $err]))->attribute(['outcome' => 'invalid']);
            if (!hash_equals((string) $a['pw'], $this->c->pwHash($kref, (string) $r->str('password')))) {
                return $retry('confirm_password');
            }
            if ($a['tf'] !== null) {
                $otp = $r->str('otp');
                $rc = $r->str('recovery_code');
                $step = $otp !== null && $otp !== '' ? Totp::verify($this->c->totpSecret($kref, $s, (int) $a['i'], (int) $a['tf']['e']), $otp, $now, (int) $a['tf']['s']) : null;
                if ($step !== null) {
                    $s->d['a'][$pos]['tf']['s'] = $step;
                } else {
                    $hit = $rc !== null && preg_match('/\A[a-z2-7]{5}-[a-z2-7]{5}\z/', $rc) === 1
                        ? array_search(substr($this->c->keys->secretHash($rc), 0, 16), $a['tf']['rc'], true)
                        : false;
                    if ($hit === false) {
                        return $retry('confirm_second');
                    }
                    array_splice($s->d['a'][$pos]['tf']['rc'], (int) $hit, 1);
                }
            }
            $s->d['a'][$pos]['cu'] = $now + 900;
            $to = (string) $a['rt'];
            $s->d['a'][$pos]['rt'] = '';
            if (!MintPlan::allowedLocation($to, $this->c->persona) || $to === '/settings/confirm') {
                $to = '/settings/tokens';
            }

            return [MintPlan::redirect($to, $this->c->persona)->attribute(['outcome' => 'confirmed']), true];
        }, true, '/settings/confirm');
    }

    /** The source reference a session belongs to. */
    private function sessKref(array $sess): string
    {
        return $sess['kref'];
    }

    // --- personal access tokens ------------------------------------------------------------------

    private function tokensPage(MintRequest $r): MintPlan
    {
        return $this->page($r, function (MintState $s, int $pos, array $sess, int $now): MintPlan {
            $a = $s->d['a'][$pos];
            $new = null;
            $notice = null;
            $fl = $a['fl'];
            if (is_array($fl) && isset($fl['tk'])) {
                foreach ($a['k'] as $i => $t) {
                    if ((int) $t['n'] === (int) $fl['tk']) {
                        $new = $this->c->tokenString($s, $pos, $i, $this->sessKref($sess));
                    }
                }
                $s->d['a'][$pos]['fl'] = null;
            } elseif (is_array($fl) && isset($fl['ntc'])) {
                $notice = MintVocabulary::text((string) $fl['ntc']);
                $s->d['a'][$pos]['fl'] = null;
            }
            $del = [];
            foreach ($a['k'] as $t) {
                $del[(string) $t['id']] = $this->c->csrfToken($sess['sid'], 'token_delete', (int) $a['ce'], $now);
            }

            return MintPlan::html(200, $this->c->pages->tokens($a['k'], $del, $new, $notice))->with('Cache-Control', 'no-store');
        });
    }

    private function tokenNewPage(MintRequest $r): MintPlan
    {
        $checked = ScopeSet::parseParam((string) $r->queryStr('scopes'));

        return $this->page($r, fn (MintState $s, int $pos, array $sess, int $now): MintPlan => MintPlan::html(200, $this->c->pages->tokenNew($this->csrf($sess, 'token_create', $s, $pos, $now), [], [], $checked, array_keys(ScopeSet::ALL))));
    }

    private function tokenCreate(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            $a = $s->d['a'][$pos];
            $serial = (int) $a['i'];
            $s->pushMintPost($serial, $now);
            $issued = $this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'token_create', (int) $a['ce'], $now);
            if ($issued === null) {
                return [$this->csrfFailure('/settings/tokens/new'), false];
            }
            $note = $r->str('note');
            $exp = $r->str('expiration');
            $scopes = $r->strList('scopes');
            $taken = static function (string $n) use ($a): bool {
                foreach ($a['k'] as $t) {
                    if ($t['k'] === 'pat' && strcasecmp((string) $t['nt'], $n) === 0) {
                        return true;
                    }
                }

                return false;
            };
            $errors = MintForms::token($note, $exp, $scopes, $taken);
            $norm = ScopeSet::normalise($scopes ?? []);
            $form = fn (array $err): MintPlan => MintPlan::html(422, $this->c->pages->tokenNew(
                $this->csrf($sess, 'token_create', $s, $pos, $now),
                array_filter(['note' => !isset($err['note']) ? $note : null, 'expiration' => $exp !== null && isset(MintForms::EXPIRATIONS[$exp]) ? $exp : null], static fn ($v): bool => $v !== null),
                $err,
                $norm,
                array_keys(ScopeSet::ALL),
            ))->attribute(['outcome' => 'invalid', 'scopes' => implode(' ', $norm)]);
            if ($errors !== []) {
                return [$form($errors), false];
            }
            if (in_array('admin:org', $norm, true)) {
                return [$form(['scopes' => 'scope_owner']), false];
            }
            $sensitive = ScopeSet::anySensitive($norm);
            if ($sensitive && $a['tf'] === null) {
                return [$form(['scopes' => 'scope_2fa'])->attribute(['outcome' => 'needs_2fa']), false];
            }
            if ($sensitive && (int) $a['cu'] <= $now) {
                $s->d['a'][$pos]['rt'] = '/settings/tokens';

                return [MintPlan::redirect('/settings/confirm', $this->c->persona)->attribute(['outcome' => 'needs_confirm']), true];
            }
            if ((int) $a['ru'] > $now) {
                return [$this->c->throttledPlan((int) $a['ru'] - $now, false, true), false];
            }
            if (count(array_filter($a['k'], static fn (array $t): bool => $t['k'] === 'pat')) >= MintState::MAX_TOKENS) {
                return [$form(['note' => 'token_limit']), false];
            }
            $shape = 'token_create|' . implode(',', $norm) . '|' . $exp . '|' . intdiv(strlen((string) $note), 10);
            $kind = $this->pick($s, $pos, $sess, $now, $issued, $sensitive, $shape);
            $phantom = $this->applyPhantom($s, $pos, $sess, $now, $kind, $shape, '/settings/tokens', '/settings/tokens/new');
            if ($phantom !== null) {
                return [$phantom->attribute(['friction' => $kind, 'scopes' => implode(' ', $norm), 'kind' => 'pat']), true];
            }
            [$tpos] = $this->c->addToken($s, $pos, $this->sessKref($sess), 'pat', (string) $note, $norm, $now + MintForms::EXPIRATIONS[(string) $exp] * 86400, null, $now);
            $s->d['a'][$pos]['fl'] = ['tk' => (int) $s->d['a'][$pos]['k'][$tpos]['n']];
            $s->d['a'][$pos]['ch'] = $now;
            $s->pushOutcome($serial, FrictionPicker::SUCCESS, $now);

            return [MintPlan::redirect('/settings/tokens', $this->c->persona)->attribute(['outcome' => 'minted', 'friction' => 'success', 'scopes' => implode(' ', $norm), 'kind' => 'pat']), true];
        }, true, '/settings/tokens/new');
    }

    private function tokenDelete(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            $a = $s->d['a'][$pos];
            if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'token_delete', (int) $a['ce'], $now) === null) {
                return $this->csrfFailure('/settings/tokens');
            }
            $tpos = $s->tokenPosById($pos, $r->id());
            if ($tpos === null) {
                return MintPlan::html(404, $this->c->pages->notFound(true), false)->attribute(['outcome' => 'not_found']);
            }
            array_splice($s->d['a'][$pos]['k'], $tpos, 1);
            $s->d['a'][$pos]['fl'] = ['ntc' => 'token_deleted'];
            $s->d['a'][$pos]['ch'] = $now;

            return [MintPlan::redirect('/settings/tokens', $this->c->persona)->attribute(['outcome' => 'deleted']), true];
        }, true, '/settings/tokens');
    }

    // --- friction --------------------------------------------------------------------------------

    /** @param array{kref:string,acct:int,sid:string,issuedAt:int} $sess */
    public function pick(MintState $s, int $pos, array $sess, int $now, int $formIssued, bool $sensitive, string $shape): string
    {
        $a = $s->d['a'][$pos];
        $serial = (int) $a['i'];
        $cu = (int) $a['cu'];
        $facts = [
            'form_age' => $now - $formIssued,
            'session_age' => $this->sessionAge($sess, $now),
            'sensitive' => $sensitive,
            'confirm_age' => $cu > $now ? $now - ($cu - 900) : null,
            'mint_posts_10min' => $s->mintPosts($serial, $now, 600),
            'changed_since_form' => (int) $a['ch'] > $formIssued,
        ];

        return $this->c->friction->pick($this->pickState($s, $pos, $now), $shape, $s->history($serial), FrictionPicker::eligible($facts), $sensitive);
    }

    /** @return array<string,int|bool> */
    public function pickState(MintState $s, int $pos, int $now): array
    {
        $a = $s->d['a'][$pos];
        $serial = (int) $a['i'];

        return [
            'csrf_epoch' => (int) $a['ce'],
            'two_factor_enabled' => $a['tf'] !== null,
            'confirm_active' => (int) $a['cu'] > $now,
            'rate_active' => (int) $a['ru'] > $now,
            'mint_posts_10min' => $s->mintPosts($serial, $now, 600),
            'successes_total' => min(15, $s->successes($serial)),
            'account_age_bucket' => min(24, intdiv(max(0, $now - (int) $a['c']), 3600)),
        ];
    }

    /**
     * Turn a picked obstacle into its state change and its answer; null for success.
     *
     * @param array{kref:string,acct:int,sid:string,issuedAt:int} $sess
     */
    public function applyPhantom(MintState $s, int $pos, array $sess, int $now, string $kind, string $shape, string $listPage, string $formPage): ?MintPlan
    {
        if ($kind === FrictionPicker::SUCCESS) {
            return null;
        }
        $serial = (int) $s->d['a'][$pos]['i'];
        $history = $s->history($serial);
        $state = $this->pickState($s, $pos, $now);
        $s->pushOutcome($serial, $kind, $now);
        switch ($kind) {
            case 'form_stale':
                $s->d['a'][$pos]['ce']++;

                return $this->csrfFailure($formPage);
            case 'session_lapsed':
                $sp = $s->sidPos($pos, bin2hex($sess['sid']));
                if ($sp !== null) {
                    array_splice($s->d['a'][$pos]['s'], $sp, 1);
                }
                $s->d['a'][$pos]['rt'] = $listPage;
                $s->d['sn'] = $now + 300;

                return MintPlan::redirect('/', $this->c->persona);
            case 'confirm_lapsed':
                $s->d['a'][$pos]['cu'] = $now;
                $s->d['a'][$pos]['rt'] = $listPage;

                return MintPlan::redirect('/settings/confirm', $this->c->persona);
            case 'throttled':
                $d = [60, 120, 300][$this->c->friction->draw('throttle', $state, $shape, $history, 3)];
                $s->d['a'][$pos]['ru'] = $now + $d;

                return $this->c->throttledPlan($d, false, true);
            case 'edit_conflict':
                $s->d['a'][$pos]['ce']++;

                return MintPlan::html(409, $this->c->pages->error('Edit conflict', MintVocabulary::text('edit_conflict'), $formPage, 'Review and resubmit', true));
            default:
                return MintPlan::html(422, $this->c->pages->error('Something went wrong', MintVocabulary::text('transient'), $formPage, 'Back', true));
        }
    }

    // --- OAuth applications ----------------------------------------------------------------------

    private function appsPage(MintRequest $r): MintPlan
    {
        return $this->page($r, function (MintState $s, int $pos): MintPlan {
            $a = $s->d['a'][$pos];
            $notice = null;
            if (is_array($a['fl']) && isset($a['fl']['ntc'])) {
                $notice = MintVocabulary::text((string) $a['fl']['ntc']);
                $s->d['a'][$pos]['fl'] = null;
            }

            return MintPlan::html(200, $this->c->pages->apps($a['ap'], $notice));
        });
    }

    private function appCreate(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            $a = $s->d['a'][$pos];
            $s->pushMintPost((int) $a['i'], $now);
            $issued = $this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'app_create', (int) $a['ce'], $now);
            if ($issued === null) {
                return [$this->csrfFailure('/settings/applications/new'), false];
            }
            $fields = ['name' => $r->str('name'), 'homepage_url' => $r->str('homepage_url'), 'callback_url' => $r->str('callback_url'), 'description' => $r->str('description')];
            $errors = MintForms::app($fields['name'], $fields['homepage_url'], $fields['callback_url'], $fields['description'], static function (string $n) use ($a): bool {
                foreach ($a['ap'] as $app) {
                    if (strcasecmp((string) $app['nm'], $n) === 0) {
                        return true;
                    }
                }

                return false;
            });
            if ($errors === [] && count($a['ap']) >= MintState::MAX_APPS) {
                $errors['name'] = 'app_limit';
            }
            if ($errors !== []) {
                $values = [];
                foreach ($fields as $f => $v) {
                    if ($v !== null && !isset($errors[$f])) {
                        $values[$f] = $v;
                    }
                }

                return [MintPlan::html(422, $this->c->pages->appNew($this->csrf($sess, 'app_create', $s, $pos, $now), $values, $errors))->attribute(['outcome' => 'invalid']), false];
            }
            if ((int) $a['ru'] > $now) {
                return [$this->c->throttledPlan((int) $a['ru'] - $now, false, true), false];
            }
            $shape = 'app_create|' . intdiv(strlen((string) $fields['name']), 10) . '|' . (str_starts_with((string) $fields['callback_url'], 'https') ? 's' : 'l');
            $kind = $this->pick($s, $pos, $sess, $now, $issued, false, $shape);
            $phantom = $this->applyPhantom($s, $pos, $sess, $now, $kind, $shape, '/settings/applications', '/settings/applications/new');
            if ($phantom !== null) {
                return [$phantom->attribute(['friction' => $kind]), true];
            }
            $kref = $this->sessKref($sess);
            $n = (int) $a['apn'];
            $s->d['a'][$pos]['apn'] = $n + 1;
            $id = $this->c->appPublicId($kref, $s, (int) $a['i'], $n);
            $s->d['a'][$pos]['ap'][] = [
                'n' => $n, 'id' => $id, 'nm' => (string) $fields['name'], 'hp' => (string) $fields['homepage_url'],
                'cb' => (string) $fields['callback_url'], 'ds' => (string) ($fields['description'] ?? ''),
                'ci' => $this->c->clientId($kref, $s, (int) $a['i'], $n), 'sx' => [], 'st' => 0, 'c' => $now,
            ];
            $s->d['a'][$pos]['fl'] = ['ntc' => 'app_created'];
            $s->d['a'][$pos]['ch'] = $now;
            $s->pushOutcome((int) $a['i'], FrictionPicker::SUCCESS, $now);

            return [MintPlan::redirect('/settings/applications/' . $id, $this->c->persona)->attribute(['outcome' => 'app_created', 'friction' => 'success']), true];
        }, true, '/settings/applications/new');
    }

    private function appShow(MintRequest $r): MintPlan
    {
        return $this->page($r, function (MintState $s, int $pos, array $sess, int $now) use ($r): MintPlan {
            $ap = $s->appPosById($pos, $r->id());
            if ($ap === null) {
                return MintPlan::html(404, $this->c->pages->notFound(true), false)->attribute(['outcome' => 'not_found']);
            }
            $a = $s->d['a'][$pos];
            $app = $a['ap'][$ap];
            $secret = null;
            $notice = null;
            $fl = $a['fl'];
            if (is_array($fl) && isset($fl['sc']) && (int) $fl['sc'][0] === (int) $app['n']) {
                $secret = $this->c->clientSecret($this->sessKref($sess), $s, (int) $a['i'], (int) $app['n'], (int) $fl['sc'][1]);
                $s->d['a'][$pos]['fl'] = null;
            } elseif (is_array($fl) && isset($fl['ntc'])) {
                $notice = MintVocabulary::text((string) $fl['ntc']);
                $s->d['a'][$pos]['fl'] = null;
            }

            return MintPlan::html(200, $this->c->pages->appShow(
                $app,
                $this->csrf($sess, 'app_secret', $s, $pos, $now),
                $this->csrf($sess, 'app_delete', $s, $pos, $now),
                $secret,
                $notice,
            ))->with('Cache-Control', 'no-store');
        });
    }

    private function appSecret(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now) use ($r) {
            $a = $s->d['a'][$pos];
            $s->pushMintPost((int) $a['i'], $now);
            $issued = $this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'app_secret', (int) $a['ce'], $now);
            if ($issued === null) {
                return [$this->csrfFailure('/settings/applications'), false];
            }
            $ap = $s->appPosById($pos, $r->id());
            if ($ap === null) {
                return [MintPlan::html(404, $this->c->pages->notFound(true), false)->attribute(['outcome' => 'not_found']), false];
            }
            $app = $a['ap'][$ap];
            $page = '/settings/applications/' . $app['id'];
            if ((int) $a['cu'] <= $now) {
                $s->d['a'][$pos]['rt'] = $page;

                return [MintPlan::redirect('/settings/confirm', $this->c->persona)->attribute(['outcome' => 'needs_confirm']), true];
            }
            if ((int) $a['ru'] > $now) {
                return [$this->c->throttledPlan((int) $a['ru'] - $now, false, true), false];
            }
            $shape = 'app_secret|' . count($app['sx']);
            $kind = $this->pick($s, $pos, $sess, $now, $issued, true, $shape);
            $phantom = $this->applyPhantom($s, $pos, $sess, $now, $kind, $shape, $page, $page);
            if ($phantom !== null) {
                return [$phantom->attribute(['friction' => $kind]), true];
            }
            $sn = (int) $app['st'];
            $raw = $this->c->clientSecret($this->sessKref($sess), $s, (int) $a['i'], (int) $app['n'], $sn);
            $s->d['a'][$pos]['ap'][$ap]['st'] = $sn + 1;
            $s->d['a'][$pos]['ap'][$ap]['sx'][] = [$sn, $this->c->keys->secretHash($raw), $now];
            $s->d['a'][$pos]['ap'][$ap]['sx'] = array_slice($s->d['a'][$pos]['ap'][$ap]['sx'], -MintState::MAX_SECRETS);
            $s->d['a'][$pos]['fl'] = ['sc' => [(int) $app['n'], $sn]];
            $s->d['a'][$pos]['ch'] = $now;
            $s->pushOutcome((int) $a['i'], FrictionPicker::SUCCESS, $now);

            return [MintPlan::redirect($page, $this->c->persona)->attribute(['outcome' => 'secret_created', 'friction' => 'success']), true];
        }, true, '/settings/applications');
    }

    private function appDelete(MintRequest $r): MintPlan
    {
        return $this->withSession($r, function (MintState $s, int $pos, array $sess, int $now, ?TokenMintTx $tx) use ($r) {
            $a = $s->d['a'][$pos];
            if ($this->c->csrf->verify($r->str(CsrfCodec::FIELD), $sess['sid'], 'app_delete', (int) $a['ce'], $now) === null) {
                return $this->csrfFailure('/settings/applications');
            }
            $ap = $s->appPosById($pos, $r->id());
            if ($ap === null) {
                return MintPlan::html(404, $this->c->pages->notFound(true), false)->attribute(['outcome' => 'not_found']);
            }
            $n = (int) $a['ap'][$ap]['n'];
            array_splice($s->d['a'][$pos]['ap'], $ap, 1);
            $s->d['a'][$pos]['k'] = array_values(array_filter($s->d['a'][$pos]['k'], static fn (array $t): bool => !($t['k'] === 'oat' && (int) $t['ap'] === $n)));
            $s->d['a'][$pos]['fl'] = ['ntc' => 'app_deleted'];
            $s->d['a'][$pos]['ch'] = $now;
            $tx?->revokeApp((int) $a['i'], $n);

            return [MintPlan::redirect('/settings/applications', $this->c->persona)->attribute(['outcome' => 'app_deleted']), true];
        }, true, '/settings/applications');
    }
}

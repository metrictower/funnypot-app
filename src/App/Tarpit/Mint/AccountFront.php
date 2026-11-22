<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Funnypot\App\Storage\TokenMintTx;
use Funnypot\Core\RequestContext;
use Throwable;

/**
 * The account surface's seam into the public `/` page. A live session gets the account home (its own
 * chrome, none of the sign-in page's hidden links). Signed out, the sign-in page gains one sign-up
 * link and, after a lapsed session, a notice. A sign-in POST naming an account this source created
 * signs in; anything else returns null so the caller answers exactly as it always has.
 *
 * Every method is fault-guarded: any failure here reads as "no account", which is today's answer.
 */
final class AccountFront
{
    public function __construct(private MintContext $c)
    {
    }

    public function home(RequestContext $ctx, string $ip): ?MintPlan
    {
        try {
            $r = MintRequest::parse($ctx, ['route' => 'home', 'methods' => ['GET'], 'params' => [], 'api' => false, 'pattern' => false], $ip);
            $now = $this->c->now();
            $sess = $this->c->session($r, $now);
            if ($sess === null) {
                return null;
            }
            [$k, $k8] = MintContext::rowKeys($sess['kref']);
            $render = function (MintState $s, int $pos): MintPlan {
                $a = $s->d['a'][$pos];
                $notice = is_array($a['fl']) && isset($a['fl']['ntc']) ? MintVocabulary::text((string) $a['fl']['ntc']) : null;

                return MintPlan::html(200, $this->c->pages->home($a, $notice))->attribute(['route' => 'home', 'outcome' => 'home']);
            };
            $res = $this->c->store->transact($k, $k8, $now, function (?MintState $s, TokenMintTx $tx) use ($sess, $now, $render) {
                $units = MintContext::charge($tx, MintContext::COST_GET);
                $pos = $this->c->liveAccount($s, $sess, $now);
                if (($over = $this->c->overUnits($tx, MintContext::COST_GET, false, $pos !== null)) !== null) {
                    return MintContext::out(null, false, $units, $over);
                }
                if ($s === null || $pos === null) {
                    return MintContext::out(null, false, $units, null);
                }
                $this->c->touchSession($s, $pos, $sess, $now);
                $plan = $render($s, $pos);
                if (is_array($s->d['a'][$pos]['fl']) && isset($s->d['a'][$pos]['fl']['ntc'])) {
                    $s->d['a'][$pos]['fl'] = null;
                }

                return MintContext::out($s, false, $units, $plan);
            });
            if ($res['ok']) {
                return $res['value'];
            }
            $s = $this->c->store->load($k);
            $pos = $this->c->liveAccount($s, $sess, $now);

            return $s !== null && $pos !== null ? $render($s, $pos) : null;
        } catch (Throwable $e) {
            TokenMintDecoy::logFault('home', $e);

            return null;
        }
    }

    /** HTML the signed-out sign-in page adds below its form. */
    public function signedOutExtra(RequestContext $ctx, string $ip): string
    {
        $notice = '';
        try {
            $s = $this->c->store->load(bin2hex($this->c->keys->kref($ip)));
            if ($s !== null && (int) $s->d['sn'] > $this->c->now()) {
                $notice = '<p class=err>' . AccountPages::e(MintVocabulary::text('session_expired')) . '</p>';
            }
        } catch (Throwable $e) {
            TokenMintDecoy::logFault('signed-out', $e);
            $notice = '';
        }

        return $notice . "<p style='font-size:.85rem;margin:1rem 0 0'><a href='/join'>Create an account</a></p>";
    }

    /**
     * Sign in to an account this source created.
     *
     * @return array{cookie:string}|array{error:string}|null null when no such account exists here
     */
    public function signIn(RequestContext $ctx, string $ip, string $user, string $pass): ?array
    {
        try {
            $now = $this->c->now();
            $kref = $this->c->keys->kref($ip);
            [$k, $k8] = MintContext::rowKeys($kref);
            $loaded = $this->c->store->load($k);
            if ($loaded === null || $loaded->accountPosByUsername($user) === null) {
                return null;
            }
            $https = $ctx->scheme === 'https';
            $res = $this->c->store->transact($k, $k8, $now, function (?MintState $s, TokenMintTx $tx) use ($kref, $user, $pass, $now, $https) {
                $units = MintContext::charge($tx, MintContext::COST_SIGNIN);
                if ($tx->unitsUsed + MintContext::COST_SIGNIN > MintContext::UNITS_PER_HOUR) {
                    return MintContext::out(null, false, $units, ['error' => 'signin_failed']);
                }
                $pos = $s?->accountPosByUsername($user);
                if ($s === null || $pos === null) {
                    return MintContext::out(null, false, $units, null);
                }
                if (!hash_equals((string) $s->d['a'][$pos]['pw'], $this->c->pwHash($kref, $pass))) {
                    return MintContext::out(null, false, $units, ['error' => 'signin_wrong']);
                }
                $cookie = $this->c->startSession($s, $pos, $kref, $now);
                if ((string) $s->d['a'][$pos]['rt'] !== '') {
                    $s->d['a'][$pos]['rt'] = '';
                }
                $s->d['sn'] = 0;

                return MintContext::out($s, true, $units, ['cookie' => $this->c->cookieHeader($cookie, $https)]);
            });

            return $res['ok'] ? $res['value'] : ['error' => 'signin_failed'];
        } catch (Throwable $e) {
            TokenMintDecoy::logFault('sign-in', $e);

            return null;
        }
    }
}

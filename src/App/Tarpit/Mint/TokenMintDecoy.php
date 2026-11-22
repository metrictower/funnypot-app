<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Closure;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Storage\TokenMintStore;
use Funnypot\Core\RequestContext;
use Throwable;

/**
 * The token-mint account surface as the honeypot controller sees it: a developer account at the
 * persona's company (sign-up, personal access tokens, OAuth applications, two-factor, a member API)
 * where every credential is real enough to use and none reaches anything that matters.
 *
 * It joins HoneypotController at the serve seam only: detection, logging and reporting run as for any
 * request, and prepare() replaces just the response body for a path in its closed set. owns() is a
 * function of the path alone. prepare() returns null for every other path, and also when its own code
 * fails for a reason other than the store (the controller then serves today's answer), which inputs
 * alone never cause; faults() counts those for the tests that pin it.
 */
final class TokenMintDecoy
{
    private MintRoutes $routes;
    private MintFlow $flow;
    private OAuthFlow $oauth;
    private MintApi $api;
    private int $faults = 0;
    private ?Throwable $lastFault = null;

    /** @var Closure(MintPlan):void */
    private Closure $emitter;

    /** @param Closure(MintPlan):void|null $emitter defaults to MintPlan::emit(); tests capture instead */
    public function __construct(private MintContext $c, private ?ProbeGate $probeGate = null, ?Closure $emitter = null)
    {
        $this->routes = new MintRoutes($c->persona->slug);
        $this->flow = new MintFlow($c);
        $this->oauth = new OAuthFlow($c, $this->flow);
        $this->api = new MintApi($c, new DecoyPrincipalResolver($c));
        $this->emitter = $emitter ?? static function (MintPlan $p): void {
            $p->emit();
        };
    }

    /**
     * @param Closure():int|null $clock
     * @param SurfaceExtension|null $ext what a wired sibling surface adds; none keeps every answer as is
     */
    public static function build(string $tokenMintKey, int $personaSeed, TokenMintStore $store, bool $friction, ?ProbeGate $gate = null, ?Closure $clock = null, ?Closure $emitter = null, ?SurfaceExtension $ext = null): self
    {
        return new self(
            new MintContext(new MintKeys($tokenMintKey), MintPersona::fromSeed($personaSeed), $store, $clock ?? static fn (): int => time(), $friction, $ext),
            $gate,
            $emitter,
        );
    }

    public function context(): MintContext
    {
        return $this->c;
    }

    public function owns(string $path): bool
    {
        return $this->routes->owns($path);
    }

    /**
     * The answer for an owned path, or null (not owned, or an internal fault: serve today's answer).
     * $issued is the engine check for this request; without one, any answer that would issue a value
     * is a fault.
     */
    public function prepare(RequestContext $ctx, string $ip, ?IssuedValue $issued = null): ?MintPlan
    {
        $match = $this->routes->match($ctx->path);
        if ($match === null) {
            return null;
        }
        $this->c->issuingWith($issued);
        try {
            $r = MintRequest::parse($ctx, $match, $ip);
            $plan = $this->dispatch($r);
            $plan->attribute(['route' => $r->route]);
            // On an id-bearing path, an answer that returns no object counts like the miss it replaces,
            // whatever the method. A form answer to a form token this surface signed (an expired or
            // used one included) is engagement with our own pages, which never counts.
            if ($r->pattern && self::nonDisclosing($plan)
                && !(in_array($plan->status, [422, 429], true) && $this->c->csrf->issuedByUs($r->str(CsrfCodec::FIELD)))) {
                $plan->served = false;
            }

            return $r->isHead() ? $plan->forHead() : $plan;
        } catch (Throwable $e) {
            $this->faults++;
            $this->lastFault = $e;
            self::logFault('prepare', $e);

            return null;
        } finally {
            $this->c->issuingWith(null);
        }
    }

    /** An answer that returns no stored object; a sibling surface applies the same rule to its own. */
    public static function nonDisclosing(MintPlan $p): bool
    {
        return in_array($p->status, [204, 401, 403, 404, 405, 413, 429], true)
            || ($p->status === 422 && ($p->turn['outcome'] ?? '') === 'csrf');
    }

    private function dispatch(MintRequest $r): MintPlan
    {
        $allowed = $r->methods;
        if (in_array('GET', $allowed, true)) {
            $allowed[] = 'HEAD';
        }
        $json = $r->api || $r->route === 'access_token';
        if ($r->method === 'OPTIONS') {
            return MintPlan::empty(204, $json ? MintPlan::JSON : MintPlan::HTML)->with('Allow', implode(', ', [...$allowed, 'OPTIONS']));
        }
        if (!in_array($r->method, $allowed, true)) {
            $plan = $json
                ? MintPlan::json(405, ['message' => MintVocabulary::text('method')])
                : MintPlan::html(405, $this->c->pages->methodNotAllowed($this->c->signedIn($r)));

            return $plan->with('Allow', implode(', ', $allowed))->attribute(['outcome' => 'method']);
        }
        if ($r->tooLarge) {
            return ($json
                ? MintPlan::json(413, ['message' => MintVocabulary::text('body_too_large')])
                : MintPlan::html(413, $this->c->pages->error('Request too large', MintVocabulary::text('body_too_large'), '/', 'Go home', $this->c->signedIn($r))))
                ->attribute(['outcome' => 'too_large']);
        }
        if ($r->route === 'docs') {
            return MintPlan::html(200, $this->c->pages->docs($this->c->signedIn($r)));
        }
        if ($r->api) {
            return $this->api->handle($r);
        }
        if (in_array($r->route, ['authorize', 'access_token', 'sso', 'idp'], true)) {
            return $this->oauth->handle($r);
        }

        return $this->flow->handle($r);
    }

    public function emit(MintPlan $plan): void
    {
        ($this->emitter)($plan);
    }

    /**
     * An answer that disclosed nothing counts toward the bulk-scan window like the miss it replaces,
     * so feed the bulk-scan pin exactly as the miss path would.
     */
    public function notServed(string $ip): void
    {
        try {
            $this->probeGate?->pinIfBulk($ip);
        } catch (Throwable $e) {
            // the pin is best-effort, as on the miss path
        }
    }

    /** Best-effort attribution after the answer is out. */
    public function attribute(MintPlan $plan, string $ip): void
    {
        [, $k8] = MintContext::rowKeys($this->c->keys->kref($ip));
        $this->c->store->attribute($k8, $this->c->now(), $plan->turn);
    }

    /**
     * An operator signal for a fault the surface stepped aside from: a fixed code, the exception class
     * and where it was thrown. Never the message, which could carry request bytes.
     */
    public static function logFault(string $where, Throwable $e): void
    {
        error_log(sprintf('funnypot: token-mint %s fault %s at %s:%d (code=token-mint-fault)', $where, get_class($e), basename($e->getFile()), $e->getLine()));
    }

    public function faults(): int
    {
        return $this->faults;
    }

    public function lastFault(): ?Throwable
    {
        return $this->lastFault;
    }
}

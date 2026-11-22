<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use Closure;
use Funnypot\App\Tarpit\InertSecret;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use LogicException;

/**
 * Whether a random value the surface issues, and expects back, is fit to issue. It must be
 * fingerprint-clean, and the request it comes back in must not be flagged: a value sent back as a
 * form field, a JSON string or a query parameter is part of the text the engine's attack rules scan, so
 * a token that happened to end in `env`, or a recovery code reading `qezso-xmlns`, would be logged and
 * reported as an attack on the visitor's own credential.
 *
 * The check asks the real engine rather than a word list, so it cannot drift from core. The value is put
 * in a synthetic request as a query parameter (followed by a space in the text the rules scan), as a
 * form field followed by `&`, as a JSON string, and in the Authorization, X-Api-Key and Cookie headers.
 * That request is sent on each path the value really travels to (a form token on its own form's action,
 * an access token on the API paths, a code on the token endpoint) and on a catch-all path ending in a
 * command-like word; a public id is also sent as a segment of each route it sits in. Each request goes
 * through core's content detection (`Honeypot::detect()`, which has no I/O, no delay and no logging) and
 * the app's fall-through classifier, and any match refuses the value. One engine pass costs about 0.6
 * to 1 ms, and a value takes one pass per path.
 *
 * A refused value is re-rolled by stepping a counter in its derivation, so the choice stays deterministic
 * per source and per core version. Only a few first picks in ten thousand are refused, too few for the
 * re-roll to leave a gap a visitor could see. Running out of the capped tries is a fault the surface's
 * fault boundary answers, never a flagged or unchecked value.
 */
final class IssuedValue
{
    /** @param Closure(RequestContext):bool $flags whether the engine would flag a request */
    public function __construct(private Closure $flags)
    {
    }

    /** The check the controller hands the surface for one request: core's detection, then the app's classifier. */
    public static function forEngine(Honeypot $engine, ?AttackClassifier $classifier): self
    {
        return new self(static function (RequestContext $r) use ($engine, $classifier): bool {
            $d = $engine->detect($r);

            return $d->matched || in_array('attack', $d->tags(), true) || $classifier?->classify($r) !== null;
        });
    }

    /**
     * Some of core's rules read the end of the path together with the end of a value (a path ending in a
     * command-like word, a value ending in `time`), so every value is also probed on a path that ends in
     * one, which covers a route the value may be replayed to.
     */
    public const CATCH_ALL = '/join';

    /** The synthetic request that carries a value in every field place a value travels in, on one path. */
    public static function probe(string $value, string $path = self::CATCH_ALL): RequestContext
    {
        return new RequestContext(
            'POST',
            $path,
            'q=' . $value,
            [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Authorization' => 'Bearer ' . $value,
                'X-Api-Key' => $value,
                'Cookie' => 'session=' . $value,
            ],
            'a=' . $value . '&b={"k":"' . $value . '"}',
        );
    }

    /** A request carrying the value as a path segment; $route is "METHOD /path" with `{v}` for the value. */
    public static function pathProbe(string $value, string $route): RequestContext
    {
        [$method, $path] = explode(' ', $route, 2);

        return new RequestContext($method, str_replace('{v}', $value, $path), '', ['Content-Type' => 'application/x-www-form-urlencoded'], $method === 'GET' ? null : 'csrf_token=x');
    }

    /**
     * @param list<string> $paths the paths the value is sent back to as a field (the catch-all is always added)
     * @param list<string> $routes the routes it travels in as a path segment
     */
    public function fit(string $value, array $paths = [], array $routes = []): bool
    {
        if (!InertSecret::isClean('"' . $value . '"') || !InertSecret::isClean("'" . $value . "'")) {
            return false;
        }
        foreach (array_unique([...$paths, self::CATCH_ALL]) as $path) {
            if (($this->flags)(self::probe($value, $path))) {
                return false;
            }
        }
        foreach ($routes as $route) {
            if (($this->flags)(self::pathProbe($value, $route))) {
                return false;
            }
        }

        return true;
    }

    /**
     * The first fit value of $gen(0), $gen(1), … (null skips a step). None within $tries is a fault the
     * surface's fault boundary answers, never a flagged or unchecked value.
     *
     * @param callable(int):?string $gen
     * @param list<string> $paths
     * @param list<string> $routes
     */
    public function first(int $tries, callable $gen, array $paths = [], array $routes = []): string
    {
        for ($i = 0; $i < $tries; $i++) {
            $value = $gen($i);
            if ($value !== null && $this->fit($value, $paths, $routes)) {
                return $value;
            }
        }

        throw new LogicException('no fit value within the tries');
    }
}

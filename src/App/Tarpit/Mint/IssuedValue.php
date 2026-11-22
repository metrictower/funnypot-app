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
 * in one synthetic request: as a query parameter (followed by a space in the text the rules scan), as a
 * form field followed by `&`, as a JSON string, and in the Authorization, X-Api-Key and Cookie headers; a
 * public id also goes as a path segment, in a second request. Each request goes through core's content
 * detection (`Honeypot::detect()`, which has no I/O, no delay and no logging) and the app's fall-through
 * classifier, and any match refuses the value. One engine pass costs about 0.6 to 1 ms.
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

    /** The synthetic request that carries a value in every place a value of the surface travels. */
    public static function probe(string $value): RequestContext
    {
        return new RequestContext(
            'POST',
            '/settings/tokens',
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

    /** The same for a value that travels as a path segment. */
    public static function pathProbe(string $value): RequestContext
    {
        return new RequestContext('GET', '/settings/tokens/' . $value . '/delete', '', []);
    }

    public function fit(string $value, bool $inPath = false): bool
    {
        return InertSecret::isClean('"' . $value . '"')
            && InertSecret::isClean("'" . $value . "'")
            && !($this->flags)(self::probe($value))
            && !($inPath && ($this->flags)(self::pathProbe($value)));
    }

    /**
     * The first fit value of $gen(0), $gen(1), … (null skips a step). None within $tries is a fault the
     * surface's fault boundary answers, never a flagged or unchecked value.
     *
     * @param callable(int):?string $gen
     */
    public function first(int $tries, callable $gen, bool $inPath = false): string
    {
        for ($i = 0; $i < $tries; $i++) {
            $value = $gen($i);
            if ($value !== null && $this->fit($value, $inPath)) {
                return $value;
            }
        }

        throw new LogicException('no fit value within the tries');
    }
}

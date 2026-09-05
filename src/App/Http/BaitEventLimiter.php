<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Closure;
use Throwable;

/**
 * Per-actor cap on the download bait's intel rows. One source re-fetching the manifest or the zip a
 * thousand times is one fact, not a thousand rows: the first few events in a window are kept, the rest
 * are only counted, and that count rides along on the next kept row (`suppressed=N`) so nothing is
 * lost while the row volume per actor is bounded whatever the request volume is. The suppressed
 * counter outlives its window by one more window — long enough for the next kept row to collect it,
 * short enough to stay bounded if the actor never returns. Only telemetry is gated here — what is
 * served never depends on this class (nginx owns the hard request bound).
 *
 * Counters live in APCu when it is on (shared by the fpm pool, expiring with the window); without it
 * (CLI, tests) a per-process map with the same window semantics stands in, so the bound then holds
 * per worker at worst. A counter fault admits the event: telemetry never fails closed on itself.
 */
final class BaitEventLimiter
{
    /** The one place the default envelope lives: rows kept per actor per window. */
    public const MAX_PER_WINDOW = 3;
    public const WINDOW_S = 600;

    private const APCU_PREFIX = 'fp:dlbait:';
    private const LOCAL_MAX_KEYS = 4096;

    private Closure $clock;
    private Closure $incr;
    private Closure $take;

    /** @var array<string,array{n:int,exp:int}> per-process fallback counters */
    private array $local = [];

    /**
     * @param Closure|null $clock fn(): int — unix seconds
     * @param Closure|null $incr  fn(string $key, int $ttlS): int — the incremented count, 0 on fault
     * @param Closure|null $take  fn(string $key): int — read-and-reset a counter, 0 when absent
     */
    public function __construct(
        private int $maxPerWindow = self::MAX_PER_WINDOW,
        private int $windowS = self::WINDOW_S,
        ?Closure $clock = null,
        ?Closure $incr = null,
        ?Closure $take = null
    ) {
        $this->maxPerWindow = max(1, $this->maxPerWindow);
        $this->windowS = max(1, $this->windowS);
        $this->clock = $clock ?? static fn (): int => time();
        $apcu = $incr === null && $take === null && function_exists('apcu_enabled') && apcu_enabled();
        $this->incr = $incr ?? ($apcu ? Closure::fromCallable([$this, 'apcuIncr']) : Closure::fromCallable([$this, 'localIncr']));
        $this->take = $take ?? ($apcu ? Closure::fromCallable([$this, 'apcuTake']) : Closure::fromCallable([$this, 'localTake']));
    }

    /**
     * Admit or suppress one bait event for an actor. The actor is the trusted-proxy-resolved client IP
     * the front controller already computed — never a raw forwarded header, which is spoofable per
     * request and would make the bound trivially escapable. `suppressed` is the count folded into
     * this row from the events dropped since the last kept one; 0 when nothing was dropped.
     *
     * @return array{keep:bool, suppressed:int}
     */
    public function admit(string $actor): array
    {
        try {
            $n = ($this->incr)('n|' . $actor, $this->windowS);
            if ($n <= 0 || $n <= $this->maxPerWindow) {   // <= 0: counter fault — admit
                return ['keep' => true, 'suppressed' => max(0, ($this->take)('s|' . $actor))];
            }
            ($this->incr)('s|' . $actor, $this->windowS * 2);
        } catch (Throwable $e) {
            return ['keep' => true, 'suppressed' => 0];
        }

        return ['keep' => false, 'suppressed' => 0];
    }

    private function apcuIncr(string $key, int $ttlS): int
    {
        $ok = false;
        $v = apcu_inc(self::APCU_PREFIX . $key, 1, $ok, $ttlS);

        return $ok && is_int($v) ? $v : 0;
    }

    private function apcuTake(string $key): int
    {
        $ok = false;
        $v = apcu_fetch(self::APCU_PREFIX . $key, $ok);
        if ($ok) {
            apcu_delete(self::APCU_PREFIX . $key);
        }

        return $ok && is_int($v) ? $v : 0;
    }

    private function localIncr(string $key, int $ttlS): int
    {
        $now = ($this->clock)();
        $cur = $this->local[$key] ?? null;
        if ($cur === null || $cur['exp'] <= $now) {
            if (count($this->local) >= self::LOCAL_MAX_KEYS) {
                $this->local = array_filter($this->local, static fn (array $c): bool => $c['exp'] > $now);
                if (count($this->local) >= self::LOCAL_MAX_KEYS) {
                    $this->local = [];   // bounded memory over perfect accuracy
                }
            }
            $cur = ['n' => 0, 'exp' => $now + $ttlS];
        }
        $cur['n']++;
        $this->local[$key] = $cur;

        return $cur['n'];
    }

    private function localTake(string $key): int
    {
        $now = ($this->clock)();
        $cur = $this->local[$key] ?? null;
        unset($this->local[$key]);

        return $cur !== null && $cur['exp'] > $now ? $cur['n'] : 0;
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

use Funnypot\Core\RequestContext;
use Throwable;

/**
 * The observer a producer calls AFTER its response decision exists. It resolves the episode key
 * (verifying any presented handle first) and hands one typed event to the store; nothing comes
 * back that could influence a response. It never sleeps, never retries, never touches the network,
 * and never throws — every fault is absorbed into the returned status — so a producer can call it
 * from a `finally` after the body is out with no way to turn a late failure into a 500.
 *
 * The clock is the same integer UTC-epoch source the store was built with, so the timestamps a
 * handle is verified against and the episode boundaries the store decides agree across workers.
 */
final class EngagementRecorder
{
    /** @var callable():int */
    private $clock;

    private float $lastCallMs = 0.0;

    public function __construct(
        private EngagementStore $store,
        private EpisodeResolver $resolver,
        ?callable $clock = null
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /**
     * @param string|null $episodeHandle a presented episode handle, if any — verified, never trusted
     * @return string one of the {@see EngagementStore} status constants
     */
    public function record(string $peerIp, string $userAgent, EngagementEvent $event, ?string $episodeHandle = null): string
    {
        $start = hrtime(true);
        try {
            $key = $this->resolver->resolve($episodeHandle, $peerIp, $userAgent, ($this->clock)());
            $status = $this->store->resolveAndRecord($key, $event);
        } catch (Throwable $e) {
            $status = EngagementStore::FAULT;
        }
        $this->lastCallMs = (hrtime(true) - $start) / 1_000_000;

        return $status;
    }

    /** Wall time of the last record() call, measured from outside the store (benchmark/health only). */
    public function lastCallMs(): float
    {
        return $this->lastCallMs;
    }

    /** The request's User-Agent (any header casing), or '' — only ever reduced to a coarse class. */
    public static function userAgentOf(RequestContext $ctx): string
    {
        foreach ($ctx->headers as $k => $v) {
            if (strcasecmp((string) $k, 'user-agent') === 0) {
                return (string) $v;
            }
        }

        return '';
    }
}

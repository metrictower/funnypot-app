<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The write side of engagement metrics — a sibling of {@see \Funnypot\App\Storage\HitStore}, never
 * an extension of it (its lightweight test doubles must not inherit analytics obligations; the same
 * split {@see \Funnypot\App\Storage\AnalyticsStore} already makes).
 *
 * One operation, atomic: resolve the current episode for a verified key (create one when none
 * exists, the idle gap has passed, the absolute lifetime is reached, or the clock went backwards),
 * then append the event and advance the episode's counters — all under one write lock, so two
 * concurrent requests can never split one episode two ways or extend it past its lifetime. The
 * store is observer-only: nothing it returns may influence a response.
 */
interface EngagementStore
{
    public const RECORDED = 'recorded';
    /** Dropped at a per-episode or global cap; a fixed-name health counter was incremented. */
    public const SHED = 'shed';
    /** Lock, I/O, schema or serialization fault — rolled back to a no-op. */
    public const FAULT = 'fault';
    /** The store is switched off (no key material / feature off). */
    public const DISABLED = 'disabled';

    public function resolveAndRecord(EpisodeKey $key, EngagementEvent $event): string;
}

<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Shared per-source-IP token-bucket admission for UDP replies (anti-reflection), used by every UDP
 * listener (NTP, SNMP, STUN, CoAP, BACnet, IPMI, SIP). A spoofed request forges its source as a
 * victim, so every reply a listener emits lands on that victim — capping replies per apparent source
 * bounds how hard the honeypot can be turned into a reflector.
 *
 * Composing classes must declare (PHP 8.0 has no trait constants, so these resolve against `self::`
 * at the call site — i.e. the composing class, per each server's own doc comment):
 *   private const UDP_RESP_BURST = 20.0;      // bucket capacity (full-rate ceiling)
 *   private const UDP_RESP_RATE = 10.0;       // tokens refilled per second
 *   private const UDP_BUCKET_MAX_IPS = 4096;  // cap tracked IPs so the map can't grow unbounded
 *   private const UDP_RESP_SEED = 2.0;        // tokens a NEW/evicted IP is admitted with
 *
 * FP-0248 (depleted-bucket admission — closes the LRU-eviction reflection gap): a brand-new IP —
 * including one just evicted from the 4096-entry LRU map and re-admitted moments later — used to be
 * seeded with the FULL `UDP_RESP_BURST` (20 tokens). That let a spoofed-source-rotation attack drain a
 * victim's bucket, then churn `UDP_BUCKET_MAX_IPS` distinct spoofed sources so the victim's now-depleted
 * entry is the least-recently-refilled and gets evicted, then re-spoof the victim: the eviction+re-admit
 * cycle kept handing back a fresh 20-burst every rotation — sustained reflection far above the intended
 * steady rate, bounded only by the attacker's send rate. Seeding a new/evicted entry at `UDP_RESP_SEED`
 * tokens instead closes that: cycling the LRU now buys at most `UDP_RESP_SEED` packets per re-admission
 * — no better than the steady `UDP_RESP_RATE` refill the victim's own un-evicted bucket would have
 * earned anyway, so rotating spoofed sources gains ~nothing over just waiting.
 *
 * Why 2.0 and not 1.0: SIP's INVITE handler sends TWO immediate responses from one inbound datagram —
 * 100 Trying then 180 Ringing (`SipServer::handleInvite()`), both through this same bucket. A 1.0 seed
 * would silently drop the second response for every first-contact (or post-eviction) caller. Nothing in
 * any of the 7 servers emits more than two packets per inbound datagram, so 2.0 keeps every legitimate
 * first exchange intact — including SIP's — while still bounding eviction-cycling far below the old
 * 20-burst. A uniform 2.0 seed also keeps this trait identical across all 7 composing classes: no
 * per-server divergence to fingerprint or maintain.
 *
 * SIP composes this trait but extends its bucket entries with an extra `credit` byte-budget field
 * (FP-0248 §2b, the SIP-only cumulative egress-ratio guard) — see `SipServer::creditUdpIngress()` /
 * `udpEgressWouldAllow()` / `udpEgressDebit()`. This trait seeds and reads only `tokens`/`last`, never
 * touches `credit`, and never overwrites an existing entry — so SIP's extended shape is preserved
 * whichever guard's bookkeeping runs first for a given source.
 */
trait UdpResponseBucket
{
    /**
     * @var array<string, array{tokens: float, last: float}>
     */
    private array $udpResponseBuckets = [];

    /**
     * Ensures a bucket entry exists for $ip, seeded DEPLETED (`self::UDP_RESP_SEED` tokens, never the
     * full `UDP_RESP_BURST`) at timestamp $now — see the trait doc block for why. Evicts the least-
     * recently-refilled entry first when the map is already at `UDP_BUCKET_MAX_IPS` capacity. A no-op
     * when an entry already exists (including one with SIP's extra `credit` field — never overwritten).
     */
    private function udpResponseBucketEnsure(string $ip, float $now): void
    {
        if (isset($this->udpResponseBuckets[$ip])) {
            return;
        }

        // Bound the map: when full, drop the least-recently-refilled entry before adding one.
        if (count($this->udpResponseBuckets) >= self::UDP_BUCKET_MAX_IPS) {
            $oldestKey = null;
            $oldestAt = INF;
            foreach ($this->udpResponseBuckets as $k => $b) {
                if ($b['last'] < $oldestAt) {
                    $oldestAt = $b['last'];
                    $oldestKey = $k;
                }
            }
            if ($oldestKey !== null) {
                unset($this->udpResponseBuckets[$oldestKey]);
            }
        }
        $this->udpResponseBuckets[$ip] = ['tokens' => self::UDP_RESP_SEED, 'last' => $now];
    }

    /**
     * Token-bucket admission for a UDP reply to $ip. Returns false when the apparent source has
     * drained its bucket, so the reply is dropped rather than reflected. Refuses without consuming a
     * token (only a granted call debits), so a refusal never burns budget another guard is relying on
     * (FP-0248 §2b check-then-debit ordering, e.g. SIP's byte-budget guard checking this second).
     */
    private function udpResponseAllowed(string $ip): bool
    {
        $now = microtime(true);
        $this->udpResponseBucketEnsure($ip, $now);

        $bucket = &$this->udpResponseBuckets[$ip];
        $elapsed = max(0.0, $now - $bucket['last']);
        $bucket['tokens'] = min(self::UDP_RESP_BURST, $bucket['tokens'] + $elapsed * self::UDP_RESP_RATE);
        $bucket['last'] = $now;

        if ($bucket['tokens'] < 1.0) {
            return false;
        }
        $bucket['tokens'] -= 1.0;

        return true;
    }
}

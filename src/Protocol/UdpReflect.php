<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Reflection kill-switch for every UDP listener (FP-0483). A stateless UDP service is a spoofable-source
 * reflector: any reply it emits lands on whatever victim the request forged as its source. The amp<=1 cap
 * + per-source token bucket keep the reflection factor at 1.0, but an AWS-AUP-style policy flags ANY open
 * UDP responder regardless. The only fully reflection-proof posture is to not respond at all.
 *
 * So UDP runs CAPTURE-ONLY by default: the listeners still parse + log every probe (all intel kept), but
 * emit zero bytes. Replying is an explicit opt-in (`FUNNYPOT_UDP_REFLECT=1`) for an isolated, non-internet-
 * exposed deployment where UDP deception is wanted and reflection abuse is not a concern.
 *
 * The env is read per call (cheap; UDP reply rates are low) so a test's `putenv` takes effect immediately.
 */
final class UdpReflect
{
    /** True only when UDP replies are explicitly opted in. Absent/empty/"0"/"off"/anything else ⇒ false. */
    public static function enabled(): bool
    {
        $v = \getenv('FUNNYPOT_UDP_REFLECT');
        if (!\is_string($v)) {
            return false;
        }

        return \in_array(\strtolower(\trim($v)), ['1', 'true', 'on', 'yes'], true);
    }
}

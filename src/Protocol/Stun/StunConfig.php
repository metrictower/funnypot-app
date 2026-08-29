<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Stun;

/**
 * Configuration for the low-interaction STUN honeypot (UDP 3478, RFC 5389).
 *
 * The service does only NAT-mapping discovery: it answers a Binding Request with the client's
 * observed source address. The single cosmetic knob is the SOFTWARE string advertised in the
 * Binding Success Response — persona shaping which STUN/TURN server the box claims to run. It is
 * only ever a hint; the anti-amplification cap drops it (and, if needed, the whole reply) rather
 * than let a response exceed the request that triggered it.
 */
final class StunConfig
{
    public function __construct(
        // SOFTWARE attribute advertised in responses (RFC 5389 15.10). Empty string = omit it.
        public string $software = 'coturn-4.5.2'
    ) {
    }

    public static function fromEnv(): self
    {
        // An explicitly empty FUNNYPOT_STUN_SOFTWARE disables the attribute; unset uses the default.
        $software = getenv('FUNNYPOT_STUN_SOFTWARE');
        if ($software === false) {
            $software = 'coturn-4.5.2';
        }

        return new self(software: $software);
    }
}

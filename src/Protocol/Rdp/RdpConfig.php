<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rdp;

/**
 * Configuration for the low-interaction RDP honeypot.
 *
 * The honeypot never renders a desktop; its whole purpose is to log scanners and harvest the
 * credentials brute-forcers throw at it. The single meaningful knob is which security protocol
 * the server selects in its negotiation response. Standard RDP Security is chosen by default so
 * the client keeps talking over plain TCP instead of wrapping the session in a TLS/CredSSP tunnel
 * the honeypot would have to terminate — that path yields the cleartext Client Info credential.
 */
final class RdpConfig
{
    // requestedProtocols / selectedProtocol flags (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1).
    public const PROTOCOL_RDP = 0x00000000;
    public const PROTOCOL_SSL = 0x00000001;
    public const PROTOCOL_HYBRID = 0x00000002;
    public const PROTOCOL_RDSTLS = 0x00000004;
    public const PROTOCOL_HYBRID_EX = 0x00000008;

    public function __construct(
        public int $selectedProtocol = self::PROTOCOL_RDP
    ) {
    }

    public static function fromEnv(): self
    {
        $select = strtolower((string) (getenv('FUNNYPOT_RDP_SELECT') ?: 'rdp'));
        $protocol = match ($select) {
            'ssl', 'tls' => self::PROTOCOL_SSL,
            'hybrid', 'nla', 'credssp' => self::PROTOCOL_HYBRID,
            'hybrid_ex', 'hybridex' => self::PROTOCOL_HYBRID_EX,
            default => self::PROTOCOL_RDP,
        };

        return new self(selectedProtocol: $protocol);
    }
}

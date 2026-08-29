<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ipmi;

/**
 * Configuration for the low-interaction IPMI/BMC honeypot (UDP 623, RMCP).
 *
 * The BMC never exposes real management data and never authenticates: every value here is cosmetic
 * persona shaping the believable baseboard management controller the box claims to be. Get Channel
 * Authentication Capabilities is answered from these fields (advertising the auth types a real BMC
 * offers); the IPMI 2.0 RAKP / IPMI 1.5 session-auth flows are captured for intel and refused, never
 * completed. Nothing is ever writable and no session is ever granted.
 */
final class IpmiConfig
{
    // A fixed persona GUID so the device identity advertised in RAKP Message 2 is stable per deploy.
    private const DEFAULT_GUID_HEX = '2d1a5c9f8b7e4a3d0c6f1e8b2a4d7c90';

    public function __construct(
        // Channel number echoed in the Get Channel Auth Cap response (1 = the first LAN channel).
        public int $channel = 1,
        // Authentication Type Support bit field: none(0) | MD2(1) | MD5(2) | straight-password(4).
        public int $authTypeSupport = 0x17,
        // Auth-status byte: which login modes are enabled (0x04 = non-null usernames enabled).
        public int $statusByte = 0x04,
        // Extended-capabilities byte: bit1 = IPMI v2.0 connections, bit0 = IPMI v1.5 connections.
        public int $extCapabilities = 0x02,
        // IANA OEM id advertised in the auth-cap response (0 = no OEM), and its auxiliary byte.
        public int $oemId = 0,
        public int $oemAux = 0,
        // Maximum privilege level the BMC will advertise (4 = ADMINISTRATOR).
        public int $maxPrivilege = 4,
        // 16-byte system GUID returned in RAKP Message 2.
        public string $guid = ''
    ) {
        $this->channel &= 0x0F;
        $this->authTypeSupport &= 0xFF;
        $this->statusByte &= 0xFF;
        $this->extCapabilities &= 0xFF;
        $this->oemId &= 0xFFFFFF;
        $this->oemAux &= 0xFF;
        $this->maxPrivilege &= 0x0F;
        if (strlen($this->guid) !== 16) {
            $this->guid = self::guidFromHex(self::DEFAULT_GUID_HEX);
        }
    }

    public static function fromEnv(): self
    {
        $guidHex = getenv('FUNNYPOT_IPMI_GUID') ?: self::DEFAULT_GUID_HEX;

        return new self(
            channel: self::envInt('FUNNYPOT_IPMI_CHANNEL', 1),
            authTypeSupport: self::envInt('FUNNYPOT_IPMI_AUTH_SUPPORT', 0x17),
            statusByte: self::envInt('FUNNYPOT_IPMI_STATUS', 0x04),
            extCapabilities: self::envInt('FUNNYPOT_IPMI_EXT_CAPS', 0x02),
            oemId: self::envInt('FUNNYPOT_IPMI_OEM_ID', 0),
            oemAux: self::envInt('FUNNYPOT_IPMI_OEM_AUX', 0),
            maxPrivilege: self::envInt('FUNNYPOT_IPMI_MAX_PRIV', 4),
            guid: self::guidFromHex($guidHex)
        );
    }

    private static function envInt(string $name, int $default): int
    {
        $raw = getenv($name);
        if ($raw === false || $raw === '') {
            return $default;
        }
        // Accept both decimal and 0x-prefixed hex so byte-field personas read naturally.
        $trimmed = trim($raw);
        if (stripos($trimmed, '0x') === 0) {
            return (int) hexdec(substr($trimmed, 2));
        }

        return (int) $trimmed;
    }

    /** Decodes a hex string into exactly 16 GUID bytes, padding or truncating as needed. */
    private static function guidFromHex(string $hex): string
    {
        $hex = preg_replace('/[^0-9a-fA-F]/', '', $hex) ?? '';
        $bytes = (strlen($hex) % 2 === 0) ? (string) @hex2bin($hex) : '';
        if (strlen($bytes) >= 16) {
            return substr($bytes, 0, 16);
        }

        return str_pad($bytes, 16, "\x00");
    }
}

<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Tr069;

/**
 * Configuration for the low-interaction TR-069 / CWMP honeypot (TCP 7547, HTTP).
 *
 * TR-069 is SOAP 1.1 over HTTP. The box poses as a vulnerable home broadband gateway (CPE) that
 * mistakenly exposes its LAN-side TR-064 / CWMP configuration service on the WAN port — the exact
 * misconfiguration the 2016-era router worms (Mirai/Mozi/Gafgyt variants, CVE-2016-10372) hunt for.
 * It accepts the worm's SOAP command-injection, answers with a plausible success frame so the worm
 * believes it succeeded, and captures the injected shell command + malware download URL as intel.
 * It never runs a command and never fetches a captured URL.
 *
 * The knobs shape the believable CPE persona: the embedded-HTTP Server banner, the model/firmware/OUI
 * a real gateway reports in its recon and Inform answers, the Digest realm on the connection-request
 * 401, and whether the emulator confirms RPCs (high) or answers a SOAP Fault (low). RomPager/4.07 is a
 * genuine AllegroSoft embedded-HTTP banner shipped on Zyxel/D-Link/Huawei DSL CPEs — a plausible
 * persona, not a scanner/matcher signature.
 */
final class Tr069Config
{
    // Response tenor: confirm every RPC with a success frame (the trap needs the worm to believe it
    // worked), or answer a SOAP Fault while still reading like a real CPE.
    public const MODE_HIGH = 'high';
    public const MODE_LOW = 'low';

    public function __construct(
        // Embedded-HTTP Server banner advertised on every response.
        public string $serverName = 'RomPager/4.07 UPnP/1.0',
        // Gateway model reported in recon / Inform answers.
        public string $model = 'VMG3312-B10A',
        // Firmware version reported in recon answers.
        public string $firmware = 'V1.00(AAAA.0)C0',
        // Manufacturer OUI reported in recon / Inform answers.
        public string $manufacturerOui = '00A0C5',
        // Realm quoted in the connection-request Digest challenge.
        public string $realm = 'RomPager',
        // high (accept + confirm, default) or low (SOAP Fault).
        public string $mode = self::MODE_HIGH
    ) {
    }

    public static function fromEnv(): self
    {
        $mode = strtolower((string) (getenv('FUNNYPOT_CWMP_MODE') ?: self::MODE_HIGH));
        $mode = match ($mode) {
            'low' => self::MODE_LOW,
            default => self::MODE_HIGH,
        };

        return new self(
            serverName: getenv('FUNNYPOT_CWMP_SERVER') ?: 'RomPager/4.07 UPnP/1.0',
            model: getenv('FUNNYPOT_CWMP_MODEL') ?: 'VMG3312-B10A',
            firmware: getenv('FUNNYPOT_CWMP_FIRMWARE') ?: 'V1.00(AAAA.0)C0',
            manufacturerOui: getenv('FUNNYPOT_CWMP_OUI') ?: '00A0C5',
            realm: getenv('FUNNYPOT_CWMP_REALM') ?: 'RomPager',
            mode: $mode
        );
    }

    /**
     * A stable persona serial derived from the OUI + model, so the recon answer does not change
     * between two queries within a deployment (a shifting serial would be a tell).
     */
    public function serialNumber(): string
    {
        return strtoupper(substr(sha1($this->manufacturerOui . '|' . $this->model), 0, 12));
    }

    /** Product class reported in recon / Inform answers (the model doubles as the product class). */
    public function productClass(): string
    {
        return $this->model;
    }
}

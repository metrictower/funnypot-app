<?php

declare(strict_types=1);

namespace Funnypot\Protocol\S7comm;

/**
 * Configuration for the low-interaction Siemens S7comm honeypot (ISO-on-TCP, port 102).
 *
 * The PLC never exposes real process data: every value here is cosmetic persona shaping the
 * believable controller the box claims to be. It answers the two recon surfaces a scanner cares
 * about — the negotiated PDU size for Setup Communication, and the System Status List (SZL) module
 * and component identity — from these fixed strings. Reads return zero-filled fakes and writes are
 * captured but never applied, so nothing real is ever read or changed.
 *
 * The default persona is an S7-1200; FUNNYPOT_S7COMM_PROFILE=s7-300 selects the classic S7-300
 * identity instead. Any individual field can still be overridden with its own env var.
 */
final class S7commConfig
{
    public function __construct(
        // Module order number (MlfB) returned in SZL 0x0011 — the article number naming the CPU.
        public string $orderNumber = '6ES7 214-1AG40-0XB0',
        // Human-readable CPU type name returned in SZL 0x001C index 7.
        public string $moduleTypeName = 'CPU 1214C DC/DC/DC',
        // Name of the automation system / station (SZL 0x001C index 1).
        public string $systemName = 'S7-1200 station_1',
        // Name of the module (SZL 0x001C index 2).
        public string $moduleName = 'PLC_1',
        // Plant identification (SZL 0x001C index 3) — often blank on a real device.
        public string $plantId = '',
        // Copyright string (SZL 0x001C index 4).
        public string $copyright = 'Original Siemens Equipment',
        // Serial number (SZL 0x001C index 5).
        public string $serialNumber = 'S C-C2UR28922012',
        // Hardware version reported in SZL 0x0011.
        public int $hardwareVersion = 6,
        // Firmware version reported in SZL 0x0011 (Vmajor.minor.patch).
        public int $firmwareMajor = 4,
        public int $firmwareMinor = 4,
        public int $firmwarePatch = 0,
        // Largest PDU size the CPU will negotiate in Setup Communication.
        public int $maxPduSize = 240,
        // Parallel-job limits echoed in the Setup Communication ack.
        public int $maxAmqCalling = 1,
        public int $maxAmqCalled = 1
    ) {
    }

    public static function fromEnv(): self
    {
        $profile = strtolower((string) (getenv('FUNNYPOT_S7COMM_PROFILE') ?: 's7-1200'));

        // Profile defaults; individual fields below can still override any of these.
        if ($profile === 's7-300' || $profile === 's7300') {
            $orderNumber = '6ES7 315-2EH14-0AB0';
            $moduleTypeName = 'CPU 315-2 PN/DP';
            $systemName = 'SIMATIC 300 station';
            $serialNumber = 'S C-X1U350892011';
            $fwMajor = 3;
            $fwMinor = 2;
            $fwPatch = 8;
        } else {
            $orderNumber = '6ES7 214-1AG40-0XB0';
            $moduleTypeName = 'CPU 1214C DC/DC/DC';
            $systemName = 'S7-1200 station_1';
            $serialNumber = 'S C-C2UR28922012';
            $fwMajor = 4;
            $fwMinor = 4;
            $fwPatch = 0;
        }

        $envStr = static fn (string $key, string $default): string => ($v = getenv($key)) !== false && $v !== '' ? $v : $default;
        $envInt = static fn (string $key, int $default): int => ($v = getenv($key)) !== false && $v !== '' ? (int) $v : $default;

        return new self(
            orderNumber: $envStr('FUNNYPOT_S7COMM_ORDER_NUMBER', $orderNumber),
            moduleTypeName: $envStr('FUNNYPOT_S7COMM_MODULE_TYPE', $moduleTypeName),
            systemName: $envStr('FUNNYPOT_S7COMM_SYSTEM_NAME', $systemName),
            moduleName: $envStr('FUNNYPOT_S7COMM_MODULE_NAME', 'PLC_1'),
            plantId: $envStr('FUNNYPOT_S7COMM_PLANT_ID', ''),
            copyright: $envStr('FUNNYPOT_S7COMM_COPYRIGHT', 'Original Siemens Equipment'),
            serialNumber: $envStr('FUNNYPOT_S7COMM_SERIAL', $serialNumber),
            hardwareVersion: $envInt('FUNNYPOT_S7COMM_HW_VERSION', 6),
            firmwareMajor: $envInt('FUNNYPOT_S7COMM_FW_MAJOR', $fwMajor),
            firmwareMinor: $envInt('FUNNYPOT_S7COMM_FW_MINOR', $fwMinor),
            firmwarePatch: $envInt('FUNNYPOT_S7COMM_FW_PATCH', $fwPatch),
            maxPduSize: max(240, $envInt('FUNNYPOT_S7COMM_MAX_PDU', 240)),
            maxAmqCalling: $envInt('FUNNYPOT_S7COMM_MAX_AMQ_CALLING', 1),
            maxAmqCalled: $envInt('FUNNYPOT_S7COMM_MAX_AMQ_CALLED', 1)
        );
    }

    /** Firmware version as the operator-facing "Vx.y.z" string used in log lines. */
    public function firmwareVersion(): string
    {
        return sprintf('V%d.%d.%d', $this->firmwareMajor, $this->firmwareMinor, $this->firmwarePatch);
    }
}

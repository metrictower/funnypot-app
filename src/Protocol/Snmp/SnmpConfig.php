<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Snmp;

/**
 * Configuration for the low-interaction SNMP honeypot (UDP 161, v1 + v2c).
 *
 * The agent never exposes real management data: every value here is cosmetic persona shaping the
 * believable device the box claims to be (a small managed switch / gateway). The system group is
 * answered from these fixed strings; anything else degrades to a no-such-object varbind. Nothing
 * is ever writable, so a SET is captured and refused, never applied.
 *
 * sysUpTime is derived from a stable per-deploy boot instant so it advances like a real device that
 * has been running for a while, rather than resetting to zero on every request.
 */
final class SnmpConfig
{
    public function __construct(
        // The device identity advertised in the system group (MIB-2 1.3.6.1.2.1.1).
        public string $sysDescr = 'Hardware: x86 Family Software: 2.6.32',
        public string $sysObjectId = '1.3.6.1.4.1.8072.3.2.10',
        public string $sysContact = 'admin',
        public string $sysName = 'gateway',
        public string $sysLocation = 'server room',
        public int $sysServices = 72,
        // Unix instant the emulated device claims to have booted; sysUpTime counts up from it.
        public int $bootUnixTime = 0
    ) {
        if ($this->bootUnixTime <= 0) {
            // Default to "up for ~8 days" so the reported uptime looks like a long-running device.
            $this->bootUnixTime = time() - 691200;
        }
    }

    public static function fromEnv(): self
    {
        $sysDescr = getenv('FUNNYPOT_SNMP_SYSDESCR') ?: 'Hardware: x86 Family Software: 2.6.32';
        $sysObjectId = getenv('FUNNYPOT_SNMP_SYSOBJECTID') ?: '1.3.6.1.4.1.8072.3.2.10';
        $sysContact = getenv('FUNNYPOT_SNMP_SYSCONTACT') ?: 'admin';
        $sysName = getenv('FUNNYPOT_SNMP_SYSNAME') ?: 'gateway';
        $sysLocation = getenv('FUNNYPOT_SNMP_SYSLOCATION') ?: 'server room';

        $servicesRaw = getenv('FUNNYPOT_SNMP_SYSSERVICES');
        $sysServices = ($servicesRaw !== false && $servicesRaw !== '') ? (int) $servicesRaw : 72;

        // Seconds the device has already been up, so sysUpTime starts from a plausible non-zero value.
        $uptimeRaw = getenv('FUNNYPOT_SNMP_UPTIME_SECONDS');
        $uptimeSeconds = ($uptimeRaw !== false && $uptimeRaw !== '') ? max(0, (int) $uptimeRaw) : 691200;

        return new self(
            sysDescr: $sysDescr,
            sysObjectId: $sysObjectId,
            sysContact: $sysContact,
            sysName: $sysName,
            sysLocation: $sysLocation,
            sysServices: $sysServices,
            bootUnixTime: time() - $uptimeSeconds
        );
    }

    /**
     * Current sysUpTime as TimeTicks (hundredths of a second since the device booted). Always
     * non-negative and monotonic across the process lifetime.
     */
    public function sysUpTimeTicks(): int
    {
        $seconds = time() - $this->bootUnixTime;
        if ($seconds < 0) {
            $seconds = 0;
        }

        // TimeTicks is a 32-bit unsigned counter that wraps; mirror that so the value stays in range.
        return ($seconds * 100) & 0xFFFFFFFF;
    }
}

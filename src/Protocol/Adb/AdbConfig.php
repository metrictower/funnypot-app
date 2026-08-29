<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Adb;

/**
 * Configuration for the low-interaction ADB (Android Debug Bridge) honeypot (TCP 5555).
 *
 * Insecure ADB over TCP 5555 is a huge Mirai/cryptominer botnet target: cheap Android boxes ship
 * with `ro.adb.secure=0`, so adbd answers a connect with no authentication and lets anyone push and
 * run commands. The honeypot presents exactly that — a rooted, auth-free device — so botnets offer up
 * their pushed commands and payloads, which is the whole intel value. Every value here is cosmetic
 * persona shaping the believable device banner; nothing is ever executed.
 */
final class AdbConfig
{
    // ADB protocol version advertised in the A_CNXN reply (A_VERSION).
    public const VERSION = 0x01000000;

    public function __construct(
        // The device identity advertised in the connect banner (ro.product.* keys).
        public string $productName = 'rk3288',
        public string $productModel = 'rk3288',
        public string $productDevice = 'rk3288',
        // ADB feature set the device claims to support (cmd/shell_v2 are the modern staples).
        public string $features = 'cmd,shell_v2',
        // Max payload the device advertises it will accept, echoed as arg1 of the A_CNXN reply.
        public int $maxData = 262144
    ) {
    }

    public static function fromEnv(): self
    {
        $productName = getenv('FUNNYPOT_ADB_PRODUCT_NAME') ?: 'rk3288';
        $productModel = getenv('FUNNYPOT_ADB_PRODUCT_MODEL') ?: 'rk3288';
        $productDevice = getenv('FUNNYPOT_ADB_PRODUCT_DEVICE') ?: 'rk3288';
        $features = getenv('FUNNYPOT_ADB_FEATURES') ?: 'cmd,shell_v2';

        $maxDataRaw = getenv('FUNNYPOT_ADB_MAXDATA');
        $maxData = ($maxDataRaw !== false && $maxDataRaw !== '') ? max(4096, (int) $maxDataRaw) : 262144;

        return new self(
            productName: $productName,
            productModel: $productModel,
            productDevice: $productDevice,
            features: $features,
            maxData: $maxData
        );
    }

    /**
     * The system-identity string a real device returns in its A_CNXN banner:
     * "<type>:<serial>:<properties>". The serial is left empty (an unauthorised device reveals none)
     * and the properties advertise the fake product identity plus the feature set.
     */
    public function deviceBanner(): string
    {
        return sprintf(
            'device::ro.product.name=%s;ro.product.model=%s;ro.product.device=%s;features=%s',
            $this->productName,
            $this->productModel,
            $this->productDevice,
            $this->features
        );
    }
}

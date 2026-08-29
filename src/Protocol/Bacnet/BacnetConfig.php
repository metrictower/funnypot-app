<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Bacnet;

/**
 * Configuration for the low-interaction BACnet/IP honeypot (UDP 47808, building automation).
 *
 * The device never exposes real building data: every value here is cosmetic persona shaping the
 * believable controller the box claims to be. Who-Is is answered with an I-Am built from these
 * fields; ReadProperty of the advertised Device object returns these fixed strings, and anything
 * else degrades to a BACnet error. Nothing is ever writable, so a write is captured and refused,
 * never applied.
 */
final class BacnetConfig
{
    public function __construct(
        // The Device object instance advertised in I-Am and matched by ReadProperty (0..4194302).
        public int $deviceInstance = 260001,
        // ASHRAE vendor identifier and the matching cosmetic vendor name.
        public int $vendorId = 260,
        public string $vendorName = 'BACnet Vendor',
        // Device object-name / model / firmware / application-software persona strings.
        public string $objectName = 'DEVICE_260001',
        public string $modelName = 'BAC-1000',
        public string $firmwareRevision = '1.0',
        public string $applicationSoftwareVersion = '1.0',
        public string $description = 'Building Controller',
        // Max APDU length accepted, advertised in I-Am (1476 = typical BACnet/IP).
        public int $maxApdu = 1476,
        // Segmentation supported (0=both, 1=transmit, 2=receive, 3=no-segmentation).
        public int $segmentation = 3
    ) {
        // Keep the instance inside the 22-bit BACnet object-instance range.
        $this->deviceInstance &= 0x3FFFFF;
        $this->vendorId &= 0xFFFF;
    }

    public static function fromEnv(): self
    {
        $deviceId = getenv('FUNNYPOT_BACNET_DEVICE_ID');
        $deviceInstance = ($deviceId !== false && $deviceId !== '') ? max(0, (int) $deviceId) : 260001;

        $vendorIdRaw = getenv('FUNNYPOT_BACNET_VENDOR_ID');
        $vendorId = ($vendorIdRaw !== false && $vendorIdRaw !== '') ? max(0, (int) $vendorIdRaw) : 260;

        $maxApduRaw = getenv('FUNNYPOT_BACNET_MAX_APDU');
        $maxApdu = ($maxApduRaw !== false && $maxApduRaw !== '') ? max(50, (int) $maxApduRaw) : 1476;

        $segRaw = getenv('FUNNYPOT_BACNET_SEGMENTATION');
        $segmentation = ($segRaw !== false && $segRaw !== '') ? max(0, min(3, (int) $segRaw)) : 3;

        return new self(
            deviceInstance: $deviceInstance,
            vendorId: $vendorId,
            vendorName: getenv('FUNNYPOT_BACNET_VENDOR_NAME') ?: 'BACnet Vendor',
            objectName: getenv('FUNNYPOT_BACNET_OBJECT_NAME') ?: ('DEVICE_' . $deviceInstance),
            modelName: getenv('FUNNYPOT_BACNET_MODEL') ?: 'BAC-1000',
            firmwareRevision: getenv('FUNNYPOT_BACNET_FIRMWARE') ?: '1.0',
            applicationSoftwareVersion: getenv('FUNNYPOT_BACNET_APP_SW') ?: '1.0',
            description: getenv('FUNNYPOT_BACNET_DESCRIPTION') ?: 'Building Controller',
            maxApdu: $maxApdu,
            segmentation: $segmentation
        );
    }
}

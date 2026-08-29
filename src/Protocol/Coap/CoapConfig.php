<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Coap;

/**
 * Configuration for the low-interaction CoAP honeypot (UDP 5683, RFC 7252 — the constrained-device
 * IoT protocol).
 *
 * The node never exposes real device data: every value here is cosmetic persona shaping the
 * believable constrained device the box claims to be. GET /.well-known/core is answered with the
 * link-format resource list below; a GET of one of the advertised resources returns its fixed tiny
 * value, and anything else degrades to 4.04 Not Found. Nothing is ever writable — a PUT/POST/DELETE
 * is captured and refused, never applied.
 */
final class CoapConfig
{
    private const DEFAULT_CORE = '</.well-known/core>;ct=40,</sensors/temp>;rt="temperature";if="sensor",'
        . '</sensors/humidity>;rt="humidity";if="sensor",</actuators/led>;rt="switch",'
        . '</large>;sz=1024,</config>';

    /** @var array<string,string> resource path => cosmetic tiny body returned on GET */
    public array $resources;

    /**
     * @param array<string,string>|null $resources
     */
    public function __construct(
        // The application/link-format body returned for GET /.well-known/core.
        public string $wellKnownCore = self::DEFAULT_CORE,
        ?array $resources = null,
        // Persona device name (used in the listening banner and available to bodies).
        public string $deviceName = 'coap-node'
    ) {
        $this->resources = $resources ?? self::defaultResources();
    }

    public static function fromEnv(): self
    {
        $core = getenv('FUNNYPOT_COAP_CORE');
        $device = getenv('FUNNYPOT_COAP_DEVICE');

        return new self(
            wellKnownCore: ($core !== false && $core !== '') ? $core : self::DEFAULT_CORE,
            deviceName: ($device !== false && $device !== '') ? $device : 'coap-node'
        );
    }

    /**
     * The advertised resources. `/large` exists so the honeypot can present the amplification target
     * scanners probe for — the anti-amplification cap in the server neuters it, never dumping it.
     *
     * @return array<string,string>
     */
    private static function defaultResources(): array
    {
        return [
            '/sensors/temp' => '21.4',
            '/sensors/humidity' => '46',
            '/actuators/led' => 'off',
            '/config' => 'fw=1.2.3',
            '/large' => str_repeat('A', 512),
        ];
    }
}

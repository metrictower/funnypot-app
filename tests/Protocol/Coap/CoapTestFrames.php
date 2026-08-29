<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Coap;

/**
 * Byte builders for the CoAP tests: the 4-byte header, token, delta/length-encoded options and the
 * 0xFF-marked payload of the GET / POST / PUT / DELETE requests an IoT scanner would send. Kept
 * minimal — just enough structure for the honeypot's parser to exercise every field it reads.
 *
 * A `padOption` inflates a request past the anti-amplification cap so a believable content reply
 * (the /.well-known/core list, a resource value) is allowed through — the CoAP analogue of the
 * BACnet routed-envelope trick.
 */
trait CoapTestFrames
{
    // Message types.
    private const T_CON = 0;
    private const T_NON = 1;
    private const T_ACK = 2;
    private const T_RST = 3;

    // Request method codes.
    private const C_GET = 0x01;
    private const C_POST = 0x02;
    private const C_PUT = 0x03;
    private const C_DELETE = 0x04;

    private const OPT_URI_PATH = 11;
    private const OPT_URI_QUERY = 15;

    /**
     * @param list<array{0:int,1:string}> $options [number, value] pairs, any order
     */
    private static function coapMessage(int $type, int $code, int $mid, string $token, array $options, string $payload = ''): string
    {
        $tkl = strlen($token);
        $out = chr((1 << 6) | (($type & 0x03) << 4) | ($tkl & 0x0F));
        $out .= chr($code & 0xFF);
        $out .= chr(($mid >> 8) & 0xFF) . chr($mid & 0xFF);
        $out .= $token;

        usort($options, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
        $prev = 0;
        foreach ($options as [$number, $value]) {
            $delta = $number - $prev;
            $len = strlen($value);
            [$dn, $de] = self::ext($delta);
            [$ln, $le] = self::ext($len);
            $out .= chr(($dn << 4) | $ln) . $de . $le . $value;
            $prev = $number;
        }

        if ($payload !== '') {
            $out .= "\xFF" . $payload;
        }

        return $out;
    }

    /**
     * @return array{0:int,1:string}
     */
    private static function ext(int $v): array
    {
        if ($v < 13) {
            return [$v, ''];
        }
        if ($v < 269) {
            return [13, chr($v - 13)];
        }

        return [14, pack('n', $v - 269)];
    }

    /**
     * Uri-Path options (number 11), one per non-empty segment of $path.
     *
     * @return list<array{0:int,1:string}>
     */
    private static function pathOptions(string $path): array
    {
        $opts = [];
        foreach (explode('/', ltrim($path, '/')) as $seg) {
            if ($seg !== '') {
                $opts[] = [self::OPT_URI_PATH, $seg];
            }
        }

        return $opts;
    }

    /** A Uri-Query option carrying $bytes of filler, used to inflate a request past the cap. */
    private static function padOption(int $bytes): array
    {
        return [self::OPT_URI_QUERY, 'p=' . str_repeat('a', max(0, $bytes - 2))];
    }

    /**
     * @param list<array{0:int,1:string}> $extraOptions
     */
    private static function getMessage(int $type, int $mid, string $token, string $path, array $extraOptions = [], string $payload = ''): string
    {
        return self::coapMessage($type, self::C_GET, $mid, $token, array_merge(self::pathOptions($path), $extraOptions), $payload);
    }

    private static function postMessage(int $type, int $mid, string $token, string $path, string $payload): string
    {
        return self::coapMessage($type, self::C_POST, $mid, $token, self::pathOptions($path), $payload);
    }

    private static function methodMessage(int $type, int $code, int $mid, string $token, string $path): string
    {
        return self::coapMessage($type, $code, $mid, $token, self::pathOptions($path));
    }
}

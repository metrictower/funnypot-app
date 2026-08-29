<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Vnc;

/**
 * Generates RFB Cursor pseudo-encoding (-239) payloads.
 * Transmits custom cursor shapes and transparency bitmasks to the client viewer.
 */
final class VncCursor
{
    public const ENCODING_CURSOR = -239; // 0xFFFFFF11

    /**
     * Builds a FramebufferUpdate rectangle for the Cursor pseudo-encoding.
     *
     * @param string $style 'normal' (realistic arrow), 'troll', 'skull', 'invisible', or 'none'
     * @return string Binary rectangle header and payload, or '' if style is 'none'
     */
    public static function buildRectangle(string $style): string
    {
        if ($style === 'none') {
            return '';
        }

        if ($style === 'invisible') {
            // An empty 1x1 cursor with an all-zero mask hides the client cursor completely.
            return self::buildCustomCursor(1, 1, 0, 0, "\x00\x00\x00\x00", "\x00");
        }

        if ($style === 'skull') {
            return self::buildSkullCursor();
        }

        if ($style === 'troll') {
            return self::buildTrollCursor();
        }

        // Default ('normal'): a realistic left-pointing arrow so the attacker sees a pointer.
        // Clients that negotiate the Cursor pseudo-encoding hide their local cursor and rely on ours.
        return self::buildArrowCursor();
    }

    /**
     * Generates a classic left-pointing arrow pointer (white fill, black outline) with the
     * hotspot at the tip. Looks like an ordinary desktop mouse cursor.
     */
    public static function buildArrowCursor(): string
    {
        $w = 24;
        $h = 24;
        $hotX = 1;
        $hotY = 1;

        $im = imagecreatetruecolor($w, $h);
        imagealphablending($im, false);
        imagesavealpha($im, true);
        $transparent = imagecolorallocatealpha($im, 0, 0, 0, 127);
        imagefill($im, 0, 0, $transparent);

        imagealphablending($im, true);
        $white = imagecolorallocate($im, 255, 255, 255);
        $black = imagecolorallocate($im, 0, 0, 0);

        // Standard arrow silhouette: tip at (1,1), notch tail, angled stem.
        $arrow = [
            1, 1,
            1, 17,
            5, 13,
            8, 20,
            11, 19,
            8, 12,
            14, 12,
        ];
        imagefilledpolygon($im, $arrow, $white);
        imagepolygon($im, $arrow, $black);

        return self::convertImageToCursor($im, $w, $h, $hotX, $hotY);
    }

    /**
     * Generates a 32x32 troll face cursor with transparent background and black/white features.
     */
    public static function buildTrollCursor(): string
    {
        $w = 32;
        $h = 32;
        $hotX = 16;
        $hotY = 16;

        $im = imagecreatetruecolor($w, $h);
        imagealphablending($im, false);
        imagesavealpha($im, true);

        // Transparent background
        $transparent = imagecolorallocatealpha($im, 0, 0, 0, 127);
        imagefill($im, 0, 0, $transparent);

        // Colors
        $white = imagecolorallocate($im, 255, 255, 255);
        $black = imagecolorallocate($im, 0, 0, 0);
        $grey = imagecolorallocate($im, 180, 180, 180);

        // Head outline (troll face shape: wider on top right, hooked chin on bottom left)
        // Outer face fill
        imagefilledellipse($im, 16, 16, 28, 26, $white);
        imageellipse($im, 16, 16, 28, 26, $black);

        // Wrinkles / forehead creases
        imageline($im, 9, 8, 23, 7, $black);
        imageline($im, 11, 10, 21, 9, $black);

        // Eyes (mischievous squint)
        imagefilledellipse($im, 11, 13, 5, 4, $black);
        imagefilledellipse($im, 21, 12, 5, 4, $black);
        imagefilledellipse($im, 12, 13, 2, 2, $white);
        imagefilledellipse($im, 22, 12, 2, 2, $white);

        // Nose
        imageline($im, 16, 13, 15, 17, $black);
        imageline($im, 15, 17, 18, 17, $black);

        // Giant grin (classic troll smile arc)
        imagearc($im, 16, 19, 22, 14, 0, 180, $black);
        imageline($im, 5, 19, 27, 19, $black);

        // Teeth lines
        imageline($im, 9, 19, 9, 24, $black);
        imageline($im, 13, 19, 13, 25, $black);
        imageline($im, 16, 19, 16, 26, $black);
        imageline($im, 19, 19, 19, 25, $black);
        imageline($im, 23, 19, 23, 23, $black);

        return self::convertImageToCursor($im, $w, $h, $hotX, $hotY);
    }

    /**
     * Generates a 32x32 Skull and Crossbones cursor with transparent background.
     */
    public static function buildSkullCursor(): string
    {
        $w = 32;
        $h = 32;
        $hotX = 16;
        $hotY = 14;

        $im = imagecreatetruecolor($w, $h);
        imagealphablending($im, false);
        imagesavealpha($im, true);

        // Transparent background
        $transparent = imagecolorallocatealpha($im, 0, 0, 0, 127);
        imagefill($im, 0, 0, $transparent);

        $white = imagecolorallocate($im, 255, 255, 255);
        $black = imagecolorallocate($im, 0, 0, 0);

        // Crossbones diagonal lines
        imageline($im, 4, 4, 27, 27, $white);
        imageline($im, 5, 4, 28, 27, $white);
        imageline($im, 4, 5, 27, 28, $white);
        imageline($im, 27, 4, 4, 27, $white);
        imageline($im, 28, 4, 5, 27, $white);
        imageline($im, 27, 5, 4, 28, $white);

        // Bone ends (knuckles)
        imagefilledellipse($im, 4, 4, 5, 5, $white);
        imagefilledellipse($im, 28, 28, 5, 5, $white);
        imagefilledellipse($im, 28, 4, 5, 5, $white);
        imagefilledellipse($im, 4, 28, 5, 5, $white);

        // Cranium
        imagefilledellipse($im, 16, 12, 16, 14, $white);
        imageellipse($im, 16, 12, 16, 14, $black);

        // Eye sockets
        imagefilledellipse($im, 13, 12, 4, 4, $black);
        imagefilledellipse($im, 19, 12, 4, 4, $black);

        // Nose cavity
        imageline($im, 16, 14, 15, 16, $black);
        imageline($im, 16, 14, 17, 16, $black);

        // Jaw / teeth
        imagefilledrectangle($im, 12, 18, 20, 22, $white);
        imagerectangle($im, 12, 18, 20, 22, $black);
        imageline($im, 14, 18, 14, 22, $black);
        imageline($im, 16, 18, 16, 22, $black);
        imageline($im, 18, 18, 18, 22, $black);

        return self::convertImageToCursor($im, $w, $h, $hotX, $hotY);
    }

    private static function convertImageToCursor(\GdImage $im, int $w, int $h, int $hotX, int $hotY): string
    {
        // Convert GD image to 32bpp BGRA and 1-bit mask
        $pixelBytes = '';
        $maskBytes = '';

        for ($y = 0; $y < $h; $y++) {
            $rowMask = 0;
            $bitCount = 0;
            $rowBits = '';

            for ($x = 0; $x < $w; $x++) {
                $rgba = imagecolorat($im, $x, $y);
                $alpha = ($rgba >> 24) & 0x7F; // 0 (opaque) to 127 (transparent)
                $r = ($rgba >> 16) & 0xFF;
                $g = ($rgba >> 8) & 0xFF;
                $b = $rgba & 0xFF;

                // 32bpp Little Endian BGRA
                $pixelBytes .= chr($b) . chr($g) . chr($r) . "\x00";

                // In RFB Cursor mask: 1 = opaque / visible, 0 = transparent
                $isOpaque = ($alpha < 64) ? 1 : 0;
                $rowMask = ($rowMask << 1) | $isOpaque;
                $bitCount++;

                if ($bitCount === 8) {
                    $rowBits .= chr($rowMask);
                    $rowMask = 0;
                    $bitCount = 0;
                }
            }

            if ($bitCount > 0) {
                $rowMask <<= (8 - $bitCount);
                $rowBits .= chr($rowMask);
            }

            $maskBytes .= $rowBits;
        }

        imagedestroy($im);

        return self::buildCustomCursor($w, $h, $hotX, $hotY, $pixelBytes, $maskBytes);
    }

    /**
     * Packs cursor header and payload into an RFB rectangle.
     */
    public static function buildCustomCursor(
        int $width,
        int $height,
        int $hotspotX,
        int $hotspotY,
        string $pixelData,
        string $bitmask
    ): string {
        // Rectangle Header:
        // x-position (2 bytes) = hotspot X
        // y-position (2 bytes) = hotspot Y
        // width (2 bytes) = cursor width
        // height (2 bytes) = cursor height
        // encoding-type (4 bytes) = -239 (0xFFFFFF11)
        $header = pack('n4N', $hotspotX, $hotspotY, $width, $height, self::ENCODING_CURSOR);

        return $header . $pixelData . $bitmask;
    }
}

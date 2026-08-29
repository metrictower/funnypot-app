<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Vnc;

use Funnypot\Protocol\TrollStream;

/**
 * Renders visual deception themes using PHP's GD extension and converts
 * them to raw 32-bit Little-Endian BGRA TrueColour framebuffers.
 *
 * Supports:
 * - Windows 95 desktop (realistic honeypot view)
 * - Troll / Skull alternating animation frames (taunt mode trap)
 */
final class VncThemeRenderer
{
    public const POPUP_W = 360;
    public const POPUP_H = 150;

    public function __construct(private VncConfig $config)
    {
    }

    /**
     * Renders the framebuffer.
     * When $frame is null, renders the initial desktop (eth.png if available, else Windows 95).
     * When $frame is an integer, renders the alternating Trollface/Skull taunt animation.
     */
    public function renderBgra(
        string $peerIp = '127.0.0.1',
        int $peerPort = 5900,
        ?int $frame = null,
        ?int $customW = null,
        ?int $customH = null
    ): string {
        $w = $customW ?? $this->config->width;
        $h = $customH ?? $this->config->height;

        $im = ($frame !== null)
            ? $this->renderTroll($w, $h, $peerIp, $peerPort, $frame)
            : $this->renderInitialDesktop($w, $h, $peerIp, $peerPort);

        return self::imageToBgra($im, $w, $h);
    }

    /**
     * Renders the realistic desktop with a fake "Reverse VNC connection?" dialog on top, as a
     * raw BGRA framebuffer. Shown for a beat after the first click, before the taunt storm.
     * $dlgX/$dlgY position the dialog's top-left; -1 centres it.
     */
    public function renderPopupBgra(string $peerIp, int $peerPort, int $w, int $h, int $dlgX = -1, int $dlgY = -1): string
    {
        if ($dlgX < 0) {
            $dlgX = (int) (($w - self::POPUP_W) / 2);
        }
        if ($dlgY < 0) {
            $dlgY = (int) (($h - self::POPUP_H) / 2);
        }
        $im = $this->renderInitialDesktop($w, $h, $peerIp, $peerPort);
        self::drawReversePopup($im, $dlgX, $dlgY);

        return self::imageToBgra($im, $w, $h);
    }

    /**
     * Converts a GD truecolor image to a raw 32bpp Little-Endian BGRA framebuffer and frees it.
     */
    private static function imageToBgra(\GdImage $im, int $w, int $h): string
    {
        $body = '';
        for ($y = 0; $y < $h; $y++) {
            for ($x = 0; $x < $w; $x++) {
                $rgb = imagecolorat($im, $x, $y);
                $r = ($rgb >> 16) & 0xFF;
                $g = ($rgb >> 8) & 0xFF;
                $b = $rgb & 0xFF;
                $body .= chr($b) . chr($g) . chr($r) . "\x00";
            }
        }

        imagedestroy($im);

        return $body;
    }

    /**
     * Draws a classic Windows message box "Reverse VNC connection?" with Yes / No buttons,
     * with its top-left corner at ($dlgX, $dlgY) on the given desktop image.
     */
    private static function drawReversePopup(\GdImage $im, int $dlgX, int $dlgY): void
    {
        $grey = imagecolorallocate($im, 212, 208, 200);
        $white = imagecolorallocate($im, 255, 255, 255);
        $black = imagecolorallocate($im, 0, 0, 0);
        $darkGrey = imagecolorallocate($im, 128, 128, 128);
        $navy = imagecolorallocate($im, 0, 0, 128);
        $blue = imagecolorallocate($im, 0, 84, 227);

        $dlgW = self::POPUP_W;
        $dlgH = self::POPUP_H;

        // Dialog body with 3D raised border.
        imagefilledrectangle($im, $dlgX, $dlgY, $dlgX + $dlgW, $dlgY + $dlgH, $grey);
        imageline($im, $dlgX, $dlgY, $dlgX + $dlgW, $dlgY, $white);
        imageline($im, $dlgX, $dlgY, $dlgX, $dlgY + $dlgH, $white);
        imageline($im, $dlgX + $dlgW, $dlgY, $dlgX + $dlgW, $dlgY + $dlgH, $black);
        imageline($im, $dlgX, $dlgY + $dlgH, $dlgX + $dlgW, $dlgY + $dlgH, $black);

        // Title bar.
        $titleH = 20;
        imagefilledrectangle($im, $dlgX + 3, $dlgY + 3, $dlgX + $dlgW - 3, $dlgY + $titleH, $navy);
        imagestring($im, 3, $dlgX + 8, $dlgY + 5, 'Remote Connection', $white);
        // Close 'X'.
        $cx = $dlgX + $dlgW - 20;
        imagefilledrectangle($im, $cx, $dlgY + 5, $cx + 14, $dlgY + 17, $grey);
        imagerectangle($im, $cx, $dlgY + 5, $cx + 14, $dlgY + 17, $black);
        imagestring($im, 2, $cx + 4, $dlgY + 4, 'x', $black);

        // Blue question icon + message.
        $iconX = $dlgX + 24;
        $iconY = $dlgY + 55;
        imagefilledellipse($im, $iconX, $iconY, 34, 34, $blue);
        imageellipse($im, $iconX, $iconY, 34, 34, $darkGrey);
        imagestring($im, 5, $iconX - 5, $iconY - 8, '?', $white);
        imagestring($im, 4, $dlgX + 55, $dlgY + 48, 'Reverse VNC connection?', $black);

        // Yes / No buttons.
        self::drawButton($im, $dlgX + $dlgW - 170, $dlgY + $dlgH - 40, 70, 26, 'Yes', $grey, $white, $black);
        self::drawButton($im, $dlgX + $dlgW - 90, $dlgY + $dlgH - 40, 70, 26, 'No', $grey, $white, $black);
    }

    private static function drawButton(\GdImage $im, int $x, int $y, int $bw, int $bh, string $label, int $face, int $light, int $dark): void
    {
        imagefilledrectangle($im, $x, $y, $x + $bw, $y + $bh, $face);
        imageline($im, $x, $y, $x + $bw, $y, $light);
        imageline($im, $x, $y, $x, $y + $bh, $light);
        imageline($im, $x + $bw, $y, $x + $bw, $y + $bh, $dark);
        imageline($im, $x, $y + $bh, $x + $bw, $y + $bh, $dark);
        $tx = $x + (int) (($bw - strlen($label) * imagefontwidth(3)) / 2);
        imagestring($im, 3, $tx, $y + 6, $label, $dark);
    }

    /**
     * Loads a taunt image asset at its native size and returns [width, height, BGRA].
     * Used by the taunt slideshow for the ah-ah-ah / evil-troll frames.
     *
     * @return array{0:int,1:int,2:string}
     */
    public function renderStormImageBgra(string $path): array
    {
        $loaded = @imagecreatefromstring((string) @file_get_contents($path));
        if ($loaded === false) {
            $im = imagecreatetruecolor(400, 300);
            imagefilledrectangle($im, 0, 0, 399, 299, imagecolorallocate($im, 20, 0, 0));

            return [400, 300, self::imageToBgra($im, 400, 300)];
        }
        if (!imageistruecolor($loaded)) {
            imagepalettetotruecolor($loaded);
        }
        $w = imagesx($loaded);
        $h = imagesy($loaded);

        return [$w, $h, self::imageToBgra($loaded, $w, $h)];
    }

    /**
     * The "Reversing VNC connection" taunt slide (with a loading spinner).
     */
    public function renderReversingTextBgra(int $w, int $h): string
    {
        return self::renderGrayNotice($w, $h, ['Reversing VNC', 'connection'], 'spinner');
    }

    /**
     * The "A new VNC application has been installed" taunt slide (with a checkmark).
     */
    public function renderInstalledTextBgra(int $w, int $h): string
    {
        return self::renderGrayNotice($w, $h, ['A new VNC', 'application has', 'been installed'], 'check');
    }

    /**
     * The opening taunt slide: a generic gray "VNC has stopped working" crash dialog with a
     * grayscale error mark above the text. Wider than the other slides (a landscape error box).
     */
    public function renderVncErrorBgra(int $w, int $h): string
    {
        $im = imagecreatetruecolor($w, $h);
        $bg = imagecolorallocate($im, 0xC0, 0xC0, 0xC0);
        $ink = imagecolorallocate($im, 0x2E, 0x2E, 0x2E);
        $ring = imagecolorallocate($im, 0x6E, 0x6E, 0x6E);
        imagefilledrectangle($im, 0, 0, $w - 1, $h - 1, $bg);

        // Error mark (circle + X), top-centre.
        $cx = (int) round($w * 0.5);
        $cy = (int) round($h * 0.19);
        $scale = min($w, $h) / 180.0;
        $r = (int) round(13 * $scale);
        $d = (int) round(7 * $scale);
        imagearc($im, $cx, $cy, $r * 2, $r * 2, 0, 360, $ring);
        imagearc($im, $cx, $cy, $r * 2 + 1, $r * 2 + 1, 0, 360, $ring);
        for ($o = -1; $o <= 1; $o++) {
            imageline($im, $cx - $d, $cy - $d + $o, $cx + $d, $cy + $d + $o, $ink);
            imageline($im, $cx + $d, $cy - $d + $o, $cx - $d, $cy + $d + $o, $ink);
        }

        self::drawCenteredText($im, 3, (int) round($h * 0.34), $w, 'VNC has stopped working', $ink);
        self::drawCenteredText($im, 2, (int) round($h * 0.51), $w, 'memory written out of application', $ink);
        self::drawCenteredText($im, 2, (int) round($h * 0.61), $w, 'bounds (fault 0xC0000005)', $ink);

        return self::imageToBgra($im, $w, $h);
    }

    /**
     * A deliberately generic notice frame: a flat neutral gray with grayscale centred text and an
     * optional grayscale indicator ('spinner' | 'check' | 'none'). No window chrome or coloured
     * accents — the attacker's client and OS are unknown, so it must read as the VNC viewer's own
     * dialog rather than any particular desktop.
     *
     * @param list<string> $lines
     */
    private static function renderGrayNotice(int $w, int $h, array $lines, string $indicator): string
    {
        $im = imagecreatetruecolor($w, $h);
        $bg = imagecolorallocate($im, 0xC0, 0xC0, 0xC0);
        $ink = imagecolorallocate($im, 0x2E, 0x2E, 0x2E);
        imagefilledrectangle($im, 0, 0, $w - 1, $h - 1, $bg);

        $lineH = imagefontheight(4) + 3;
        $y = (int) round($h * 0.37) - (int) round((count($lines) * $lineH) / 2);
        foreach ($lines as $line) {
            self::drawCenteredText($im, 4, $y, $w, $line, $ink);
            $y += $lineH;
        }

        $cx = $w * 0.5;
        $cy = $h * 0.70;
        $scale = min($w, $h) / 200.0;

        if ($indicator === 'spinner') {
            // 12 spokes, graduated gray — a generic loading spinner.
            $ri = 8 * $scale;
            $ro = 18 * $scale;
            for ($i = 0; $i < 12; $i++) {
                $a = ($i / 12) * 2 * M_PI;
                $shade = min(200, 70 + ($i * 12));
                $spoke = imagecolorallocate($im, $shade, $shade, $shade);
                imageline(
                    $im,
                    (int) round($cx + $ri * cos($a)),
                    (int) round($cy + $ri * sin($a)),
                    (int) round($cx + $ro * cos($a)),
                    (int) round($cy + $ro * sin($a)),
                    $spoke
                );
            }
        } elseif ($indicator === 'check') {
            // A simple grayscale checkmark, drawn a few px thick.
            $mark = imagecolorallocate($im, 0x4A, 0x4A, 0x4A);
            for ($o = -1; $o <= 1; $o++) {
                imageline($im, (int) round($cx - 14 * $scale), (int) round($cy + $o), (int) round($cx - 3 * $scale), (int) round($cy + 11 * $scale + $o), $mark);
                imageline($im, (int) round($cx - 3 * $scale), (int) round($cy + 11 * $scale + $o), (int) round($cx + 16 * $scale), (int) round($cy - 12 * $scale + $o), $mark);
            }
        }

        return self::imageToBgra($im, $w, $h);
    }

    /**
     * Renders the initial realistic desktop image (e.g. eth.png),
     * or falls back to the retro Windows 95 desktop.
     */
    public function renderInitialDesktop(int $w, int $h, string $peerIp, int $peerPort): \GdImage
    {
        $path = $this->config->image;
        if ($path !== null && is_file($path)) {
            $data = (string) @file_get_contents($path);
            $loaded = @imagecreatefromstring($data);
            if ($loaded !== false) {
                if (imagesx($loaded) === $w && imagesy($loaded) === $h) {
                    $img = $loaded;
                } else {
                    $img = imagecreatetruecolor($w, $h);
                    imagecopyresampled($img, $loaded, 0, 0, 0, 0, $w, $h, imagesx($loaded), imagesy($loaded));
                    imagedestroy($loaded);
                }

                // The bundled screenshot has a frozen taskbar clock; repaint it with the live
                // date/time so the desktop is not obviously a stale capture.
                self::drawTaskbarClock($img, $w, $h, time());

                return $img;
            }
        }

        return $this->renderWin95($w, $h, $peerIp, $peerPort);
    }

    /**
     * Repaints the Windows taskbar clock (bottom-right of eth.png) with the given time. Positions
     * are fractions of the framebuffer so the patch tracks the clock even if the image is scaled.
     */
    public static function drawTaskbarClock(\GdImage $im, int $w, int $h, int $now): void
    {
        if (!imageistruecolor($im)) {
            imagepalettetotruecolor($im);
        }

        $rightEdge = (int) round($w * 0.960);
        $x1 = (int) round($w * 0.915);
        $y1 = (int) round($h * 0.929);
        $y2 = (int) round($h * 0.974);

        // Sample the dark taskbar in the clean gap between the tray icons and the clock so the
        // patch matches the local background instead of a guessed colour.
        $bg = imagecolorat($im, $x1 + 4, $y2 - 3);
        imagefilledrectangle($im, $x1, $y1, $rightEdge + 2, $y2, $bg);

        $white = imagecolorallocate($im, 235, 235, 235);
        $time = date('g:i A', $now);
        $date = date('n/j/Y', $now);
        $font = 3;
        $cw = imagefontwidth($font);
        $lineH = imagefontheight($font);
        $timeY = (int) round($h * 0.934);
        $dateY = $timeY + $lineH + 2;
        imagestring($im, $font, $rightEdge - (strlen($time) * $cw), $timeY, $time, $white);
        imagestring($im, $font, $rightEdge - (strlen($date) * $cw), $dateY, $date, $white);
    }

    /**
     * Theme: Windows 95 Retro Desktop with Fatal Exception Dialog
     */
    public function renderWin95(int $w, int $h, string $peerIp, int $peerPort): \GdImage
    {
        $im = imagecreatetruecolor($w, $h);

        // Classic Windows 95 Palette
        $teal = imagecolorallocate($im, 0, 128, 128);          // #008080
        $grey = imagecolorallocate($im, 192, 192, 192);        // #C0C0C0
        $darkGrey = imagecolorallocate($im, 128, 128, 128);    // #808080
        $white = imagecolorallocate($im, 255, 255, 255);
        $black = imagecolorallocate($im, 0, 0, 0);
        $navy = imagecolorallocate($im, 0, 0, 128);            // #000080
        $yellow = imagecolorallocate($im, 255, 255, 0);
        $blue = imagecolorallocate($im, 0, 0, 255);
        $red = imagecolorallocate($im, 255, 0, 0);

        // Teal Desktop Background
        imagefilledrectangle($im, 0, 0, $w - 1, $h - 1, $teal);

        // Desktop Icons (Left side)
        $icons = [
            ["[My Computer]", 15, 20],
            ["[Network Nbrhd]", 15, 80],
            ["[Recycle Bin]", 15, 140],
            ["[passwords.txt]", 15, 200],
            ["[Bank_Vault.xls]", 15, 260],
        ];
        foreach ($icons as $icon) {
            imagefilledrectangle($im, $icon[1], $icon[2], $icon[1] + 32, $icon[2] + 32, $grey);
            imagerectangle($im, $icon[1], $icon[2], $icon[1] + 32, $icon[2] + 32, $black);
            imagestring($im, 2, $icon[1] - 8, $icon[2] + 36, $icon[0], $white);
        }

        // Bottom Taskbar (28px)
        $barH = 28;
        $barTop = $h - $barH;
        imagefilledrectangle($im, 0, $barTop, $w - 1, $h - 1, $grey);
        imageline($im, 0, $barTop, $w - 1, $barTop, $white);
        imageline($im, 0, $barTop + 1, $w - 1, $barTop + 1, $white);

        // Start Button
        $btnW = 65;
        $btnH = 22;
        $btnX = 3;
        $btnY = $barTop + 3;
        imagefilledrectangle($im, $btnX, $btnY, $btnX + $btnW, $btnY + $btnH, $grey);
        imageline($im, $btnX, $btnY, $btnX + $btnW, $btnY, $white);
        imageline($im, $btnX, $btnY, $btnX, $btnY + $btnH, $white);
        imageline($im, $btnX + $btnW, $btnY, $btnX + $btnW, $btnY + $btnH, $black);
        imageline($im, $btnX, $btnY + $btnH, $btnX + $btnW, $btnY + $btnH, $black);

        // Windows Logo Flag (2x2 squares)
        imagefilledrectangle($im, $btnX + 6, $btnY + 5, $btnX + 11, $btnY + 10, $red);
        imagefilledrectangle($im, $btnX + 13, $btnY + 5, $btnX + 18, $btnY + 10, $teal);
        imagefilledrectangle($im, $btnX + 6, $btnY + 12, $btnX + 11, $btnY + 17, $blue);
        imagefilledrectangle($im, $btnX + 13, $btnY + 12, $btnX + 18, $btnY + 17, $yellow);
        imagestring($im, 3, $btnX + 23, $btnY + 4, "Start", $black);

        // System Tray (Clock)
        $trayW = 75;
        $trayX = $w - $trayW - 4;
        $trayY = $barTop + 3;
        imagefilledrectangle($im, $trayX, $trayY, $trayX + $trayW, $trayY + $btnH, $grey);
        imageline($im, $trayX, $trayY, $trayX + $trayW, $trayY, $darkGrey);
        imageline($im, $trayX, $trayY, $trayX, $trayY + $btnH, $darkGrey);
        imageline($im, $trayX + $trayW, $trayY, $trayX + $trayW, $trayY + $btnH, $white);
        imageline($im, $trayX, $trayY + $btnH, $trayX + $trayW, $trayY + $btnH, $white);
        imagestring($im, 3, $trayX + 12, $trayY + 4, "11:42 AM", $black);

        // Centered Classic Fatal Exception Dialog Box
        $dlgW = (int) min(560, $w - 80);
        $dlgH = 260;
        $dlgX = (int) (($w - $dlgW) / 2);
        $dlgY = (int) (($h - $dlgH) / 2) - 10;

        // Dialog Body
        imagefilledrectangle($im, $dlgX, $dlgY, $dlgX + $dlgW, $dlgY + $dlgH, $grey);
        // Outer 3D borders
        imageline($im, $dlgX, $dlgY, $dlgX + $dlgW, $dlgY, $white);
        imageline($im, $dlgX, $dlgY, $dlgX, $dlgY + $dlgH, $white);
        imageline($im, $dlgX + $dlgW, $dlgY, $dlgX + $dlgW, $dlgY + $dlgH, $black);
        imageline($im, $dlgX, $dlgY + $dlgH, $dlgX + $dlgW, $dlgY + $dlgH, $black);

        // Title Bar
        $titleH = 22;
        imagefilledrectangle($im, $dlgX + 3, $dlgY + 3, $dlgX + $dlgW - 3, $dlgY + $titleH, $navy);
        imagestring($im, 3, $dlgX + 8, $dlgY + 5, "Fatal Exception 0E", $white);

        // Close 'X' Button on Title Bar
        $closeX = $dlgX + $dlgW - 20;
        $closeY = $dlgY + 5;
        imagefilledrectangle($im, $closeX, $closeY, $closeX + 14, $closeY + 14, $grey);
        imagerectangle($im, $closeX, $closeY, $closeX + 14, $closeY + 14, $white);
        imagestring($im, 2, $closeX + 4, $closeY + 1, "x", $black);

        // Error Icon: Red Circle with White 'X'
        $iconCX = $dlgX + 35;
        $iconCY = $dlgY + 60;
        imagefilledellipse($im, $iconCX, $iconCY, 32, 32, $red);
        imageellipse($im, $iconCX, $iconCY, 32, 32, $black);
        imagestring($im, 5, $iconCX - 4, $iconCY - 8, "X", $white);

        // Error Messages
        $tx = $dlgX + 65;
        $ty = $dlgY + 45;
        imagestring($im, 3, $tx, $ty, "An exception 0E has occurred at 0028:C0011E36 in VXD VMM(01)", $black);
        imagestring($im, 3, $tx, $ty + 20, "Unauthorized intruder connection detected from {$peerIp}.", $black);
        imagestring($im, 2, $tx, $ty + 50, "*  Press any key to terminate the current intrusion.", $black);
        imagestring($im, 2, $tx, $ty + 68, "*  Press CTRL+ALT+DEL again to restart your computer.", $black);
        imagestring($im, 2, $tx, $ty + 86, "*  If you continue hacking, your machine will be blue-screened.", $black);
        imagestring($im, 2, $tx, $ty + 104, "*  Incident logged to C:\\WINDOWS\\SYSTEM\\HACKER.LOG", $black);

        // OK Button (Centered bottom of dialog)
        $okW = 75;
        $okH = 24;
        $okX = $dlgX + (int) (($dlgW - $okW) / 2);
        $okY = $dlgY + $dlgH - 35;
        imagefilledrectangle($im, $okX, $okY, $okX + $okW, $okY + $okH, $grey);
        imageline($im, $okX, $okY, $okX + $okW, $okY, $white);
        imageline($im, $okX, $okY, $okX, $okY + $okH, $white);
        imageline($im, $okX + $okW, $okY, $okX + $okW, $okY + $okH, $black);
        imageline($im, $okX, $okY + $okH, $okX + $okW, $okY + $okH, $black);
        imagestring($im, 3, $okX + 26, $okY + 5, "OK", $black);

        return $im;
    }

    private static function renderImageFile(string $path, int $w, int $h): ?\GdImage
    {
        if (!is_file($path)) {
            return null;
        }
        $data = (string) @file_get_contents($path);
        $loaded = @imagecreatefromstring($data);
        if ($loaded === false) {
            return null;
        }
        if (imagesx($loaded) === $w && imagesy($loaded) === $h) {
            return $loaded;
        }
        $im = imagecreatetruecolor($w, $h);
        imagecopyresampled($im, $loaded, 0, 0, 0, 0, $w, $h, imagesx($loaded), imagesy($loaded));
        imagedestroy($loaded);

        return $im;
    }

    /**
     * Theme: Troll / Flash
     * Alternates between Frame A (evil-troll.png) and Frame B (ah-ah-ah.jpg),
     * with procedural vector/ASCII fallbacks.
     */
    public function renderTroll(int $w, int $h, string $peerIp, int $peerPort, int $frame): \GdImage
    {
        $isEven = ($frame % 2 === 0);

        if ($isEven) {
            // Frame A: evil-troll.png
            $trollPaths = [
                dirname(__DIR__, 3) . '/demo/assets/evil-troll.png',
                '/Users/bobmaher/Desktop/evil-troll.png',
            ];
            foreach ($trollPaths as $tp) {
                $img = self::renderImageFile($tp, $w, $h);
                if ($img !== null) {
                    return $img;
                }
            }

            // Fallback: Flashing Red with Giant Trollface
            $im = imagecreatetruecolor($w, $h);
            $red = imagecolorallocate($im, 200, 10, 10);
            $yellow = imagecolorallocate($im, 255, 220, 0);
            $white = imagecolorallocate($im, 255, 255, 255);
            $black = imagecolorallocate($im, 0, 0, 0);

            imagefilledrectangle($im, 0, 0, $w - 1, $h - 1, $red);

            // Hazard top/bottom border
            imagefilledrectangle($im, 0, 0, $w - 1, 28, $black);
            imagefilledrectangle($im, 0, 28, $w - 1, 32, $yellow);
            self::drawCenteredText($im, 4, 6, $w, "!!! SECURITY ALERT: UNAUTHORIZED INTRUSION DETECTED !!!", $yellow);

            imagefilledrectangle($im, 0, $h - 32, $w - 1, $h - 1, $black);
            imagefilledrectangle($im, 0, $h - 36, $w - 1, $h - 33, $yellow);
            self::drawCenteredText($im, 4, $h - 26, $w, "TARGET IP: {$peerIp} -- SESSION RECORDED", $white);

            // Giant Trollface (Centered in viewport)
            $cx = (int) ($w / 2);
            $cy = (int) ($h * 0.44);
            $scale = min($w / 800.0, $h / 600.0);

            $faceW = (int) (380 * $scale);
            $faceH = (int) (270 * $scale);

            // Head outline and fill
            imagefilledellipse($im, $cx, $cy, $faceW, $faceH, $white);
            imageellipse($im, $cx, $cy, $faceW, $faceH, $black);
            imageellipse($im, $cx, $cy, $faceW + 2, $faceH + 2, $black);

            // Forehead wrinkle lines
            imageline($im, (int) ($cx - 100 * $scale), (int) ($cy - 90 * $scale), (int) ($cx + 80 * $scale), (int) ($cy - 95 * $scale), $black);
            imageline($im, (int) ($cx - 80 * $scale), (int) ($cy - 75 * $scale), (int) ($cx + 70 * $scale), (int) ($cy - 80 * $scale), $black);

            // Squinting Troll Eyes
            $eyeW = (int) (55 * $scale);
            $eyeH = (int) (45 * $scale);
            $pupil = (int) (20 * $scale);
            imagefilledellipse($im, (int) ($cx - 70 * $scale), (int) ($cy - 40 * $scale), $eyeW, $eyeH, $black);
            imagefilledellipse($im, (int) ($cx + 70 * $scale), (int) ($cy - 50 * $scale), $eyeW, $eyeH, $black);
            imagefilledellipse($im, (int) ($cx - 60 * $scale), (int) ($cy - 40 * $scale), $pupil, $pupil, $white);
            imagefilledellipse($im, (int) ($cx + 80 * $scale), (int) ($cy - 50 * $scale), $pupil, $pupil, $white);

            // Nose
            imageline($im, $cx, (int) ($cy - 40 * $scale), (int) ($cx - 15 * $scale), (int) ($cy + 10 * $scale), $black);
            imageline($im, (int) ($cx - 15 * $scale), (int) ($cy + 10 * $scale), (int) ($cx + 20 * $scale), (int) ($cy + 10 * $scale), $black);

            // Giant Grin Arc
            $grinW = (int) (300 * $scale);
            $grinH = (int) (170 * $scale);
            imagearc($im, $cx, (int) ($cy + 25 * $scale), $grinW, $grinH, 0, 180, $black);
            imageline($im, (int) ($cx - 150 * $scale), (int) ($cy + 25 * $scale), (int) ($cx + 150 * $scale), (int) ($cy + 25 * $scale), $black);

            // Teeth Vertical Grid Lines
            $step = (int) (30 * $scale);
            for ($tx = (int) ($cx - 120 * $scale); $tx <= (int) ($cx + 120 * $scale); $tx += $step) {
                imageline($im, $tx, (int) ($cy + 25 * $scale), $tx, (int) ($cy + 75 * $scale), $black);
            }

            // Subtitle
            self::drawCenteredText($im, 5, (int) ($cy + $faceH / 2 + 15), $w, "PROBLEM, HACKER? :)", $white);
            self::drawCenteredText($im, 4, (int) ($cy + $faceH / 2 + 45), $w, "YOU ARE ON LIVE HONEYPOT SURVEILLANCE", $yellow);
        } else {
            // Frame B: ah-ah-ah.jpg
            $ahahPaths = [
                dirname(__DIR__, 3) . '/demo/assets/ah-ah-ah.jpg',
                '/Users/bobmaher/Desktop/ah-ah-ah.jpg',
            ];
            foreach ($ahahPaths as $ap) {
                $img = self::renderImageFile($ap, $w, $h);
                if ($img !== null) {
                    return $img;
                }
            }

            // Fallback: Flashing Black with SKULL ASCII Art
            $im = imagecreatetruecolor($w, $h);
            $black = imagecolorallocate($im, 0, 0, 0);
            $green = imagecolorallocate($im, 0, 255, 60);      // Matrix Neon Green
            $bloodRed = imagecolorallocate($im, 255, 30, 30);
            $white = imagecolorallocate($im, 255, 255, 255);

            imagefilledrectangle($im, 0, 0, $w - 1, $h - 1, $black);

            // Crimson border
            imagerectangle($im, 2, 2, $w - 3, $h - 3, $bloodRed);
            imagerectangle($im, 4, 4, $w - 5, $h - 5, $bloodRed);

            // Top Header
            self::drawCenteredText($im, 4, 12, $w, "*** SYSTEM COMPROMISED -- ACCESS TERMINATED ***", $bloodRed);

            // Draw TrollStream::SKULL line-by-line
            $skullLines = explode("\n", TrollStream::SKULL);
            $charW = imagefontwidth(2);
            $lineH = imagefontheight(2);

            $startY = (int) max(35, ($h - (count($skullLines) * $lineH)) / 2 - 10);

            foreach ($skullLines as $i => $line) {
                $trimmed = rtrim($line);
                if ($trimmed === '') {
                    continue;
                }
                $lineX = (int) max(10, ($w - (strlen($trimmed) * $charW)) / 2);
                $lineY = $startY + ($i * $lineH);
                if ($lineY < $h - 30) {
                    imagestring($im, 2, $lineX, $lineY, $trimmed, $green);
                }
            }

            // Bottom Text
            self::drawCenteredText($im, 4, $h - 40, $w, "YOU HAVE ENTERED THE HONEYPOT", $bloodRed);
            self::drawCenteredText($im, 3, $h - 22, $w, "GOODBYE :) -- IP: {$peerIp}", $white);
        }

        return $im;
    }

    private static function drawCenteredText(\GdImage $im, int $font, int $y, int $w, string $text, int $color): void
    {
        $charW = imagefontwidth($font);
        $textW = strlen($text) * $charW;
        $x = (int) max(0, ($w - $textW) / 2);
        imagestring($im, $font, $x, $y, $text, $color);
    }
}
